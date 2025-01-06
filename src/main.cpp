/**
 * @file src/main.cpp
 * @brief Main entry point for Sunshine.
 */

// standard includes
#include <csignal>
#include <fstream>
#include <iostream>

// local includes
#include "confighttp.h"
#include "entry_handler.h"
#include "globals.h"
#include "httpcommon.h"
#include "logging.h"
#include "main.h"
#include "nvhttp.h"
#include "process.h"
#include "system_tray.h"
#include "upnp.h"
#include "version.h"
#include "video.h"

#if RAZER_MOD == 1 
#include "RazerNamedPipe.h"
#include "RazerState.h"
#include "stream.h"
#include "file_handler.h"
#include <boost/property_tree/ptree.hpp>
#endif

extern "C" {
#include <rs.h>
}

using namespace std::literals;

std::map<int, std::function<void()>> signal_handlers;
void
on_signal_forwarder(int sig) {
  signal_handlers.at(sig)();
}

template <class FN>
void
on_signal(int sig, FN &&fn) {
  signal_handlers.emplace(sig, std::forward<FN>(fn));

  std::signal(sig, on_signal_forwarder);
}

std::map<std::string_view, std::function<int(const char *name, int argc, char **argv)>> cmd_to_func {
  { "creds"sv, args::creds },
  { "help"sv, args::help },
  { "version"sv, args::version },
#ifdef _WIN32
  { "restore-nvprefs-undo"sv, args::restore_nvprefs_undo },
#endif
};

#ifdef _WIN32
LRESULT CALLBACK
SessionMonitorWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
  switch (uMsg) {
    case WM_CLOSE:
      DestroyWindow(hwnd);
      return 0;
    case WM_DESTROY:
      PostQuitMessage(0);
      return 0;
    case WM_ENDSESSION: {
      // Terminate ourselves with a blocking exit call
      std::cout << "Received WM_ENDSESSION"sv << std::endl;
      lifetime::exit_sunshine(0, false);
      return 0;
    }
    default:
      return DefWindowProc(hwnd, uMsg, wParam, lParam);
  }
}
#endif

std::string GetExecutablePath() {
    char buffer[MAX_PATH];
    GetModuleFileName(NULL, buffer, MAX_PATH);
    std::string::size_type pos = std::string(buffer).find_last_of("\\/");
    return std::string(buffer).substr(0, pos);
}

#if RAZER_MOD == 1
bool is_port_available(int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return false;
    }

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(sockfd);
        return false;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    bool available = bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == 0;

    close(sockfd);
    return available;
}

bool check_port_available(int base_port){
  BOOST_LOG(info) << "Checking port available..:";

  bool ret;
  ret = is_port_available(base_port);
  BOOST_LOG(info) << " - Base port:" << base_port << ". " << ret;
  if(!ret) return ret;

  ret = is_port_available(net::map_port(confighttp::PORT_HTTPS));
  BOOST_LOG(info) << " - UI port:" << net::map_port(confighttp::PORT_HTTPS) << ". " << ret;
  if(!ret) return ret;

  ret = is_port_available(net::map_port(nvhttp::PORT_HTTPS));
  BOOST_LOG(info) << " - setup port:" << net::map_port(nvhttp::PORT_HTTPS) << ". " << ret;
  if(!ret) return ret;

  ret = is_port_available(net::map_port(rtsp_stream::RTSP_SETUP_PORT));
  BOOST_LOG(info) << " - RTSP port:" << net::map_port(rtsp_stream::RTSP_SETUP_PORT) << ". " << ret;
  if(!ret) return ret;

  ret = is_port_available(net::map_port(stream::VIDEO_STREAM_PORT));
  BOOST_LOG(info) << " - Video port:" << net::map_port(stream::VIDEO_STREAM_PORT) << ". " << ret;
  if(!ret) return ret;

  ret = is_port_available(net::map_port(stream::CONTROL_PORT));
  BOOST_LOG(info) << " - Control port:" << net::map_port(stream::CONTROL_PORT) << ". " << ret;
  if(!ret) return ret;

  ret = is_port_available(net::map_port(stream::AUDIO_STREAM_PORT));
  BOOST_LOG(info) << " - Audio port:" << net::map_port(stream::AUDIO_STREAM_PORT) << ". " << ret;
  if(!ret) return ret;

  return true;
}

int find_base_port(int range_start = 10000, int range_end = 60000) {
    std::srand(std::time(nullptr));

    std::vector<int> offsets = {0, confighttp::PORT_HTTPS, nvhttp::PORT_HTTPS, rtsp_stream::RTSP_SETUP_PORT, stream::VIDEO_STREAM_PORT, stream::CONTROL_PORT, stream::AUDIO_STREAM_PORT};
    
    while (true) {
        int base_port = range_start + std::rand() % (range_end - range_start);

        bool all_available = true;

        for (int offset : offsets) {
            if (!is_port_available(base_port + offset)) {
                all_available = false;
                break;
            }
        }

        if (all_available) {
            return base_port;
        }
    }
}
#endif

/**
 * @brief Main application entry point.
 * @param argc The number of arguments.
 * @param argv The arguments.
 *
 * EXAMPLES:
 * ```cpp
 * main(1, const char* args[] = {"sunshine", nullptr});
 * ```
 */
int
main(int argc, char *argv[]) {

  std::string execPath = GetExecutablePath();
  std::cout << "Executable Path: " << execPath << std::endl;
  //set working dir
  if (chdir(execPath.c_str()) == 0) {
      std::cout << "Successfully changed working directory to: " << execPath << std::endl;
  } else {
      std::cerr << "Error changing working directory" << std::endl;
  }

  lifetime::argv = argv;

  task_pool_util::TaskPool::task_id_t force_shutdown = nullptr;

#ifdef _WIN32
  // Switch default C standard library locale to UTF-8 on Windows 10 1803+
  setlocale(LC_ALL, ".UTF-8");
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
  // Use UTF-8 conversion for the default C++ locale (used by boost::log)
  std::locale::global(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));
#pragma GCC diagnostic pop

  mail::man = std::make_shared<safe::mail_raw_t>();

  if (config::parse(argc, argv)) {
    return 0;
  }

  auto log_deinit_guard = logging::init(config::sunshine.min_log_level, config::sunshine.log_file);
  if (!log_deinit_guard) {
    BOOST_LOG(error) << "Logging failed to initialize"sv;
  }

  // logging can begin at this point
  // if anything is logged prior to this point, it will appear in stdout, but not in the log viewer in the UI
  // the version should be printed to the log before anything else
  BOOST_LOG(info) << " ----------------------------------------------------------------------------------------------------------------- ";
  BOOST_LOG(info) << PROJECT_NAME << " version: " << PROJECT_VER;

#if RAZER_MOD == 1
  if(check_port_available(config::sunshine.port) == false){
    //any conflict port , we automatically generate one.
    config::sunshine.port = find_base_port();
    BOOST_LOG(info) << " meets conflict port, we temporarily change it to " << config::sunshine.port;
  }

  //write a real port for Cortex anyway.
  boost::property_tree::ptree fileTree;
  auto vars = config::parse_config(file_handler::read_file(config::sunshine.config_file.c_str()));

  for (auto &[name, value] : vars) {
      fileTree.put(std::move(name), std::move(value));
  }
  fileTree.put("real_port", config::sunshine.port);
  std::stringstream configStream;

  for (const auto &kv : fileTree) {
    std::string value = fileTree.get<std::string>(kv.first);
    if (value.length() == 0 || value.compare("null") == 0) continue;
    configStream << kv.first << " = " << value << std::endl;
  }
  file_handler::write_file(config::sunshine.config_file.c_str(), configStream.str());
#endif

  if (!config::sunshine.cmd.name.empty()) {
    auto fn = cmd_to_func.find(config::sunshine.cmd.name);
    if (fn == std::end(cmd_to_func)) {
      BOOST_LOG(fatal) << "Unknown command: "sv << config::sunshine.cmd.name;

      BOOST_LOG(info) << "Possible commands:"sv;
      for (auto &[key, _] : cmd_to_func) {
        BOOST_LOG(info) << '\t' << key;
      }

      return 7;
    }

    return fn->second(argv[0], config::sunshine.cmd.argc, config::sunshine.cmd.argv);
  }

#if RAZER_MOD
  std::thread commandThread { rz_state::StartEventThread };
  std::thread heartbeatThread { rz_state::Heartbeat };
#endif

#ifdef WIN32
  // Modify relevant NVIDIA control panel settings if the system has corresponding gpu
  if (nvprefs_instance.load()) {
    // Restore global settings to the undo file left by improper termination of RazerRemotePlayHost.exe
    nvprefs_instance.restore_from_and_delete_undo_file_if_exists();
    // Modify application settings for RazerRemotePlayHost.exe
    nvprefs_instance.modify_application_profile();
    // Modify global settings, undo file is produced in the process to restore after improper termination
    nvprefs_instance.modify_global_profile();
    // Unload dynamic library to survive driver re-installation
    nvprefs_instance.unload();
  }

  // Wait as long as possible to terminate RazerRemotePlayHost.exe during logoff/shutdown
  SetProcessShutdownParameters(0x100, SHUTDOWN_NORETRY);

  // We must create a hidden window to receive shutdown notifications since we load gdi32.dll
  std::promise<HWND> session_monitor_hwnd_promise;
  auto session_monitor_hwnd_future = session_monitor_hwnd_promise.get_future();
  std::promise<void> session_monitor_join_thread_promise;
  auto session_monitor_join_thread_future = session_monitor_join_thread_promise.get_future();

  std::thread session_monitor_thread([&]() {
    session_monitor_join_thread_promise.set_value_at_thread_exit();

    WNDCLASSA wnd_class {};
    wnd_class.lpszClassName = "RazerRemotePlayHostSessionMonitorClass";
    wnd_class.lpfnWndProc = SessionMonitorWindowProc;
    if (!RegisterClassA(&wnd_class)) {
      session_monitor_hwnd_promise.set_value(NULL);
      BOOST_LOG(error) << "Failed to register session monitor window class"sv << std::endl;
      return;
    }

    auto wnd = CreateWindowExA(
      0,
      wnd_class.lpszClassName,
      "Razer Remote Play Host Session Monitor Window",
      0,
      CW_USEDEFAULT,
      CW_USEDEFAULT,
      CW_USEDEFAULT,
      CW_USEDEFAULT,
      nullptr,
      nullptr,
      nullptr,
      nullptr);

    session_monitor_hwnd_promise.set_value(wnd);

    if (!wnd) {
      BOOST_LOG(error) << "Failed to create session monitor window"sv << std::endl;
      return;
    }

    ShowWindow(wnd, SW_HIDE);

    // Run the message loop for our window
    MSG msg {};
    while (GetMessage(&msg, nullptr, 0, 0) > 0) {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }
  });

  auto session_monitor_join_thread_guard = util::fail_guard([&]() {
    if (session_monitor_hwnd_future.wait_for(1s) == std::future_status::ready) {
      if (HWND session_monitor_hwnd = session_monitor_hwnd_future.get()) {
        PostMessage(session_monitor_hwnd, WM_CLOSE, 0, 0);
      }

      if (session_monitor_join_thread_future.wait_for(1s) == std::future_status::ready) {
        session_monitor_thread.join();
        return;
      }
      else {
        BOOST_LOG(warning) << "session_monitor_join_thread_future reached timeout";
      }
    }
    else {
      BOOST_LOG(warning) << "session_monitor_hwnd_future reached timeout";
    }

    session_monitor_thread.detach();
  });

#endif

  task_pool.start(1);

#if defined SUNSHINE_TRAY && SUNSHINE_TRAY >= 1
  // create tray thread and detach it
  system_tray::run_tray();
#endif

  // Create signal handler after logging has been initialized
  auto shutdown_event = mail::man->event<bool>(mail::shutdown);
  on_signal(SIGINT, [&force_shutdown, shutdown_event]() {
    BOOST_LOG(info) << "Interrupt handler called"sv;

    auto task = []() {
      BOOST_LOG(fatal) << "10 seconds passed, yet Sunshine's still running: Forcing shutdown"sv;
      logging::log_flush();
      lifetime::debug_trap();
    };
    force_shutdown = task_pool.pushDelayed(task, 10s).task_id;

    shutdown_event->raise(true);
  });

  on_signal(SIGTERM, [&force_shutdown, shutdown_event]() {
    BOOST_LOG(info) << "Terminate handler called"sv;

    auto task = []() {
      BOOST_LOG(fatal) << "10 seconds passed, yet Sunshine's still running: Forcing shutdown"sv;
      logging::log_flush();
      lifetime::debug_trap();
    };
    force_shutdown = task_pool.pushDelayed(task, 10s).task_id;

    shutdown_event->raise(true);
  });

  proc::refresh(config::stream.file_apps);

  // If any of the following fail, we log an error and continue event though sunshine will not function correctly.
  // This allows access to the UI to fix configuration problems or view the logs.

  auto platf_deinit_guard = platf::init();
  if (!platf_deinit_guard) {
    BOOST_LOG(error) << "Platform failed to initialize"sv;
  }

  auto proc_deinit_guard = proc::init();
  if (!proc_deinit_guard) {
    BOOST_LOG(error) << "Proc failed to initialize"sv;
  }

  reed_solomon_init();
  auto input_deinit_guard = input::init();
  if (video::probe_encoders()) {
    BOOST_LOG(error) << "Video failed to find working encoder"sv;
  }

  if (http::init()) {
    BOOST_LOG(fatal) << "HTTP interface failed to initialize"sv;

#ifdef _WIN32
    BOOST_LOG(fatal) << "To relaunch Sunshine successfully, use the shortcut in the Start Menu. Do not run RazerRemotePlayHost.exe manually."sv;
    std::this_thread::sleep_for(10s);
#endif

    return -1;
  }

  std::unique_ptr<platf::deinit_t> mDNS;
  auto sync_mDNS = std::async(std::launch::async, [&mDNS]() {
    mDNS = platf::publish::start();
  });

  std::unique_ptr<platf::deinit_t> upnp_unmap;
  auto sync_upnp = std::async(std::launch::async, [&upnp_unmap]() {
    upnp_unmap = upnp::start();
  });

  // FIXME: Temporary workaround: Simple-Web_server needs to be updated or replaced
  if (shutdown_event->peek()) {
    return lifetime::desired_exit_code;
  }

  std::thread httpThread { nvhttp::start };
  std::thread configThread { confighttp::start };

#ifdef _WIN32
  // If we're using the default port and GameStream is enabled, warn the user
  if (config::sunshine.port == 47989 && is_gamestream_enabled()) {
    BOOST_LOG(fatal) << "GameStream is still enabled in GeForce Experience! This *will* cause streaming problems with Sunshine!"sv;
    BOOST_LOG(fatal) << "Disable GameStream on the SHIELD tab in GeForce Experience or change the Port setting on the Advanced tab in the Sunshine Web UI."sv;
  }
#endif

  rtsp_stream::rtpThread();
#if RAZER_MOD == 1  
  commandThread.join();
  heartbeatThread.join();
#endif
  httpThread.join();
  configThread.join();

  task_pool.stop();
  task_pool.join();

  // stop system tray
#if defined SUNSHINE_TRAY && SUNSHINE_TRAY >= 1
  system_tray::end_tray();
#endif

#ifdef WIN32
  // Restore global NVIDIA control panel settings
  if (nvprefs_instance.owning_undo_file() && nvprefs_instance.load()) {
    nvprefs_instance.restore_global_profile();
    nvprefs_instance.unload();
  }
#endif

  return lifetime::desired_exit_code;
}
