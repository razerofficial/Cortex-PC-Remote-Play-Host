/**
 * @file src/confighttp.cpp
 * @brief todo
 *
 * @todo Authentication, better handling of routes common to nvhttp, cleanup
 */

#define BOOST_BIND_GLOBAL_PLACEHOLDERS

#include "process.h"

#include <filesystem>
#include <set>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <boost/algorithm/string.hpp>

#include <boost/asio/ssl/context.hpp>

#include <boost/filesystem.hpp>

#include <Simple-Web-Server/crypto.hpp>
#include <Simple-Web-Server/server_https.hpp>
#include <Simple-Web-Server/server_http.hpp>
#include <boost/asio/ssl/context_base.hpp>

#include "config.h"
#include "confighttp.h"
#include "crypto.h"
#include "file_handler.h"
#include "globals.h"
#include "httpcommon.h"
#include "logging.h"
#include "network.h"
#include "nvhttp.h"
#include "platform/common.h"
#include "rtsp.h"
#include "utility.h"
#include "uuid.h"
#include "version.h"

#if (RAZER_MOD==1)
#include "RazerState.h"

#define SERVER_HTTP 1
#define RAZER_WEB_API 1
#endif

#if RAZER_WEB_API == 1

#define ENABLE_SUNSHINE_WEB_UI

#define ACCESS_CONTROL_ALLOW_ORIGIN "*"
#define ACCESS_CONTROL_ALLOW_METHODS "GET, POST, PUT, DELETE, OPTIONS"
#define ACCESS_CONTROL_ALLOW_HEADERS "Content-Type"
#endif

using namespace std::literals;

namespace confighttp {
  namespace fs = std::filesystem;
  namespace pt = boost::property_tree;

  using https_server_t = SimpleWeb::Server<SimpleWeb::HTTPS>;
  using http_server_t = SimpleWeb::Server<SimpleWeb::HTTP>;

  using args_t = SimpleWeb::CaseInsensitiveMultimap;
  using resp_https_t = std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTPS>::Response>;
  using resp_http_t = std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTP>::Response>;
  using req_https_t = std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTPS>::Request>;
  using req_http_t = std::shared_ptr<typename SimpleWeb::ServerBase<SimpleWeb::HTTP>::Request>;

#if (SERVER_HTTP==1)
  using type_server_t = http_server_t;
  using resp_type_t = resp_http_t;
  using req_type_t = req_http_t;
#else
  using type_server_t = https_server_t;
  using resp_type_t = resp_https_t;
  using req_type_t = req_https_t;
#endif

  enum class op_e {
    ADD,
    REMOVE
  };

  void
  print_req(const req_type_t &request) {
    BOOST_LOG(debug) << "METHOD :: "sv << request->method;
    BOOST_LOG(debug) << "DESTINATION :: "sv << request->path;

    for (auto &[name, val] : request->header) {
      BOOST_LOG(debug) << name << " -- " << (name == "Authorization" ? "CREDENTIALS REDACTED" : val);
    }

    BOOST_LOG(debug) << " [--] "sv;

    for (auto &[name, val] : request->parse_query_string()) {
      BOOST_LOG(debug) << name << " -- " << val;
    }

    BOOST_LOG(debug) << " [--] "sv;
  }
  
  void
  send_unauthorized(resp_type_t response, req_type_t request) {
    auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
    BOOST_LOG(info) << "Web UI: ["sv << address << "] -- not authorized"sv;
    const SimpleWeb::CaseInsensitiveMultimap headers {
      { "WWW-Authenticate", R"(Basic realm="Sunshine Gamestream Host", charset="UTF-8")" }
    };
    response->write(SimpleWeb::StatusCode::client_error_unauthorized, headers);
  }

  void
  send_redirect(resp_type_t response, req_type_t request, const char *path) {
    auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
    BOOST_LOG(info) << "Web UI: ["sv << address << "] -- not authorized"sv;
    const SimpleWeb::CaseInsensitiveMultimap headers {
      { "Location", path }
    };
    response->write(SimpleWeb::StatusCode::redirection_temporary_redirect, headers);
  }

  bool
  authenticate(resp_type_t response, req_type_t request) {
    /*auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
    auto ip_type = net::from_address(address);

    if (ip_type > http::origin_web_ui_allowed) {
      BOOST_LOG(info) << "Web UI: ["sv << address << "] -- denied"sv;
      response->write(SimpleWeb::StatusCode::client_error_forbidden);
      return false;
    }

    // If credentials are shown, redirect the user to a /welcome page
    if (config::sunshine.username.empty()) {
      send_redirect(response, request, "/welcome");
      return false;
    }

    auto fg = util::fail_guard([&]() {
      send_unauthorized(response, request);
    });

    auto auth = request->header.find("authorization");
    if (auth == request->header.end()) {
      return false;
    }

    auto &rawAuth = auth->second;
    auto authData = SimpleWeb::Crypto::Base64::decode(rawAuth.substr("Basic "sv.length()));

    int index = authData.find(':');
    if (index >= authData.size() - 1) {
      return false;
    }

    auto username = authData.substr(0, index);
    auto password = authData.substr(index + 1);
    auto hash = util::hex(crypto::hash(password + config::sunshine.salt)).to_string();

    if (!boost::iequals(username, config::sunshine.username) || hash != config::sunshine.password) {
      return false;
    }

    fg.disable();*/
    return true;
  }

  void
  not_found(resp_type_t response, req_type_t request) {
    pt::ptree tree;
    tree.put("root.<xmlattr>.status_code", 404);

    std::ostringstream data;

    pt::write_xml(data, tree);
    //std::string result = data.str
    response->write(data.str());

    *response << "HTTP/1.1 404 NOT FOUND\r\n"
              << data.str();
  }

  // todo - combine these functions into a single function that accepts the page, i.e "index", "pin", "apps"
  void
  getIndexPage(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::string content = file_handler::read_file(WEB_DIR "index.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(content, headers);
  }

  void
  getPinPage(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::string content = file_handler::read_file(WEB_DIR "pin.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(content, headers);
  }

  void
  getAppsPage(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::string content = file_handler::read_file(WEB_DIR "apps.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    headers.emplace("Access-Control-Allow-Origin", "https://images.igdb.com/");
    response->write(content, headers);
  }

  void
  getClientsPage(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::string content = file_handler::read_file(WEB_DIR "clients.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(content, headers);
  }

  void
  getConfigPage(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::string content = file_handler::read_file(WEB_DIR "config.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(content, headers);
  }

  void
  getPasswordPage(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::string content = file_handler::read_file(WEB_DIR "password.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(content, headers);
  }

  void
  getWelcomePage(resp_type_t response, req_type_t request) {
    print_req(request);
    if (!config::sunshine.username.empty()) {
      send_redirect(response, request, "/");
      return;
    }
    std::string content = file_handler::read_file(WEB_DIR "welcome.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(content, headers);
  }

  void
  getTroubleshootingPage(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::string content = file_handler::read_file(WEB_DIR "troubleshooting.html");
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");
    response->write(content, headers);
  }

  void
  getFaviconImage(resp_type_t response, req_type_t request) {
    // todo - combine function with getSunshineLogoImage and possibly getNodeModules
    // todo - use mime_types map
    print_req(request);

    std::ifstream in(WEB_DIR "images/RazerRemotePlayHost.ico", std::ios::binary);
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "image/x-icon");
    #if (RAZER_WEB_API==1)
    headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
    headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
    headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);
    #endif
    response->write(SimpleWeb::StatusCode::success_ok, in, headers);
  }

  void
  getSunshineLogoImage(resp_type_t response, req_type_t request) {
    // todo - combine function with getFaviconImage and possibly getNodeModules
    // todo - use mime_types map
    print_req(request);

    std::ifstream in(WEB_DIR "images/logo-sunshine-45.png", std::ios::binary);
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace(ACCESS_CONTROL_ALLOW_HEADERS, "image/png");
    headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
    headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
    headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);

    response->write(SimpleWeb::StatusCode::success_ok, in, headers);
  }

  bool
  isChildPath(fs::path const &base, fs::path const &query) {
    auto relPath = fs::relative(base, query);
    return *(relPath.begin()) != fs::path("..");
  }

  void
  getNodeModules(resp_type_t response, req_type_t request) {
    print_req(request);
    fs::path webDirPath(WEB_DIR);
    fs::path nodeModulesPath(webDirPath / "assets");

    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
    headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
    headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);

    // .relative_path is needed to shed any leading slash that might exist in the request path
    auto filePath = fs::weakly_canonical(webDirPath / fs::path(request->path).relative_path());

    // Don't do anything if file does not exist or is outside the assets directory
    if (!isChildPath(filePath, nodeModulesPath)) {
      BOOST_LOG(warning) << "Someone requested a path " << filePath << " that is outside the assets folder";
      response->write(SimpleWeb::StatusCode::client_error_bad_request, "Bad Request", headers);
    }
    else if (!fs::exists(filePath)) {
      response->write(SimpleWeb::StatusCode::client_error_not_found, headers);
    }
    else {
      auto relPath = fs::relative(filePath, webDirPath);
      // get the mime type from the file extension mime_types map
      // remove the leading period from the extension
      auto mimeType = mime_types.find(relPath.extension().string().substr(1));
      // check if the extension is in the map at the x position
      if (mimeType != mime_types.end()) {
        // if it is, set the content type to the mime type
        SimpleWeb::CaseInsensitiveMultimap headers;
        headers.emplace(ACCESS_CONTROL_ALLOW_HEADERS, mimeType->second);
        headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
        headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
        headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);
        std::ifstream in(filePath.string(), std::ios::binary);
        response->write(SimpleWeb::StatusCode::success_ok, in, headers);
      }
      // do not return any file if the type is not in the map
    }
  }

  void
  getApps(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::string content = file_handler::read_file(config::stream.file_apps.c_str());
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "application/json");
    headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
    headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
    headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);
    response->write(content, headers);
  }

  void
  getLogs(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::string content = file_handler::read_file(config::sunshine.log_file.c_str());
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
    headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
    headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);
    response->write(SimpleWeb::StatusCode::success_ok, content, headers);
  }

  void modify_or_add_node(boost::property_tree::ptree &pt, const std::string &guid, const std::string &new_name, const std::string &new_image_path,
  const std::string &new_cmd, const std::string &new_launch_type, const std::string &new_monitor_exe ) {
    bool found = false;
    for (auto &app : pt.get_child("apps")) {
        if (app.second.get<std::string>("guid") == guid) {
            app.second.put("name", new_name);
            app.second.put("custom_image_path", new_image_path);
            app.second.put("cmd", new_cmd);
            app.second.put("launch_type", new_launch_type);
            app.second.put("monitor_exe", new_monitor_exe);
            found = true;
            break;
        }
    }

    if (!found) {
        boost::property_tree::ptree new_app;
        new_app.put("name", new_name);
        new_app.put("guid", guid);
        new_app.put("custom_image_path", new_image_path);
        new_app.put("cmd", new_cmd);
        new_app.put("launch_type", new_launch_type);
        new_app.put("monitor_exe", new_monitor_exe);
       pt.get_child("apps").push_back(std::make_pair("", new_app));
    }
  }

  void
  saveApp(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();
    BOOST_LOG(info) << "save app";
    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);
      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
      headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
      headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);
      response->write(SimpleWeb::StatusCode::success_ok, data.str(), headers);
    });

    //reading and writing app file causes stream disconncet, weired
    if(rtsp_stream::session_count() >= 1)
      return;

    pt::ptree inputTree, fileTree;

    BOOST_LOG(info) << config::stream.file_apps;
    try {
      // TODO: Input Validation
      pt::read_json(ss, inputTree);
      pt::read_json(config::stream.file_apps, fileTree);

#if (RAZER_WEB_API==1)
      auto name = inputTree.get<std::string>("name");
      auto guid = inputTree.get<std::string>("guid");
      auto custom_image_path = inputTree.get<std::string>("custom_image_path");
      auto cmd = inputTree.get<std::string>("cmd");
      auto launchType = inputTree.get<std::string>("launch_type");
      auto monitor_exe = inputTree.get<std::string>("monitor_exe");
      modify_or_add_node(fileTree, guid, name, custom_image_path, cmd, launchType, monitor_exe);

      pt::write_json(config::stream.file_apps, fileTree);
#else
      if (inputTree.get_child("prep-cmd").empty()) {
        inputTree.erase("prep-cmd");
      }

      if (inputTree.get_child("detached").empty()) {
        inputTree.erase("detached");
      }

      auto &apps_node = fileTree.get_child("apps"s);
      int index = inputTree.get<int>("index");

      inputTree.erase("index");

      if (index == -1) {
        apps_node.push_back(std::make_pair("", inputTree));
      }
      else {
        // Unfortunately Boost PT does not allow to directly edit the array, copy should do the trick
        pt::ptree newApps;
        int i = 0;
        for (const auto &kv : apps_node) {
          if (i == index) {
            newApps.push_back(std::make_pair("", inputTree));
          }
          else {
            newApps.push_back(std::make_pair("", kv.second));
          }
          i++;
        }
        fileTree.erase("apps");
        fileTree.push_back(std::make_pair("apps", newApps));
      }
      pt::write_json(config::stream.file_apps, fileTree);
#endif
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "SaveApp: "sv << e.what();

      outputTree.put("status", "false");
      outputTree.put("error", "Invalid Input JSON");
      return;
    }

    outputTree.put("status", "true");
    proc::refresh(config::stream.file_apps);
  }

#if (RAZER_WEB_API==1)
void
  saveMultiApps(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();
    BOOST_LOG(warning) << "Save multiple Apps[ "sv << request->content.size();

    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);
      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
      headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
      headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);
      response->write(SimpleWeb::StatusCode::success_ok, data.str(), headers);
    });

    //reading and writing app file causes stream disconncet, weired
    if(rtsp_stream::session_count() >= 1)
      return;

    pt::ptree inputTree, fileTree;

    BOOST_LOG(info) << config::stream.file_apps;
    try {
      // put 'env' as sunshine old file format
      pt::ptree output_pt;
      output_pt.put("env", "");

      boost::property_tree::ptree apps_pt;
      
      {//put desktop in it first anyway
        boost::property_tree::ptree desktop_pt;
        desktop_pt.put("name", "Desktop");
        desktop_pt.put("guid", DESKTOP_GUID);
        desktop_pt.put("image-path", "desktop.png");
        apps_pt.push_back(std::make_pair("", desktop_pt));
      }

      pt::read_json(ss, inputTree);
      auto apps = inputTree.get_child("apps");

      for (const auto &array_element : apps) {
          boost::property_tree::ptree app_pt;
          for (const auto &node : array_element.second) {
              app_pt.put(node.first, node.second.data());
          }

          //default secitons
          // app_pt.put("output", "");
          // app_pt.put("exclude-global-prep-cmd", "false");
          // app_pt.put("elevated", "false");
          // app_pt.put("auto-detach", "true");
          // app_pt.put("wait-all", "true");
          // app_pt.put("exit-timeout", "5");

          apps_pt.push_back(std::make_pair("", app_pt));
      }

      output_pt.add_child("apps", apps_pt);
      boost::property_tree::write_json(config::stream.file_apps, output_pt);
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "Save multiple Apps: "sv << e.what();

      outputTree.put("status", "false");
      outputTree.put("error", "Invalid Input JSON");
      return;
    }

    outputTree.put("status", "true");
    proc::refresh(config::stream.file_apps);
  }
#endif

  // 
  void delete_node(boost::property_tree::ptree &pt, const std::string &guid) {
    for (auto it = pt.get_child("apps").begin(); it != pt.get_child("apps").end(); ++it) {
        if (it->second.get<std::string>("guid") == guid) {
            pt.get_child("apps").erase(it);
            break;
        }
    }
  }

  void
  deleteApp(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);
      
      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
      headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
      headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);

      response->write(SimpleWeb::StatusCode::success_ok, data.str(), headers);
    });

    //reading and writing app file causes stream disconncet, weired
    if(rtsp_stream::session_count() >= 1)
      return;

    pt::ptree fileTree;
    try {
      pt::read_json(config::stream.file_apps, fileTree);      

      #if RAZER_WEB_API == 1
      std::string guid = request->path_match[1];

      delete_node(fileTree, guid);
      pt::write_json(config::stream.file_apps, fileTree);
      #else
      auto &apps_node = fileTree.get_child("apps"s);
      int index = stoi(request->path_match[1]);

      if (index < 0) {
        outputTree.put("status", "false");
        outputTree.put("error", "Invalid Index");
        return;
      }
      else {
        // Unfortunately Boost PT does not allow to directly edit the array, copy should do the trick
        pt::ptree newApps;
        int i = 0;
        for (const auto &kv : apps_node) {
          if (i++ != index) {
            newApps.push_back(std::make_pair("", kv.second));
          }
        }
        fileTree.erase("apps");
        fileTree.push_back(std::make_pair("apps", newApps));
      }
      pt::write_json(config::stream.file_apps, fileTree);
      #endif
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "DeleteApp: "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", "Invalid File JSON");
      return;
    }

    outputTree.put("status", "true");
    proc::refresh(config::stream.file_apps);
  }

  void
  uploadCover(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    std::stringstream ss;
    std::stringstream configStream;
    ss << request->content.rdbuf();
    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      SimpleWeb::StatusCode code = SimpleWeb::StatusCode::success_ok;
      if (outputTree.get_child_optional("error").has_value()) {
        code = SimpleWeb::StatusCode::client_error_bad_request;
      }

      pt::write_json(data, outputTree);

      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
      headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
      headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);

      response->write(code, data.str(), headers);
    });
    pt::ptree inputTree;
    try {
      pt::read_json(ss, inputTree);
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "UploadCover: "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", e.what());
      return;
    }

    auto key = inputTree.get("key", "");
    if (key.empty()) {
      outputTree.put("error", "Cover key is required");
      return;
    }
    auto url = inputTree.get("url", "");

    const std::string coverdir = platf::appdata().string() + "/covers/";
    if (!boost::filesystem::exists(coverdir)) {
      boost::filesystem::create_directories(coverdir);
    }

    std::basic_string path = coverdir + http::url_escape(key) + ".png";
    if (!url.empty()) {
      if (http::url_get_host(url) != "images.igdb.com") {
        outputTree.put("error", "Only images.igdb.com is allowed");
        return;
      }
      if (!http::download_file(url, path)) {
        outputTree.put("error", "Failed to download cover");
        return;
      }
    }
    else {
      auto data = SimpleWeb::Crypto::Base64::decode(inputTree.get<std::string>("data"));

      std::ofstream imgfile(path);
      imgfile.write(data.data(), (int) data.size());
    }
    outputTree.put("path", path);
  }

  void
  getConfig(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);
      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
      headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
      headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);

      response->write(SimpleWeb::StatusCode::success_ok, data.str(), headers);
    });

    outputTree.put("status", "true");
    outputTree.put("platform", SUNSHINE_PLATFORM);
    outputTree.put("version", PROJECT_VER);

    auto vars = config::parse_config(file_handler::read_file(config::sunshine.config_file.c_str()));

    for (auto &[name, value] : vars) {
      outputTree.put(std::move(name), std::move(value));
    }

    bool hasHostname = outputTree.get_optional<std::string>("sunshine_name").has_value();
    if (hasHostname == false) {
      #if RAZER_MOD == 1
        outputTree.put("sunshine_name", rz_state::GetUTF8HostName());
      #else
        outputTree.put("sunshine_name", boost::asio::ip::host_name());
      #endif
    } 
    
  }

  void
  getLocale(resp_type_t response, req_type_t request) {
    // we need to return the locale whether authenticated or not

    print_req(request);

    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);

      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
      headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
      headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);

      response->write(SimpleWeb::StatusCode::success_ok, data.str(), headers);
    });

    outputTree.put("status", "true");
    outputTree.put("locale", config::sunshine.locale);
  }

  void
  saveConfig(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::stringstream ss;
    std::stringstream configStream;
    ss << request->content.rdbuf();
    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);

      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
      headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
      headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);

      response->write(SimpleWeb::StatusCode::success_ok, data.str(), headers);
    });
    pt::ptree inputTree;
    try {
      // TODO: Input Validation
      pt::read_json(ss, inputTree);
      for (const auto &kv : inputTree) {
        std::string value = inputTree.get<std::string>(kv.first);
        if (value.length() == 0 || value.compare("null") == 0) continue;

        configStream << kv.first << " = " << value << std::endl;
      }
      file_handler::write_file(config::sunshine.config_file.c_str(), configStream.str());
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "SaveConfig: "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", e.what());
      return;
    }
  }

  void
  resetConfig(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    pt::ptree outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);

      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
      headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
      headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);

      response->write(SimpleWeb::StatusCode::success_ok, data.str(), headers);
    });

    config::reset_config();

    //parse again
    auto vars = config::parse_config(file_handler::read_file(config::sunshine.config_file.c_str()));

    outputTree.put("status", "true");
    outputTree.put("platform", SUNSHINE_PLATFORM);
    outputTree.put("version", PROJECT_VER);

    //There should be no vars anymore.
    for (auto &[name, value] : vars) {
      outputTree.put(std::move(name), std::move(value));
    }
  }

  void
  restart(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    // We may not return from this call
    platf::restart();
  }

#if RAZER_WEB_API==1
 void
  shutdown(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    auto g = util::fail_guard([&]() {
        SimpleWeb::CaseInsensitiveMultimap headers;
        headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
        headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
        headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);
        response->write(SimpleWeb::StatusCode::success_ok, headers);
    });
    
    std::stringstream ss;
    ss << request->content.rdbuf();
    pt::ptree inputTree;
    try {      
      pt::read_json(ss, inputTree);
       for (const auto &kv : inputTree) {
         std::string value = inputTree.get<std::string>(kv.first);
         if (value.length() == 0 || value.compare("null") == 0) continue;
          //{ "shutdown_type": "CortexShutdown" }

         if(value=="CortexShutdown")
         {
            platf::force_shutdown(5);
         }

         BOOST_LOG(debug) << kv.first << "= " << value << std::endl;
       }
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "force shutdown: "sv << e.what();
      return;
    }

    print_req(request);

    std::thread t([]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            platf::shutdown();
    });

    t.detach();
    // We may not return from this call
  }
  void
  saveTokens(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::stringstream ss;
    std::stringstream configStream;
    ss << request->content.rdbuf();
    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);

      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
      headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
      headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);

      response->write(SimpleWeb::StatusCode::success_ok, data.str(), headers);
    });
    pt::ptree inputTree;
    try {      
      pt::read_json(ss, inputTree);
       for (const auto &kv : inputTree) {
         std::string value = inputTree.get<std::string>(kv.first);
         if (value.length() == 0 || value.compare("null") == 0) continue;
          if(kv.first == "RazerPairToken")
          {
              config::sunshine.razer_pair_token = value;
          }
          else if(kv.first == "RazerUUID")
          {
              config::sunshine.razer_uuid = value;
          }

          BOOST_LOG(debug) << kv.first << "= " << value << std::endl;
       }
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "SaveTokens: "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", e.what());
      return;
    }
  }

void
  gameStartEvent(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::stringstream ss;
    std::stringstream configStream;
    ss << request->content.rdbuf();
    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);

      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
      headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
      headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);

      response->write(SimpleWeb::StatusCode::success_ok, data.str(), headers);
    });
    pt::ptree inputTree;
    try {      
      pt::read_json(ss, inputTree);
      std::string guid;
      std::string pid;
      std::string startupPath;
      BOOST_LOG(info) << "------ Game start " << std::endl;

      for (const auto &kv : inputTree) {
         std::string value = inputTree.get<std::string>(kv.first);
         if (value.length() == 0 || value.compare("null") == 0) continue;
          if(kv.first == "Guid")
              guid = value;
          if(kv.first == "Pid")
              pid = value;
          if(kv.first == "StartupPath")
              startupPath = value;
         BOOST_LOG(info) << kv.first << " = " << value << std::endl;
       }

       proc::proc.appStart(guid, pid);       
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "game start event: "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", e.what());
      return;
    }
  }
  
void
  gameEndEvent(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();
  
    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);

      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
      headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
      headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);

      response->write(SimpleWeb::StatusCode::success_ok, data.str(), headers);
    });
    try {           
      BOOST_LOG(info) << "-------- Game end : " << ss.str() << std::endl;
      proc::proc.appEnd(ss.str());  
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "game end event: "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", e.what());
      return;
    }
  }

  void
  getCurrentState(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);
      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
      headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
      headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);

      response->write(SimpleWeb::StatusCode::success_ok, data.str(), headers);
    });
    
    auto responseEvent = rz_state::getCurrentState();
    outputTree.put("id", responseEvent.id);  
    outputTree.put("state", responseEvent.state_name);
    outputTree.put("appName", responseEvent.app_name);
    outputTree.put("deviceName", responseEvent.device_name);
    outputTree.put("countdownState", rz_state::IsGameCloseCountdownCounting());
    outputTree.put("countdownRemainingTime", rz_state::GetGameCloseCountdownRemainingTime());
  }

  void
  getRazerIdPairConfig(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);
      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
      headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
      headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);

      response->write(SimpleWeb::StatusCode::success_ok, data.str(), headers);
    });

    outputTree.put("status", "true");

    auto vars = config::parse_config(file_handler::read_file(config::sunshine.config_file.c_str()));

    for (auto &[name, value] : vars) {
      if(name == "RazerIdPairing")
        outputTree.put(std::move(name), std::move(value));
    }
  }
  
  void
  saveRazerIdPairConfig(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::stringstream ss;
    std::stringstream configStream;
    ss << request->content.rdbuf();
    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      pt::write_json(data, outputTree);

      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
      headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
      headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);

      response->write(SimpleWeb::StatusCode::success_ok, data.str(), headers);
    });
    pt::ptree inputTree;
    try {
      pt::ptree fileTree;
      auto vars = config::parse_config(file_handler::read_file(config::sunshine.config_file.c_str()));

      for (auto &[name, value] : vars) {
          fileTree.put(std::move(name), std::move(value));
      }

      pt::read_json(ss, inputTree);
      for (const auto &kv : inputTree) {
        std::string value = inputTree.get<std::string>(kv.first);
        if (value.length() == 0 || value.compare("null") == 0) continue;

        fileTree.put(kv.first, value);
      }

      for (const auto &kv : fileTree) {
        std::string value = fileTree.get<std::string>(kv.first);
        if (value.length() == 0 || value.compare("null") == 0) continue;

        configStream << kv.first << " = " << value << std::endl;
        if(kv.first == "RazerIdPairing")
        {
          config::razerSettings.IDPairing = value;
        }
      }
      file_handler::write_file(config::sunshine.config_file.c_str(), configStream.str());
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "save razer id paring config: "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", e.what());
      return;
    }
  }

  void
  agreeRazerIdPair(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::stringstream ss;
    std::stringstream configStream;
    ss << request->content.rdbuf();
    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
      headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
      headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);

      response->write(SimpleWeb::StatusCode::success_ok, data.str(), headers);
    });
    pt::ptree inputTree;
    try {
      pt::read_json(ss, inputTree);
      for (const auto &kv : inputTree) {
        std::string value = inputTree.get<std::string>(kv.first);
        if (value.length() == 0 || value.compare("null") == 0) continue;
        if(kv.first == "agreeRazeridPair")
        {
          nvhttp::pinLast(value == "true");
        }
      }
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "agree razer id paring "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", e.what());
      return;
    }
  }

  void
  OnPressCountdown(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::stringstream ss;
    std::stringstream configStream;
    ss << request->content.rdbuf();
    pt::ptree outputTree;
    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
      headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
      headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);

      response->write(SimpleWeb::StatusCode::success_ok, data.str(), headers);
    });
    pt::ptree inputTree;
    try {
      pt::read_json(ss, inputTree);
      for (const auto &kv : inputTree) {
        std::string value = inputTree.get<std::string>(kv.first);
        if (value.length() == 0 || value.compare("null") == 0) continue;
        if(kv.first == "PressCancel"){
          rz_state::CancelGameCloseCountdown();
        }

        if(kv.first == "PressX"){
          rz_state::IgnoreGameCloseCountdown();
        }
      }
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "OnPressCountdown "sv << e.what();
      outputTree.put("status", "false");
      outputTree.put("error", e.what());
      return;
    }
  }
#endif

  void
  savePassword(resp_type_t response, req_type_t request) {
    if (!config::sunshine.username.empty() && !authenticate(response, request)) return;

    print_req(request);

    std::stringstream ss;
    std::stringstream configStream;
    ss << request->content.rdbuf();

    pt::ptree inputTree, outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);
      response->write(data.str());
    });

    try {
      // TODO: Input Validation
      pt::read_json(ss, inputTree);
      auto username = inputTree.count("currentUsername") > 0 ? inputTree.get<std::string>("currentUsername") : "";
      auto newUsername = inputTree.get<std::string>("newUsername");
      auto password = inputTree.count("currentPassword") > 0 ? inputTree.get<std::string>("currentPassword") : "";
      auto newPassword = inputTree.count("newPassword") > 0 ? inputTree.get<std::string>("newPassword") : "";
      auto confirmPassword = inputTree.count("confirmNewPassword") > 0 ? inputTree.get<std::string>("confirmNewPassword") : "";
      if (newUsername.length() == 0) newUsername = username;
      if (newUsername.length() == 0) {
        outputTree.put("status", false);
        outputTree.put("error", "Invalid Username");
      }
      else {
        auto hash = util::hex(crypto::hash(password + config::sunshine.salt)).to_string();
        if (config::sunshine.username.empty() || (boost::iequals(username, config::sunshine.username) && hash == config::sunshine.password)) {
          if (newPassword.empty() || newPassword != confirmPassword) {
            outputTree.put("status", false);
            outputTree.put("error", "Password Mismatch");
          }
          else {
            http::save_user_creds(config::sunshine.credentials_file, newUsername, newPassword);
            http::reload_user_creds(config::sunshine.credentials_file);
            outputTree.put("status", true);
          }
        }
        else {
          outputTree.put("status", false);
          outputTree.put("error", "Invalid Current Credentials");
        }
      }
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "SavePassword: "sv << e.what();
      outputTree.put("status", false);
      outputTree.put("error", e.what());
      return;
    }
  }

  void
  savePin(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();

    pt::ptree inputTree, outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;

      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
      headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
      headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);
      
      pt::write_json(data, outputTree);
      response->write(SimpleWeb::StatusCode::success_ok, data.str(), headers);
    });

    try {
      // TODO: Input Validation
      pt::read_json(ss, inputTree);
      std::string pin = inputTree.get<std::string>("pin");
      BOOST_LOG(info) << "user input PIN code = " << pin;
      outputTree.put("status", nvhttp::pin(pin));
    }
    catch (std::exception &e) {
      BOOST_LOG(warning) << "SavePin: "sv << e.what();
      outputTree.put("status", false);
      outputTree.put("error", e.what());
      return;
    }
  }

  void
  unpairAll(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    pt::ptree outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);

      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
      headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
      headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);

      response->write(SimpleWeb::StatusCode::success_ok, data.str(), headers);
    });

    //disconnet the current stream session anyway.
    proc::proc.terminate();

    nvhttp::erase_all_clients();
    outputTree.put("status", true);
  }

  void
  closeApp(resp_type_t response, req_type_t request) {
    if (!authenticate(response, request)) return;

    print_req(request);

    pt::ptree outputTree;

    auto g = util::fail_guard([&]() {
      std::ostringstream data;
      pt::write_json(data, outputTree);

      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Access-Control-Allow-Origin", ACCESS_CONTROL_ALLOW_ORIGIN);
      headers.emplace("Access-Control-Allow-Methods", ACCESS_CONTROL_ALLOW_METHODS);
      headers.emplace("Access-Control-Allow-Headers", ACCESS_CONTROL_ALLOW_HEADERS);

      response->write(SimpleWeb::StatusCode::success_ok, data.str(), headers);
    });

    proc::proc.terminate();
    outputTree.put("status", true);
  }

  void
  start() {
    auto shutdown_event = mail::man->event<bool>(mail::shutdown);

    auto port_https = net::map_port(PORT_HTTPS);
    //auto address_family = net::af_from_enum_string(config::sunshine.address_family);
#if SERVER_HTTP
    type_server_t server;
#else
    type_server_t server{ config::nvhttp.cert, config::nvhttp.pkey };
#endif

#ifdef ENABLE_SUNSHINE_WEB_UI
    server.default_resource["GET"] = not_found;
#endif
    server.default_resource["OPTIONS"] = [](resp_type_t response, req_type_t request) {
    *response << "HTTP/1.1 204 No Content\r\n"
              << "Access-Control-Allow-Origin: *\r\n" // set CORS 
              << "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n" // set allow method
              << "Access-Control-Allow-Headers: Content-Type\r\n" // set allow header
              << "Content-Length: 0\r\n"
              << "\r\n";
    };

#ifdef ENABLE_SUNSHINE_WEB_UI
    server.resource["^/$"]["GET"] = getIndexPage;
    server.resource["^/pin/?$"]["GET"] = getPinPage;
    server.resource["^/apps/?$"]["GET"] = getAppsPage;
    server.resource["^/clients/?$"]["GET"] = getClientsPage;
    server.resource["^/config/?$"]["GET"] = getConfigPage;
    server.resource["^/password/?$"]["GET"] = getPasswordPage;
    server.resource["^/welcome/?$"]["GET"] = getWelcomePage;
    server.resource["^/troubleshooting/?$"]["GET"] = getTroubleshootingPage;
#endif
    server.resource["^/api/pin$"]["POST"] = savePin;
    server.resource["^/api/apps$"]["GET"] = getApps;
    server.resource["^/api/logs$"]["GET"] = getLogs;
    server.resource["^/api/apps$"]["POST"] = saveApp;
    server.resource["^/api/config$"]["GET"] = getConfig;
    server.resource["^/api/config$"]["POST"] = saveConfig;
    server.resource["^/api/configLocale$"]["GET"] = getLocale;
    server.resource["^/api/restart$"]["POST"] = restart;
    server.resource["^/api/password$"]["POST"] = savePassword;
    #if RAZER_WEB_API==1
    server.resource["^/api/multiApps$"]["POST"] = saveMultiApps;
    server.resource["^/api/gameStart$"]["POST"] = gameStartEvent;
    server.resource["^/api/gameEnd$"]["POST"] = gameEndEvent;
    server.resource["^/api/resetConfig$"]["POST"] = resetConfig;
    server.resource["^/api/shutdown$"]["POST"] = shutdown;
    server.resource["^/api/tokens$"]["POST"] = saveTokens;
    server.resource["^/api/currentState$"]["GET"] = getCurrentState;
    server.resource["^/api/apps/([0-9a-fA-F-]+)$"]["DELETE"] = deleteApp;
    server.resource["^/api/razeridPair$"]["GET"] = getRazerIdPairConfig;
    server.resource["^/api/razeridPair$"]["POST"] = saveRazerIdPairConfig;
    server.resource["^/api/agreeRazeridPair$"]["POST"] = agreeRazerIdPair;    
    server.resource["^/api/countdown$"]["POST"] = OnPressCountdown;    
    #else
    server.resource["^/api/apps/([0-9]+)$"]["DELETE"] = deleteApp;
    #endif
    server.resource["^/api/clients/unpair$"]["POST"] = unpairAll;
    server.resource["^/api/apps/close$"]["POST"] = closeApp;
    server.resource["^/api/covers/upload$"]["POST"] = uploadCover;
    server.resource["^/images/RazerRemotePlayHost.ico$"]["GET"] = getFaviconImage;
    server.resource["^/images/logo-sunshine-45.png$"]["GET"] = getSunshineLogoImage;
    server.resource["^/assets\\/.+$"]["GET"] = getNodeModules;
    server.config.reuse_address = true;
    server.config.address = "127.0.0.1";//net::af_to_any_address_string(address_family);
    server.config.port = port_https;

    auto accept_and_run = [&](auto *server) {
      try {
        server->start([](unsigned short port) {
          #if SERVER_HTTP
          BOOST_LOG(info) << "Configuration UI available at [http://localhost:"sv << port << "]";
          #else
          BOOST_LOG(info) << "Configuration UI available at [https://localhost:"sv << port << "]";
          #endif
        });
      }
      catch (boost::system::system_error &err) {
        // It's possible the exception gets thrown after calling server->stop() from a different thread
        if (shutdown_event->peek()) {
          return;
        }

        BOOST_LOG(fatal) << "Couldn't start Configuration HTTPS server on port ["sv << port_https << "]: "sv << err.what();
        rz_state::message_state_t tmpmsg;
        rz_state::SendEventToCortex(rz_state::CortexEvent::Cortex_Event_Change_HTTP_Port, tmpmsg);
        shutdown_event->raise(true);
        return;
      }
    };
    std::thread tcp { accept_and_run, &server };

    // Wait for any event
    shutdown_event->view();

    server.stop();

    tcp.join();
  }
}  // namespace confighttp
