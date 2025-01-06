#include "RazerState.h"
#include "process.h"
#include "utility.h"
#include <mutex>
#include <queue>
#include <windows.h>
#include "RazerNamedPipe.h"
#include "logging.h"
#include "globals.h"
#include <chrono>
#include "rtsp.h"
#include <tlhelp32.h>
#include <nlohmann/json.hpp>
#ifdef _WIN32
  // from_utf8() string conversion function
  #include "platform/windows/misc.h"
#endif

namespace rz_state{

    message_state_t clientState
    {
        0,
        "unknown",
        "",
    };

    bool _IsVirtualDisplayCreated = false;

    //count down
    std::string _countdownTimer = "";
    Countdown _countdown;
    bool _ignoreCountdown = false;

    void updateCurrentState(std::string state_name, std::string app_name, std::string device_name)
    {
        //auto lg = std::lock_guard(_event_mutex);
        clientState.id++;
        clientState.state_name = state_name;
        clientState.app_name = app_name;
        clientState.device_name = device_name;
        message_state_t tmpmsg;
        tmpmsg.state_name = state_name;
        tmpmsg.app_name = app_name;
        tmpmsg.device_name = device_name;
        SendEventToCortex(Corte_Event_Notification, tmpmsg);
        //BOOST_LOG(info) << "  state id=" << clientState.id << " name=" << clientState.state_name << " app_name=" << clientState.app_name << " devic_name=" << clientState.device_name;
    }

    message_state_t getCurrentState()
    {
        // auto g = util::fail_guard([&]() {
        //     auto lg = std::lock_guard(_event_mutex);
        //     event.id++;
        //     event.app_name="";
        //     event.state_name="unknown";
        // });

        return clientState;
    }

    bool m_isPipeReady = false;
    std::deque<EventHostToCortex*>  m_vecFpsCommand;
    std::mutex m_mutexFpsCommand;
    bool m_currentEventACK = false;

    bool isProcessRunning(const std::string &processName) {
        HANDLE hProcessSnap;
        PROCESSENTRY32 pe32;
        hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (hProcessSnap == INVALID_HANDLE_VALUE) {
            BOOST_LOG(error) << "Failed to create process snapshot." << std::endl;
            return false;
        }

        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(hProcessSnap, &pe32)) {
            CloseHandle(hProcessSnap);
            BOOST_LOG(error) << "Failed to retrieve process information." << std::endl;
            return false;
        }

        do {
            if (processName == pe32.szExeFile) {
                CloseHandle(hProcessSnap);
                return true;
            }
        } while (Process32Next(hProcessSnap, &pe32));

        CloseHandle(hProcessSnap);
        return false;
    }

    void Heartbeat(){
        std::string processName = "RazerCortex.exe";
        auto shutdown_event = mail::man->event<bool>(mail::shutdown);
        while (true) {
            if (shutdown_event->peek()) {
                return;
            }

            if (isProcessRunning(processName)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(3000));

            } else {
                if (shutdown_event->peek()) {
                    return;
                }
                BOOST_LOG(warning) << "Cortex is not running, exit host";
                shutdown_event->raise(true);
                return;
            }            
        }
    }

    void StartEventThread(){
        auto shutdown_event = mail::man->event<bool>(mail::shutdown);

        NamedPipeWriter writerPipe(FILE_MAPPING_NAME_NEURON_FROM_HOST, RAZER_EVENT_NAME);

        if (writerPipe.Create() == false){
            BOOST_LOG(error) << "Failed to create pipe: error " << GetLastError();
                return;
            }

        BOOST_LOG(info) << "try to connect event pipeline";
        if (writerPipe.Connect() == false){
                BOOST_LOG(error) << "Failed to connect to overlay parse named pipe: ", GetLastError();
                return;
            }

        m_isPipeReady = true;
        BOOST_LOG(info) << "event pipeline connected";
        BOOST_LOG(info) << "Mount Razer Virtual controller..";
        rz_state::updateEvent(Command_Protocol_VirtualController_MountDriver, "Start", "");
        
        BOOST_LOG(info) << "Mount Razer Audio controller..";
        rz_state::updateEvent(Command_Protocol_VirtualAudio_MountDriver, "Start", "");

        int failTryCount = 0;
        while (!shutdown_event->peek()){
            UINT uSize = 0;
            //when the setting list has content, then we handle it
            {
                std::lock_guard<std::mutex> lock(m_mutexFpsCommand);
                uSize = m_vecFpsCommand.size();
            }

            if(0 == uSize){
            Sleep(10);
            continue;
            }

            //pop command
            EventHostToCortex data;
            {
                std::lock_guard<std::mutex> lock(m_mutexFpsCommand);
                if (!m_vecFpsCommand.empty())
                {
                    auto it = m_vecFpsCommand.front();
                    if (it)
                    {
                    data = *(it);
                    if(it)
                        delete it;
                    m_vecFpsCommand.pop_front();
                    }
                }
            }

            //send command to fpsrunner
            if (writerPipe.Write(data) == false){
                DWORD dwError = GetLastError();
                BOOST_LOG(error) << "event thread failed to write data: " <<  dwError;
                if (dwError == ERROR_NO_DATA){
                    failTryCount++;
                    if (failTryCount == 20){
                    //fpsrunner.exe exit					
                    break;
                    }
                }
            }
            else{
                writerPipe.waitSignal();
                m_currentEventACK = true;
                failTryCount = 0;
            }
            
            Sleep(10);
        }

        BOOST_LOG(info) << "Event thread end ";
        return;
    }

#define WM_PLUGIN                   (WM_USER + 1)       //
#define WM_DISABLE_DEVICE           (WM_USER + 2)       // 
#define WM_ENABLE_DEVICE            (WM_USER + 3)       //
#define WM_PLUGOUT                  (WM_USER + 4)       // Destory deivce

    void SendStringMessage(HWND hwnd, DWORD msgID, const wchar_t* message) {
        COPYDATASTRUCT cds;
        cds.dwData = msgID;  
        cds.cbData = (wcslen(message) + 1) * sizeof(wchar_t);
        cds.lpData = (void*)message;

        SendMessage(hwnd, WM_COPYDATA, (WPARAM)nullptr, (LPARAM)&cds);
    }

    void SendStringMessageA(HWND hwnd, DWORD msgID, const char* message) {
        COPYDATASTRUCT cds;
        cds.dwData = msgID;  
        cds.cbData = (DWORD)((strlen(message) + 1) * sizeof(char));
        cds.lpData = (void*)message;

        SendMessage(hwnd, WM_COPYDATA, (WPARAM)nullptr, (LPARAM)&cds);
    }

    void SendMessageToUserWindow(DWORD msgID, const char* param)
    {
        HWND hwnd = FindWindow("RzVirDisp Window Class", "RzVirDisp Window");

        if (hwnd == nullptr) {
            return;
        }

        // send user-define PLUGIN/PLUGOUT Message
        SendStringMessageA(hwnd, msgID, param);
    }

    void SendMessageToService(int eventID, std::string data, std::string param, bool wait = true){
        if(m_isPipeReady == false)
        {
            BOOST_LOG(warning) << "pipeline offline!"; 
            return;
        }

        EventHostToCortex* event = new EventHostToCortex;
        if (!event)        {
            BOOST_LOG(warning) << "out of memory!";
        }
        event->dwProtocol = eventID;
        strcpy_s(event->param, MAX_PATH * 2, param.c_str());
        strcpy_s(event->data, MAX_PATH * 2, data.c_str());
        //event->dwParam1 = index;
        //event->dwParam2 = value;
        {
            m_currentEventACK = false;
            std::lock_guard<std::mutex> lock(m_mutexFpsCommand);
            m_vecFpsCommand.push_back(event);
        }

        if(wait)
            waitForEvent();      
    }


    void updateEvent(int eventID, std::string data, std::string param){      
        DWORD msgID;
        switch(eventID){
            case Command_Protocol_VirtualDisplay_Plugin:{
                SendMessageToService(eventID, data, param);     
                _IsVirtualDisplayCreated = true; 
            }
            break;

            // case Command_Protocol_VirtualDisplay_Disable:{
            //     msgID = WM_DISABLE_DEVICE;
            //     SendMessageToUserWindow(msgID, param.c_str());
            // }
            // break;

            // case Command_Protocol_VirtualDisplay_Enable:{
            //     msgID = WM_ENABLE_DEVICE;
            //     SendMessageToUserWindow(msgID, param.c_str());
            // }
            // break;

            case Command_Protocol_VirtualDisplay_Plugout:{
                msgID = WM_PLUGOUT;
                SendMessageToUserWindow(msgID, param.c_str());
                _IsVirtualDisplayCreated = false;
            }
            break;

            case Command_Protocol_VirtualController_MountDriver:{
                SendMessageToService(eventID, data, param, false);
            }
            break;
            case Command_Protocol_VirtualAudio_MountDriver:{
                SendMessageToService(eventID, data, param, false);
            }
            break;
        }

    }

    bool IsVirtualDisplayCreated(){
        return _IsVirtualDisplayCreated;
    }

    void waitForEvent(){
        int timeout = 5000;
        while(m_currentEventACK==false){
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            timeout--;
            if(timeout<0)
            {
                break;
            }
        }
    }

    void SetCountdownTimer(std::string seconds){
        _countdownTimer = seconds;
    }

    std::string GetCountdownTimer(){
        return _countdownTimer;
    }

    void onCountdownComplete() {
        BOOST_LOG(info) << "coutndown end, close the game application\n";
        _ignoreCountdown = true;
        proc::proc.kill_running_game();
        BOOST_LOG(info) << "kill_running_game end";
    }

    int SendNormalEvent(int eventID){
        message_state_t tmpmsg;
        tmpmsg.state_name = "";
        SendEventToCortex(CortexEvent(eventID), tmpmsg);
        return 0;
    }

    void StartGameCloseCountdown(){
        if(_countdownTimer != "-1"){ //user don't set this value
            message_state_t tmpmsg;
            tmpmsg.countdown_timer = _countdownTimer.c_str();
            SendEventToCortex(CortexEvent::Cortex_Event_Start_QuitGame_Countdown, tmpmsg);

            if(_countdown.isCountingDown() == false){
                _ignoreCountdown = false;
                _countdown.start(std::atoi(_countdownTimer.c_str()), onCountdownComplete);
            }
            else{
                BOOST_LOG(info) << "coutndown already started";
            }
        }
    }

    void CancelGameCloseCountdown(){
        if(_countdown.isCountingDown() == true){
            _ignoreCountdown = true;
            _countdown.cancel();
        }

    }

    void ForceStopGameCloseCountdown(){
        if(_countdown.isCountingDown()){
            _ignoreCountdown = true;
            _countdown.finishNow([]{});
        }
    }

    int GetGameCloseCountdownRemainingTime(){
        if(_countdown.isCountingDown())
            return _countdown.getRemainingTime();
        else
            return -1;
    }

    int IsGameCloseCountdownCounting(){
        if(!_ignoreCountdown)
            return _countdown.isCountingDown() == true ? 0: 1;
        else
            return -1;
    }

    void IgnoreGameCloseCountdown(){
        _ignoreCountdown = true;
    }

    void SendEventToCortex(unsigned int eventID, message_state_t msg){
        //BOOST_LOG(warning) << "enter SendEventToCortex =>";
        HWND hwnd = FindWindow("RazerCortexHostWindowClass", "Razer Cortex Log");
        //BOOST_LOG(warning) << " - FindWindow cortex: last error:" << GetLastError();
        if (hwnd == nullptr) {
            BOOST_LOG(warning) << " - cannot find Cortex window";
            return;
        }

        //serialize to json
        try{
            nlohmann::json obj;
            obj["event_id"] = eventID;
            if(msg.state_name.length() > 0)
                obj["state_name"] = msg.state_name;

            if(msg.app_name.length() > 0)
                obj["app_name"] = msg.app_name;

            //if(msg.device_name.length() > 0)    
            //    obj["device_name"] = msg.device_name;

            if(msg.countdown_timer.length() > 0)    
                obj["countdown_timer"] = msg.countdown_timer;

            std::string serialized = obj.dump();
            BOOST_LOG(info) << "Send message to Cortex :";
            BOOST_LOG(info) << "    - " << serialized;

            //  0x8000 + 100 hardcode message defination
            SendStringMessage(hwnd, 0x8000 + 100, platf::from_utf8(serialized).c_str());
            //SendMessage(hwnd, 0x8000 + 100, (WPARAM)eventID, (LPARAM)eventParam);        
            //BOOST_LOG(warning) << " - sent message to cortex: last error:" << GetLastError();
        }
        catch(std::exception &e){
            BOOST_LOG(error) << "send to cortex error :" << e.what();
        }       
    }

    std::string GetUTF8HostName() {
        wchar_t hostname[1000];
        DWORD size = sizeof(hostname) / sizeof(hostname[0]);
        if (GetComputerNameW(hostname, &size)) {
            // Convert UTF-16 to UTF-8
            int utf8Size = WideCharToMultiByte(CP_UTF8, 0, hostname, -1, nullptr, 0, nullptr, nullptr);
            std::string utf8Hostname(utf8Size - 1, '\0');
            WideCharToMultiByte(CP_UTF8, 0, hostname, -1, &utf8Hostname[0], utf8Size, nullptr, nullptr);

            BOOST_LOG(info) << " Host name = " << utf8Hostname;
            return utf8Hostname;
        }
        return "Unknown Host";
    }
}//namespace rz_state
