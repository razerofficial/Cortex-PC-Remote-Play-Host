/**
 * @file src/RazerID.h
 * @brief Store Razer id, token, jwt , etc.
 */
#pragma once
#include <iostream>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <chrono>
#include <functional>

namespace rz_state{
    struct message_state_t {
        int id;
        std::string state_name;   //could be null     
        std::string app_name; //could be null
        std::string device_name; //could be null
        std::string countdown_timer; //could be null
    };

    void updateCurrentState(std::string state_name, std::string app_name, std::string device_name);
    message_state_t getCurrentState();

#define Command_Protocol_VirtualDisplay_InstallDriver                        1
#define Command_Protocol_VirtualDisplay_UninstallDriver                      2
#define Command_Protocol_VirtualDisplay_Plugin                               3
//#define Command_Protocol_VirtualDisplay_Disable                              4
//#define Command_Protocol_VirtualDisplay_Enable                               5
#define Command_Protocol_VirtualDisplay_Plugout                              6


#define Command_Protocol_VirtualController_InstallDriver                     10
#define Command_Protocol_VirtualController_UninstallDriver                   11
#define Command_Protocol_VirtualController_MountDriver                       12
#define Command_Protocol_VirtualAudio_MountDriver                            13

    class Countdown {
    public:
        Countdown() : is_canceled(false), remaining_time(0) {}

        Countdown(const Countdown&) = delete;
        Countdown& operator=(const Countdown&) = delete;

        void start(int seconds, std::function<void()> on_complete) {
            cancel();

            is_canceled = false;
            remaining_time = seconds;
            countdown_thread = std::thread([this, seconds, on_complete]() {
                for (int i = 0; i < seconds; ++i) {
                    {
                        std::unique_lock<std::mutex> lock(mtx);
                        if (cv.wait_for(lock, std::chrono::seconds(1), [this]() { return is_canceled; })) {
                            return;
                        }
                        --remaining_time;
                    }
                }
                if (!is_canceled) {
                    on_complete();
                }
            });
        }

        int getRemainingTime() {
            std::lock_guard<std::mutex> lock(mtx);
            return remaining_time;
        }

        bool isCountingDown() {
            std::lock_guard<std::mutex> lock(mtx);
            return !is_canceled && remaining_time > 0;
        }

        void cancel() {
            {
                std::lock_guard<std::mutex> lock(mtx);
                is_canceled = true;
            }
            cv.notify_all();
            if (countdown_thread.joinable()) {
                countdown_thread.join();
            }
        }

        void finishNow(std::function<void()> on_complete) {
            {
                std::lock_guard<std::mutex> lock(mtx);
                is_canceled = true;
            }
            cv.notify_all();
            if (countdown_thread.joinable()) {
                countdown_thread.join();
            }
            on_complete();
        }

        ~Countdown() {
            cancel();
        }

    private:
        bool is_canceled;
        std::thread countdown_thread;
        std::mutex mtx;
        std::condition_variable cv;
        int remaining_time;
    };

    void Heartbeat();
    void StartEventThread();
    void updateEvent(int eventID, std::string data, std::string param);
    bool IsVirtualDisplayCreated();

    void waitForEvent();
    
    void SetCountdownTimer(std::string seconds);
    std::string GetCountdownTimer();

    int SendNormalEvent(int eventID);
    void StartGameCloseCountdown();
    void CancelGameCloseCountdown();
    void ForceStopGameCloseCountdown();
    int GetGameCloseCountdownRemainingTime();
    int IsGameCloseCountdownCounting();
    void IgnoreGameCloseCountdown(); // let it count and execute complete event. just return a flag to UI

    void SendEventToCortex(unsigned int eventID, message_state_t msg);

    std::string GetUTF8HostName();

    enum CortexEvent{
        //http port
        Cortex_Event_Change_HTTP_Port = 1,

        //virtual display error
        Cortex_Event_Error_VirtualDisplay = 2,

        //notification
        Corte_Event_Notification = 3,

        //Quit game countdown
        Cortex_Event_Start_QuitGame_Countdown = 4,
        Cortex_Event_Cancel_QuitGame_Countdown = 5,
        Cortex_Event_ForceStop_QuitGame_Countdown = 6,

        Cortex_Event_RazerID_pair_Success = 7,
        Cortex_Event_RazerID_pair_Failed = 8,
        Cortex_Event_RazerID_pair_Deny = 9,
        Cortex_Event_MAX
    };

}