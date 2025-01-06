#pragma once
#include <Windows.h>
#include <iostream>
#include "tchar.h"

#define FILE_MAPPING_NAME_NEURON_FROM_HOST _T( "\\\\.\\pipe\\RzNeuronFileMap1r" )
#define RAZER_EVENT_NAME _T("RzNeuronPipeMessageProcessed")


// host to Cortex
struct EventHostToCortex 
{
    DWORD dwProtocol = -1;
    char data[MAX_PATH*2] = {};
    char param[MAX_PATH*2] = {};

    EventHostToCortex& operator=(const EventHostToCortex& other) 
    {
        if (this != &other) {
            dwProtocol = other.dwProtocol;
            strcpy_s(data, MAX_PATH * 2, other.data);
            strcpy_s(param, MAX_PATH * 2, other.param);
        }
        return *this;
    }

    ~EventHostToCortex() {
    }

    bool operator==(const EventHostToCortex& other) const {
        return dwProtocol == other.dwProtocol &&
            strcmp(data, other.data) == 0 &&
            strcmp(param, other.param) == 0;
    }
};


class NamedPipeWriter
{
public:
	NamedPipeWriter(const std::string& pipeName, const std::string& eventName) : pipeName_(pipeName),  eventName_(eventName){
        // open existed event
        hEvent_ = OpenEvent(SYNCHRONIZE, FALSE, eventName_.c_str());
    }

	bool Create() {
		hPipe_ = CreateNamedPipe(
			pipeName_.c_str(),
			PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES,
			0, 0, 0, NULL);

		return (hPipe_ != INVALID_HANDLE_VALUE);
	}

	bool Connect() {
		return ConnectNamedPipe(hPipe_, NULL);
	}

    template<typename T>
	bool Write(const T& data) {
		DWORD bytesWritten;
		bool result = WriteFile(hPipe_, &data, sizeof(decltype(data)), &bytesWritten, NULL);
		return (result /*&& bytesWritten == sizeof(decltype(data))*/ );
	}

    void waitSignal(){        
        if (WaitForSingleObject(hEvent_, INFINITE) == WAIT_OBJECT_0) {
            std::wcout << L"Message processed by reader." << std::endl;
            ResetEvent(hEvent_);
        }
    }

	void Close() {
		if (hPipe_ != INVALID_HANDLE_VALUE) {
			CloseHandle(hPipe_);
			hPipe_ = INVALID_HANDLE_VALUE;
		}

        if (hEvent_ != NULL) {
            CloseHandle(hEvent_);
            hEvent_ = NULL;
        }
	}

	~NamedPipeWriter() {
		Close();
	}

private:
	std::string pipeName_;
    std::string eventName_;
	HANDLE hPipe_ = INVALID_HANDLE_VALUE;
    HANDLE hEvent_ = NULL;  //
};

class NamedPipeReader {
public:
    NamedPipeReader() = default;
    void SetPipeName(const std::string& pipeName) { pipeName_ = pipeName; }

    bool Connect() {
        hPipe_ = CreateFile(
            pipeName_.c_str(),
            GENERIC_READ,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);

        return (hPipe_ != INVALID_HANDLE_VALUE);
    }

    template<typename R>
    bool Read(R& data) {
        DWORD bytesRead;
        bool result = ReadFile(hPipe_, &data, sizeof(decltype(data)), &bytesRead, NULL);

#if _DEBUG
        auto structSize = sizeof(decltype(data));
#endif
        return (result/* && bytesRead == sizeof(decltype(data))*/);
    }

    template<typename R>
    bool ReadEx(R& data, DWORD timeout_ms) {
        DWORD bytesRead;
        OVERLAPPED overlapped = { 0 };
        overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

        ReadFileEx(hPipe_, &data, sizeof(decltype(data)), &overlapped, [](DWORD dwErrorCode, DWORD dwNumberOfBytesTransfered, LPOVERLAPPED lpOverlapped) {
            // Completion routine not needed in this case.
            });

        if (WaitForSingleObject(overlapped.hEvent, timeout_ms) == WAIT_TIMEOUT) {
            CloseHandle(overlapped.hEvent);
            return false; // Timeout
        }

        GetOverlappedResult(hPipe_, &overlapped, &bytesRead, FALSE);

#if _DEBUG
        auto structSize = sizeof(decltype(data));
#endif

        CloseHandle(overlapped.hEvent);
        return true;
    }

    void Close() {
        if (hPipe_ != INVALID_HANDLE_VALUE) {
            CloseHandle(hPipe_);
            hPipe_ = INVALID_HANDLE_VALUE;
        }
    }

    ~NamedPipeReader() {
        Close();
    }

private:
    std::string pipeName_;
    HANDLE hPipe_;
};