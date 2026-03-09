// dllmain.cpp : Enhanced AMSI monitoring DLL
#include "pch.h"
#include <Windows.h>
#include <stdio.h>
#include <string>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <mutex>

// Configuration
#define LOG_TO_CONSOLE
#define LOG_TO_FILE
#define LOG_FILE L"C:\\temp\\amsi_monitor.log"
#define MAX_LOG_LINE_SIZE 4096

typedef struct HAMSICONTEXT {
    DWORD       Signature;         // "AMSI" or 0x49534D41
    PWCHAR      AppName;           // set by AmsiInitialize
    DWORD       Antimalware;       // set by AmsiInitialize
    DWORD       SessionCount;      // increased by AmsiOpenSession
} HAMSICONTEXT;

typedef enum AMSI_RESULT {
    AMSI_RESULT_CLEAN,
    AMSI_RESULT_NOT_DETECTED,
    AMSI_RESULT_BLOCKED_BY_ADMIN_START,
    AMSI_RESULT_BLOCKED_BY_ADMIN_END,
    AMSI_RESULT_DETECTED
} AMSI_RESULT;

typedef struct HAMSISESSION {
    DWORD SessionId;
    PVOID Context;
} HAMSISESSION;

// Global variables
std::mutex g_logMutex;
std::wofstream g_logFile;
bool g_bInitialized = false;

// Function prototypes for original AMSI functions
typedef HRESULT(WINAPI* AmsiInitializeT)(LPCWSTR, HAMSICONTEXT*);
typedef HRESULT(WINAPI* AmsiOpenSessionT)(HAMSICONTEXT*, HAMSISESSION*);
typedef VOID(WINAPI* AmsiCloseSessionT)(HAMSICONTEXT*, HAMSISESSION*);
typedef HRESULT(WINAPI* AmsiScanBufferT)(HAMSICONTEXT*, PVOID, ULONG, LPCWSTR, HAMSISESSION*, AMSI_RESULT*);
typedef HRESULT(WINAPI* AmsiScanStringT)(HAMSICONTEXT*, LPCWSTR, LPCWSTR, HAMSISESSION*, AMSI_RESULT*);
typedef VOID(WINAPI* AmsiUninitializeT)(HAMSICONTEXT*);
typedef HRESULT(WINAPI* AmsiNotifyOperationT)(HAMSICONTEXT*, PVOID, DWORD, LPCWSTR, DWORD);

// Original function pointers
AmsiInitializeT pAmsiInitialize = nullptr;
AmsiOpenSessionT pAmsiOpenSession = nullptr;
AmsiCloseSessionT pAmsiCloseSession = nullptr;
AmsiScanBufferT pAmsiScanBuffer = nullptr;
AmsiScanStringT pAmsiScanString = nullptr;
AmsiUninitializeT pAmsiUninitialize = nullptr;
AmsiNotifyOperationT pAmsiNotifyOperation = nullptr;

// Helper function to get current timestamp
std::wstring GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    
    std::tm bt;
    localtime_s(&bt, &in_time_t);
    
    std::wstringstream ss;
    ss << std::put_time(&bt, L"%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// Helper function to log messages
void LogMessage(const std::wstring& message) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    
#ifdef LOG_TO_CONSOLE
    wprintf(L"%s\n", message.c_str());
#endif
    
#ifdef LOG_TO_FILE
    if (g_logFile.is_open()) {
        g_logFile << GetCurrentTimestamp() << L" - " << message << std::endl;
        g_logFile.flush();
    }
#endif
}

// Helper function to get AMSI result string
LPCWSTR GetAmsiResultString(AMSI_RESULT result) {
    switch (result) {
        case AMSI_RESULT_CLEAN: return L"CLEAN";
        case AMSI_RESULT_NOT_DETECTED: return L"NOT_DETECTED";
        case AMSI_RESULT_BLOCKED_BY_ADMIN_START: return L"BLOCKED_BY_ADMIN_START";
        case AMSI_RESULT_BLOCKED_BY_ADMIN_END: return L"BLOCKED_BY_ADMIN_END";
        case AMSI_RESULT_DETECTED: return L"DETECTED";
        default: return L"UNKNOWN";
    }
}

// Safe string conversion for logging
std::wstring SafeString(LPCWSTR str, size_t maxLen = 256) {
    if (!str) return L"<null>";
    
    std::wstring result;
    size_t len = 0;
    
    while (str[len] && len < maxLen) {
        if (iswprint(str[len])) {
            result += str[len];
        } else {
            wchar_t buf[8];
            swprintf_s(buf, L"\\x%04X", str[len]);
            result += buf;
        }
        len++;
    }
    
    if (len >= maxLen) result += L"...";
    return result;
}

// Safe buffer conversion for logging
std::wstring SafeBuffer(PVOID buffer, ULONG length, size_t maxBytes = 64) {
    if (!buffer || length == 0) return L"<empty>";
    
    std::wstring result;
    PBYTE bytes = (PBYTE)buffer;
    ULONG bytesToLog = min(length, maxBytes);
    
    // Try to interpret as string if all bytes are printable ASCII/Unicode
    bool printable = true;
    for (ULONG i = 0; i < bytesToLog && printable; i++) {
        if (bytes[i] < 0x20 || bytes[i] > 0x7E) printable = false;
    }
    
    if (printable && bytesToLog > 0) {
        // Log as ASCII string
        char* str = (char*)buffer;
        result = L"\"";
        for (ULONG i = 0; i < bytesToLog; i++) {
            result += (wchar_t)str[i];
        }
        if (bytesToLog < length) result += L"...";
        result += L"\"";
    } else {
        // Log as hex
        result = L"0x";
        for (ULONG i = 0; i < bytesToLog; i++) {
            wchar_t buf[4];
            swprintf_s(buf, L"%02X", bytes[i]);
            result += buf;
        }
        if (bytesToLog < length) {
            wchar_t buf[16];
            swprintf_s(buf, L" (+%d more bytes)", length - bytesToLog);
            result += buf;
        }
    }
    
    return result;
}

/*
    ============== Hooked AMSI Functions ==============
*/

extern "C" __declspec(dllexport) HRESULT WINAPI AmsiInitialize(
    LPCWSTR appName,
    HAMSICONTEXT* amsiContext
) {
    HRESULT hr = pAmsiInitialize ? pAmsiInitialize(appName, amsiContext) : E_FAIL;
    
    std::wstringstream ss;
    ss << L"AmsiInitialize - App: " << SafeString(appName) 
       << L" | Context: 0x" << std::hex << (ULONG_PTR)amsiContext
       << L" | Result: 0x" << std::hex << hr;
    
    if (SUCCEEDED(hr) && amsiContext) {
        ss << L" | Signature: 0x" << std::hex << amsiContext->Signature
           << L" | SessionCount: " << std::dec << amsiContext->SessionCount;
    }
    
    LogMessage(ss.str());
    return hr;
}

extern "C" __declspec(dllexport) HRESULT WINAPI AmsiOpenSession(
    HAMSICONTEXT* amsiContext,
    HAMSISESSION* amsiSession
) {
    HRESULT hr = pAmsiOpenSession ? pAmsiOpenSession(amsiContext, amsiSession) : E_FAIL;
    
    std::wstringstream ss;
    ss << L"AmsiOpenSession - Context: 0x" << std::hex << (ULONG_PTR)amsiContext;
    
    if (SUCCEEDED(hr) && amsiSession) {
        ss << L" | Session ID: 0x" << std::hex << amsiSession->SessionId;
    }
    
    ss << L" | Result: 0x" << std::hex << hr;
    LogMessage(ss.str());
    
    return hr;
}

extern "C" __declspec(dllexport) VOID WINAPI AmsiCloseSession(
    HAMSICONTEXT* amsiContext,
    HAMSISESSION* amsiSession
) {
    std::wstringstream ss;
    ss << L"AmsiCloseSession - Context: 0x" << std::hex << (ULONG_PTR)amsiContext;
    
    if (amsiSession) {
        ss << L" | Session ID: 0x" << std::hex << amsiSession->SessionId;
    }
    
    LogMessage(ss.str());
    
    if (pAmsiCloseSession) {
        pAmsiCloseSession(amsiContext, amsiSession);
    }
}

extern "C" __declspec(dllexport) HRESULT WINAPI AmsiScanBuffer(
    HAMSICONTEXT* amsiContext,
    PVOID buffer,
    ULONG length,
    LPCWSTR contentName,
    HAMSISESSION* amsiSession,
    AMSI_RESULT* result
) {
    AMSI_RESULT originalResult = AMSI_RESULT_CLEAN;
    HRESULT hr = pAmsiScanBuffer ? 
        pAmsiScanBuffer(amsiContext, buffer, length, contentName, amsiSession, &originalResult) : E_FAIL;
    
    // Log the scan
    std::wstringstream ss;
    ss << L"AmsiScanBuffer - Content: " << SafeString(contentName)
       << L" | Length: " << length
       << L" | Buffer: " << SafeBuffer(buffer, length)
       << L" | Original Result: " << GetAmsiResultString(originalResult);
    
    if (amsiSession) {
        ss << L" | Session: 0x" << std::hex << amsiSession->SessionId;
    }
    
    LogMessage(ss.str());
    
    // Return the original result to maintain functionality
    if (result) *result = originalResult;
    return hr;
}

extern "C" __declspec(dllexport) HRESULT WINAPI AmsiScanString(
    HAMSICONTEXT* amsiContext,
    LPCWSTR string,
    LPCWSTR contentName,
    HAMSISESSION* amsiSession,
    AMSI_RESULT* result
) {
    AMSI_RESULT originalResult = AMSI_RESULT_CLEAN;
    HRESULT hr = pAmsiScanString ? 
        pAmsiScanString(amsiContext, string, contentName, amsiSession, &originalResult) : E_FAIL;
    
    std::wstringstream ss;
    ss << L"AmsiScanString - Content: " << SafeString(contentName)
       << L" | String: " << SafeString(string)
       << L" | Original Result: " << GetAmsiResultString(originalResult);
    
    if (amsiSession) {
        ss << L" | Session: 0x" << std::hex << amsiSession->SessionId;
    }
    
    LogMessage(ss.str());
    
    if (result) *result = originalResult;
    return hr;
}

extern "C" __declspec(dllexport) VOID WINAPI AmsiUninitialize(
    HAMSICONTEXT* amsiContext
) {
    std::wstringstream ss;
    ss << L"AmsiUninitialize - Context: 0x" << std::hex << (ULONG_PTR)amsiContext;
    LogMessage(ss.str());
    
    if (pAmsiUninitialize) {
        pAmsiUninitialize(amsiContext);
    }
}

// Initialize the DLL
void DllInit() {
    if (g_bInitialized) return;
    
    // Open log file
#ifdef LOG_TO_FILE
    CreateDirectory(L"C:\\temp", NULL);
    g_logFile.open(LOG_FILE, std::ios::out | std::ios::app);
    if (g_logFile.is_open()) {
        g_logFile << L"=== AMSI Monitor Started ===" << std::endl;
    }
#endif
    
    HMODULE hAmsiDll = LoadLibraryA("C:\\Windows\\System32\\amsi.dll");
    if (!hAmsiDll) {
        LogMessage(L"ERROR: Failed to load amsi.dll");
        return;
    }
    
    pAmsiInitialize = (AmsiInitializeT)GetProcAddress(hAmsiDll, "AmsiInitialize");
    pAmsiOpenSession = (AmsiOpenSessionT)GetProcAddress(hAmsiDll, "AmsiOpenSession");
    pAmsiCloseSession = (AmsiCloseSessionT)GetProcAddress(hAmsiDll, "AmsiCloseSession");
    pAmsiScanBuffer = (AmsiScanBufferT)GetProcAddress(hAmsiDll, "AmsiScanBuffer");
    pAmsiScanString = (AmsiScanStringT)GetProcAddress(hAmsiDll, "AmsiScanString");
    pAmsiUninitialize = (AmsiUninitializeT)GetProcAddress(hAmsiDll, "AmsiUninitialize");
    
    // Optional: Get additional AMSI functions if available
    pAmsiNotifyOperation = (AmsiNotifyOperationT)GetProcAddress(hAmsiDll, "AmsiNotifyOperation");
    
    if (pAmsiInitialize && pAmsiScanBuffer && pAmsiScanString) {
        LogMessage(L"AMSI hooks initialized successfully");
        g_bInitialized = true;
    } else {
        LogMessage(L"ERROR: Failed to get AMSI function addresses");
    }
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            // Disable thread notifications for performance
            DisableThreadLibraryCalls(hModule);
            
            // Initialize in a separate function to avoid doing too much in DllMain
            DllInit();
            break;
        }
        
        case DLL_PROCESS_DETACH: {
#ifdef LOG_TO_FILE
            if (g_logFile.is_open()) {
                g_logFile << L"=== AMSI Monitor Stopped ===" << std::endl;
                g_logFile.close();
            }
#endif
            break;
        }
        
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            // Ignored
            break;
    }
    
    return TRUE;
}
