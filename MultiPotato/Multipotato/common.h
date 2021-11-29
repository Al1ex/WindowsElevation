#pragma once
#define TECHNIQUE_NAME L"CreateProcessWithTokenW"
#define PIPE_NAME L"pwned/pipe/srvsvc"
#define THREAD_TIMEOUT 60000
BOOL EnablePriv(HANDLE, LPCTSTR);
PSID BuildEveryoneSid();
BOOL AddTheAceDesktop(HDESK, PSID);
BOOL AddTheAceWindowStation(HWINSTA, PSID);
void Usage();
void MultiPotato(wchar_t* commandline, wchar_t* technique_placeholder, wchar_t* arguments);
int CreatePipeServer(wchar_t*, bool endless);
