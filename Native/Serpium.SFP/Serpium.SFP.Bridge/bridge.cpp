#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mstcpip.h>

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cwchar>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "..\Serpium.SFP.Protocol\serpium_sfp_protocol.h"

static std::atomic<bool> g_Stop(false);
static unsigned short g_SocksPort = 0;

static BOOL WINAPI
ConsoleHandler(
    DWORD type
    )
{
    if (type == CTRL_C_EVENT ||
        type == CTRL_BREAK_EVENT ||
        type == CTRL_CLOSE_EVENT ||
        type == CTRL_SHUTDOWN_EVENT)
    {
        g_Stop.store(true);
        return TRUE;
    }

    return FALSE;
}

static HANDLE
OpenKernel()
{
    return CreateFileW(
        SERPIUM_SFP_WIN32_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
}

static bool
SendAll(
    SOCKET socket,
    const unsigned char* data,
    int length
    )
{
    int offset = 0;

    while (offset < length)
    {
        int sent =
            send(
                socket,
                reinterpret_cast<const char*>(data + offset),
                length - offset,
                0);

        if (sent <= 0)
            return false;

        offset += sent;
    }

    return true;
}

static bool
ReceiveAll(
    SOCKET socket,
    unsigned char* data,
    int length
    )
{
    int offset = 0;

    while (offset < length)
    {
        int received =
            recv(
                socket,
                reinterpret_cast<char*>(data + offset),
                length - offset,
                0);

        if (received <= 0)
            return false;

        offset += received;
    }

    return true;
}

static bool
QueryRedirectContext(
    SOCKET client,
    SERPIUM_SFP_REDIRECT_CONTEXT* context
    )
{
    ZeroMemory(context, sizeof(*context));

    DWORD bytesReturned = 0;

    int result =
        WSAIoctl(
            client,
            SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
            nullptr,
            0,
            context,
            sizeof(*context),
            &bytesReturned,
            nullptr,
            nullptr);

    return
        result == 0 &&
        bytesReturned >= sizeof(*context) &&
        context->Size == sizeof(*context) &&
        context->ProtocolVersion ==
            SERPIUM_SFP_PROTOCOL_VERSION &&
        context->Magic ==
            SERPIUM_SFP_REDIRECT_CONTEXT_MAGIC &&
        context->Route == SERPIUM_SFP_ROUTE_VPN &&
        context->Protocol == IPPROTO_TCP &&
        context->RemotePort != 0 &&
        (context->AddressFamily == AF_INET ||
         context->AddressFamily == AF_INET6);
}

static bool
QueryRedirectRecords(
    SOCKET client,
    std::vector<unsigned char>* records
    )
{
    for (DWORD capacity = 256;
         capacity <= 65536;
         capacity *= 2)
    {
        records->assign(capacity, 0);

        DWORD bytesReturned = 0;

        int result =
            WSAIoctl(
                client,
                SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
                nullptr,
                0,
                records->data(),
                capacity,
                &bytesReturned,
                nullptr,
                nullptr);

        if (result == 0 && bytesReturned > 0)
        {
            records->resize(bytesReturned);
            return true;
        }

        int error = WSAGetLastError();

        if (error != WSAEFAULT &&
            error != WSAENOBUFS)
        {
            break;
        }
    }

    records->clear();
    return false;
}

static SOCKET
ConnectToSocks(
    const std::vector<unsigned char>& redirectRecords
    )
{
    SOCKET upstream =
        WSASocketW(
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP,
            nullptr,
            0,
            WSA_FLAG_OVERLAPPED);

    if (upstream == INVALID_SOCKET)
        return INVALID_SOCKET;

    if (!redirectRecords.empty())
    {
        DWORD bytesReturned = 0;

        int result =
            WSAIoctl(
                upstream,
                SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS,
                const_cast<unsigned char*>(redirectRecords.data()),
                static_cast<DWORD>(redirectRecords.size()),
                nullptr,
                0,
                &bytesReturned,
                nullptr,
                nullptr);

        if (result != 0)
        {
            closesocket(upstream);
            return INVALID_SOCKET;
        }
    }

    sockaddr_in endpoint = {};
    endpoint.sin_family = AF_INET;
    endpoint.sin_port = htons(g_SocksPort);
    endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(
            upstream,
            reinterpret_cast<const sockaddr*>(&endpoint),
            sizeof(endpoint)) != 0)
    {
        closesocket(upstream);
        return INVALID_SOCKET;
    }

    return upstream;
}

static bool
SocksGreeting(
    SOCKET upstream
    )
{
    const unsigned char request[] =
        { 0x05, 0x01, 0x00 };

    unsigned char response[2] = {};

    return
        SendAll(
            upstream,
            request,
            sizeof(request)) &&
        ReceiveAll(
            upstream,
            response,
            sizeof(response)) &&
        response[0] == 0x05 &&
        response[1] == 0x00;
}

static bool
SocksConnect(
    SOCKET upstream,
    const SERPIUM_SFP_REDIRECT_CONTEXT& context
    )
{
    unsigned char request[22] = {};
    int length = 0;

    request[0] = 0x05;
    request[1] = 0x01;
    request[2] = 0x00;

    if (context.AddressFamily == AF_INET)
    {
        request[3] = 0x01;
        memcpy(
            request + 4,
            context.RemoteAddress,
            4);
        length = 10;
    }
    else
    {
        request[3] = 0x04;
        memcpy(
            request + 4,
            context.RemoteAddress,
            16);
        length = 22;
    }

    request[length - 2] =
        static_cast<unsigned char>(
            context.RemotePort >> 8);

    request[length - 1] =
        static_cast<unsigned char>(
            context.RemotePort & 0xff);

    if (!SendAll(upstream, request, length))
        return false;

    unsigned char response[4] = {};

    if (!ReceiveAll(
            upstream,
            response,
            sizeof(response)) ||
        response[0] != 0x05 ||
        response[1] != 0x00 ||
        response[2] != 0x00)
    {
        return false;
    }

    if (response[3] == 0x01)
    {
        unsigned char tail[6] = {};
        return ReceiveAll(
            upstream,
            tail,
            sizeof(tail));
    }

    if (response[3] == 0x04)
    {
        unsigned char tail[18] = {};
        return ReceiveAll(
            upstream,
            tail,
            sizeof(tail));
    }

    if (response[3] == 0x03)
    {
        unsigned char nameLength = 0;

        if (!ReceiveAll(
                upstream,
                &nameLength,
                1))
        {
            return false;
        }

        std::vector<unsigned char> tail(
            static_cast<size_t>(nameLength) + 2);

        return ReceiveAll(
            upstream,
            tail.data(),
            static_cast<int>(tail.size()));
    }

    return false;
}

static void
Relay(
    SOCKET client,
    SOCKET upstream
    )
{
    std::vector<unsigned char> buffer(32768);

    while (!g_Stop.load())
    {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(client, &readSet);
        FD_SET(upstream, &readSet);

        timeval timeout = {};
        timeout.tv_sec = 1;

        int selected =
            select(
                0,
                &readSet,
                nullptr,
                nullptr,
                &timeout);

        if (selected == SOCKET_ERROR)
            break;

        if (selected == 0)
            continue;

        if (FD_ISSET(client, &readSet))
        {
            int received =
                recv(
                    client,
                    reinterpret_cast<char*>(buffer.data()),
                    static_cast<int>(buffer.size()),
                    0);

            if (received <= 0 ||
                !SendAll(
                    upstream,
                    buffer.data(),
                    received))
            {
                break;
            }
        }

        if (FD_ISSET(upstream, &readSet))
        {
            int received =
                recv(
                    upstream,
                    reinterpret_cast<char*>(buffer.data()),
                    static_cast<int>(buffer.size()),
                    0);

            if (received <= 0 ||
                !SendAll(
                    client,
                    buffer.data(),
                    received))
            {
                break;
            }
        }
    }
}

static void
HandleClient(
    SOCKET client
    )
{
    SERPIUM_SFP_REDIRECT_CONTEXT context = {};
    std::vector<unsigned char> records;
    SOCKET upstream = INVALID_SOCKET;

    if (QueryRedirectContext(client, &context) &&
        QueryRedirectRecords(client, &records))
    {
        upstream = ConnectToSocks(records);

        if (upstream != INVALID_SOCKET &&
            SocksGreeting(upstream) &&
            SocksConnect(upstream, context))
        {
            Relay(client, upstream);
        }
    }

    if (upstream != INVALID_SOCKET)
    {
        shutdown(upstream, SD_BOTH);
        closesocket(upstream);
    }

    shutdown(client, SD_BOTH);
    closesocket(client);
}

static SOCKET
CreateListener(
    int family,
    unsigned short* port
    )
{
    SOCKET listener =
        WSASocketW(
            family,
            SOCK_STREAM,
            IPPROTO_TCP,
            nullptr,
            0,
            WSA_FLAG_OVERLAPPED);

    if (listener == INVALID_SOCKET)
        return INVALID_SOCKET;

    if (family == AF_INET)
    {
        sockaddr_in endpoint = {};
        endpoint.sin_family = AF_INET;
        endpoint.sin_port = 0;
        endpoint.sin_addr.s_addr =
            htonl(INADDR_LOOPBACK);

        if (bind(
                listener,
                reinterpret_cast<const sockaddr*>(&endpoint),
                sizeof(endpoint)) != 0)
        {
            closesocket(listener);
            return INVALID_SOCKET;
        }

        int size = sizeof(endpoint);

        if (getsockname(
                listener,
                reinterpret_cast<sockaddr*>(&endpoint),
                &size) != 0)
        {
            closesocket(listener);
            return INVALID_SOCKET;
        }

        *port = ntohs(endpoint.sin_port);
    }
    else
    {
        DWORD v6Only = 1;

        setsockopt(
            listener,
            IPPROTO_IPV6,
            IPV6_V6ONLY,
            reinterpret_cast<const char*>(&v6Only),
            sizeof(v6Only));

        sockaddr_in6 endpoint = {};
        endpoint.sin6_family = AF_INET6;
        endpoint.sin6_port = 0;
        endpoint.sin6_addr = in6addr_loopback;

        if (bind(
                listener,
                reinterpret_cast<const sockaddr*>(&endpoint),
                sizeof(endpoint)) != 0)
        {
            closesocket(listener);
            return INVALID_SOCKET;
        }

        int size = sizeof(endpoint);

        if (getsockname(
                listener,
                reinterpret_cast<sockaddr*>(&endpoint),
                &size) != 0)
        {
            closesocket(listener);
            return INVALID_SOCKET;
        }

        *port = ntohs(endpoint.sin6_port);
    }

    if (listen(listener, SOMAXCONN) != 0)
    {
        closesocket(listener);
        return INVALID_SOCKET;
    }

    return listener;
}

static bool
ConfigureKernel(
    unsigned short port4,
    unsigned short port6,
    const std::vector<unsigned long long>& bypass
    )
{
    HANDLE device = OpenKernel();

    if (device == INVALID_HANDLE_VALUE)
        return false;

    SERPIUM_SFP_BRIDGE_CONFIG_REQUEST request = {};
    request.Size = sizeof(request);
    request.ProtocolVersion =
        SERPIUM_SFP_PROTOCOL_VERSION;
    request.BridgeProcessId =
        GetCurrentProcessId();
    request.ListenPortV4 = port4;
    request.ListenPortV6 = port6;

    request.BypassProcessCount =
        static_cast<unsigned long>(
            std::min<size_t>(
                bypass.size(),
                SERPIUM_SFP_MAX_BYPASS_PROCESSES));

    for (unsigned long index = 0;
         index < request.BypassProcessCount;
         index++)
    {
        request.BypassProcessIds[index] =
            bypass[index];
    }

    SERPIUM_SFP_BRIDGE_CONFIG_RESPONSE response = {};
    DWORD returned = 0;

    BOOL ok =
        DeviceIoControl(
            device,
            IOCTL_SERPIUM_SFP_CONFIGURE_BRIDGE,
            &request,
            sizeof(request),
            &response,
            sizeof(response),
            &returned,
            nullptr);

    CloseHandle(device);

    return
        ok != FALSE &&
        returned >= sizeof(response) &&
        response.ProtocolVersion ==
            SERPIUM_SFP_PROTOCOL_VERSION &&
        response.Armed != 0;
}

static void
DisarmKernel()
{
    HANDLE device = OpenKernel();

    if (device == INVALID_HANDLE_VALUE)
        return;

    SERPIUM_SFP_BRIDGE_CONFIG_RESPONSE response = {};
    DWORD returned = 0;

    DeviceIoControl(
        device,
        IOCTL_SERPIUM_SFP_DISARM_BRIDGE,
        nullptr,
        0,
        &response,
        sizeof(response),
        &returned,
        nullptr);

    CloseHandle(device);
}

static void
AcceptLoop(
    SOCKET listener
    )
{
    while (!g_Stop.load())
    {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(listener, &readSet);

        timeval timeout = {};
        timeout.tv_sec = 1;

        int selected =
            select(
                0,
                &readSet,
                nullptr,
                nullptr,
                &timeout);

        if (selected == SOCKET_ERROR)
            break;

        if (selected == 0)
            continue;

        SOCKET client =
            accept(
                listener,
                nullptr,
                nullptr);

        if (client == INVALID_SOCKET)
            continue;

        std::thread(
            [client]()
            {
                HandleClient(client);
            }).detach();
    }
}

int wmain(
    int argc,
    wchar_t** argv
    )
{
    if (argc < 2)
    {
        std::wcerr
            << L"Usage:\n"
            << L"  Serpium.SFP.Bridge.exe <socks-port> [relay-pid ...]\n";

        return 1;
    }

    unsigned long socks =
        wcstoul(
            argv[1],
            nullptr,
            10);

    if (socks == 0 || socks > 65535)
    {
        std::wcerr << L"Invalid SOCKS5 port.\n";
        return 2;
    }

    g_SocksPort =
        static_cast<unsigned short>(socks);

    std::vector<unsigned long long> bypass;

    for (int index = 2;
         index < argc &&
         bypass.size() < SERPIUM_SFP_MAX_BYPASS_PROCESSES;
         index++)
    {
        unsigned long long pid =
            _wcstoui64(
                argv[index],
                nullptr,
                10);

        if (pid == 0)
        {
            std::wcerr << L"Invalid relay PID.\n";
            return 3;
        }

        bypass.push_back(pid);
    }

    WSADATA wsa = {};

    if (WSAStartup(
            MAKEWORD(2, 2),
            &wsa) != 0)
    {
        return 4;
    }

    SetConsoleCtrlHandler(
        ConsoleHandler,
        TRUE);

    unsigned short port4 = 0;
    unsigned short port6 = 0;

    SOCKET listener4 =
        CreateListener(
            AF_INET,
            &port4);

    SOCKET listener6 =
        CreateListener(
            AF_INET6,
            &port6);

    if (listener4 == INVALID_SOCKET ||
        listener6 == INVALID_SOCKET)
    {
        if (listener4 != INVALID_SOCKET)
            closesocket(listener4);

        if (listener6 != INVALID_SOCKET)
            closesocket(listener6);

        WSACleanup();
        return 5;
    }

    if (!ConfigureKernel(
            port4,
            port6,
            bypass))
    {
        closesocket(listener4);
        closesocket(listener6);
        WSACleanup();

        std::wcerr
            << L"Failed to arm SFP Bridge. "
            << L"Is the SFP kernel running?\n";

        return 6;
    }

    std::wcout
        << L"SFP Bridge armed.\n"
        << L"SOCKS5: 127.0.0.1:"
        << g_SocksPort
        << L"\nTCP redirect listeners: "
        << L"127.0.0.1:"
        << port4
        << L" / [::1]:"
        << port6
        << L"\nBridge PID: "
        << GetCurrentProcessId()
        << L"\nRelay bypass PIDs: "
        << bypass.size()
        << L"\nCtrl+C to stop.\n";

    std::thread thread4(
        [listener4]()
        {
            AcceptLoop(listener4);
        });

    std::thread thread6(
        [listener6]()
        {
            AcceptLoop(listener6);
        });

    while (!g_Stop.load())
    {
        Sleep(200);
    }

    DisarmKernel();

    closesocket(listener4);
    closesocket(listener6);

    if (thread4.joinable())
        thread4.join();

    if (thread6.joinable())
        thread6.join();

    WSACleanup();

    std::wcout << L"SFP Bridge disarmed.\n";
    return 0;
}
