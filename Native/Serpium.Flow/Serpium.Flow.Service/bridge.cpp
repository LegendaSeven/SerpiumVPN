#define FD_SETSIZE 128
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mstcpip.h>
#include <mswsock.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <string>
#include <vector>

#include "..\Serpium.Flow.Protocol\serpium_flow_protocol.h"
#include "bridge.h"

static HANDLE g_BridgeStopEvent = nullptr;
static HANDLE g_NoConnectionsEvent = nullptr;
static volatile LONG g_ActiveConnections = 0;
static unsigned short g_SocksPort = 0;
static bool g_DomainAware = false;

struct DOMAIN_RULE
{
    bool IncludeSubdomains;
    std::string Domain;
};

static SRWLOCK g_DomainPolicyLock = SRWLOCK_INIT;
static std::vector<DOMAIN_RULE> g_DomainRules;

static const unsigned long kLeaseMilliseconds = 5000;
static const unsigned long kLeaseRenewMilliseconds = 2000;
static const LONG kMaximumConnections = 128;

struct CONNECTION_CONTEXT
{
    SOCKET Client;
};

struct LISTENER_CONTEXT
{
    SOCKET Listener;
};

static HANDLE
OpenDriver()
{
    return CreateFileW(
        SERPIUM_FLOW_WIN32_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
        );
}

static bool
SendRouteConfiguration(
    const std::vector<unsigned long long>& backendProcessIds,
    unsigned short listenPortV4,
    unsigned short listenPortV6,
    bool inspectAllTcp,
    bool udpAppRouting,
    bool quicTcpFallback,
    bool domainQuicFallback,
    SERPIUM_FLOW_ROUTE_CONFIG_RESULT* result,
    DWORD* errorCode
    )
{
    HANDLE device = OpenDriver();

    if (device == INVALID_HANDLE_VALUE)
    {
        if (errorCode != nullptr)
        {
            *errorCode = GetLastError();
        }

        return false;
    }

    SERPIUM_FLOW_ROUTE_CONFIG_REQUEST request = {};
    request.Size = sizeof(request);
    request.ProtocolVersion = SERPIUM_FLOW_PROTOCOL_VERSION;
    request.Flags = SERPIUM_FLOW_ROUTE_CONFIG_FLAG_ARM;
    if (inspectAllTcp)
    {
        request.Flags |= SERPIUM_FLOW_ROUTE_CONFIG_FLAG_INSPECT_ALL_TCP;
    }
    if (udpAppRouting)
    {
        request.Flags |= SERPIUM_FLOW_ROUTE_CONFIG_FLAG_UDP_APP_ROUTING;
    }
    if (quicTcpFallback)
    {
        request.Flags |= SERPIUM_FLOW_ROUTE_CONFIG_FLAG_QUIC_TCP_FALLBACK;
    }
    if (domainQuicFallback)
    {
        request.Flags |= SERPIUM_FLOW_ROUTE_CONFIG_FLAG_DOMAIN_QUIC_FALLBACK;
    }
    request.LeaseMilliseconds = kLeaseMilliseconds;
    request.BridgeProcessId = GetCurrentProcessId();
    request.ListenPortV4 = listenPortV4;
    request.ListenPortV6 = listenPortV6;
    request.BypassProcessCount =
        static_cast<unsigned long>(backendProcessIds.size());

    for (size_t index = 0; index < backendProcessIds.size(); index++)
    {
        request.BypassProcessIds[index] = backendProcessIds[index];
    }

    SERPIUM_FLOW_ROUTE_CONFIG_RESULT localResult = {};
    DWORD bytesReturned = 0;
    BOOL ioctlResult = DeviceIoControl(
        device,
        IOCTL_SERPIUM_FLOW_CONFIGURE_ROUTE,
        &request,
        sizeof(request),
        &localResult,
        sizeof(localResult),
        &bytesReturned,
        nullptr
        );

    DWORD localError = ioctlResult ? ERROR_SUCCESS : GetLastError();

    // Backward compatibility with an already-installed U1 runtime.
    // If the older driver rejects the new QUIC flags, retry without them.
    if (!ioctlResult &&
        (quicTcpFallback || domainQuicFallback) &&
        (localError == ERROR_INVALID_PARAMETER ||
         localError == ERROR_NOT_SUPPORTED))
    {
        request.Flags &=
            ~(SERPIUM_FLOW_ROUTE_CONFIG_FLAG_QUIC_TCP_FALLBACK |
              SERPIUM_FLOW_ROUTE_CONFIG_FLAG_DOMAIN_QUIC_FALLBACK);
        ZeroMemory(&localResult, sizeof(localResult));
        bytesReturned = 0;
        ioctlResult = DeviceIoControl(
            device,
            IOCTL_SERPIUM_FLOW_CONFIGURE_ROUTE,
            &request,
            sizeof(request),
            &localResult,
            sizeof(localResult),
            &bytesReturned,
            nullptr
            );
        localError = ioctlResult ? ERROR_SUCCESS : GetLastError();
        quicTcpFallback = false;
        domainQuicFallback = false;
    }

    CloseHandle(device);

    bool valid =
        ioctlResult != FALSE &&
        bytesReturned >= sizeof(localResult) &&
        localResult.Size == sizeof(localResult) &&
        localResult.ProtocolVersion == SERPIUM_FLOW_PROTOCOL_VERSION &&
        (localResult.Flags &
         (SERPIUM_FLOW_ROUTE_CONFIG_FLAG_ARM |
          SERPIUM_FLOW_ROUTE_CONFIG_FLAG_LEASE_ACTIVE)) ==
            (SERPIUM_FLOW_ROUTE_CONFIG_FLAG_ARM |
             SERPIUM_FLOW_ROUTE_CONFIG_FLAG_LEASE_ACTIVE) &&
        (!inspectAllTcp ||
         (localResult.Flags & SERPIUM_FLOW_ROUTE_CONFIG_FLAG_INSPECT_ALL_TCP) != 0) &&
        (!udpAppRouting ||
         (localResult.Flags & SERPIUM_FLOW_ROUTE_CONFIG_FLAG_UDP_APP_ROUTING) != 0) &&
        (!quicTcpFallback ||
         (localResult.Flags & SERPIUM_FLOW_ROUTE_CONFIG_FLAG_QUIC_TCP_FALLBACK) != 0) &&
        (!domainQuicFallback ||
         (localResult.Flags & SERPIUM_FLOW_ROUTE_CONFIG_FLAG_DOMAIN_QUIC_FALLBACK) != 0);

    if (valid && result != nullptr)
    {
        *result = localResult;
    }

    if (errorCode != nullptr)
    {
        *errorCode =
            valid
                ? ERROR_SUCCESS
                : (localError == ERROR_SUCCESS
                    ? ERROR_INVALID_DATA
                    : localError);
    }

    return valid;
}

static bool
DisarmRoute(
    SERPIUM_FLOW_ROUTE_CONFIG_RESULT* result,
    DWORD* errorCode
    )
{
    HANDLE device = OpenDriver();

    if (device == INVALID_HANDLE_VALUE)
    {
        if (errorCode != nullptr)
        {
            *errorCode = GetLastError();
        }

        return false;
    }

    SERPIUM_FLOW_ROUTE_CONFIG_RESULT localResult = {};
    DWORD bytesReturned = 0;
    BOOL ioctlResult = DeviceIoControl(
        device,
        IOCTL_SERPIUM_FLOW_DISARM_ROUTE,
        nullptr,
        0,
        &localResult,
        sizeof(localResult),
        &bytesReturned,
        nullptr
        );

    DWORD localError = ioctlResult ? ERROR_SUCCESS : GetLastError();
    CloseHandle(device);

    bool valid =
        ioctlResult != FALSE &&
        bytesReturned >= sizeof(localResult) &&
        localResult.Size == sizeof(localResult) &&
        localResult.ProtocolVersion == SERPIUM_FLOW_PROTOCOL_VERSION &&
        (localResult.Flags & SERPIUM_FLOW_ROUTE_CONFIG_FLAG_ARM) == 0;

    if (valid && result != nullptr)
    {
        *result = localResult;
    }

    if (errorCode != nullptr)
    {
        *errorCode =
            valid
                ? ERROR_SUCCESS
                : (localError == ERROR_SUCCESS
                    ? ERROR_INVALID_DATA
                    : localError);
    }

    return valid;
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
        int sent = send(
            socket,
            reinterpret_cast<const char*>(data + offset),
            length - offset,
            0
            );

        if (sent <= 0)
        {
            return false;
        }

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
        int received = recv(
            socket,
            reinterpret_cast<char*>(data + offset),
            length - offset,
            0
            );

        if (received <= 0)
        {
            return false;
        }

        offset += received;
    }

    return true;
}

static std::string
NormalizeHost(
    std::string host
    )
{
    while (!host.empty() &&
           (host.back() == '.' || host.back() == '\r' || host.back() == '\n' ||
            host.back() == ' ' || host.back() == '\t'))
    {
        host.pop_back();
    }

    size_t start = 0;
    while (start < host.size() &&
           (host[start] == ' ' || host[start] == '\t'))
    {
        start++;
    }
    if (start > 0)
    {
        host.erase(0, start);
    }

    if (!host.empty() && host.front() == '[')
    {
        return std::string();
    }

    size_t colon = host.rfind(':');
    if (colon != std::string::npos &&
        host.find(':') == colon)
    {
        host.erase(colon);
    }

    std::transform(
        host.begin(),
        host.end(),
        host.begin(),
        [](unsigned char value) { return static_cast<char>(std::tolower(value)); }
        );
    return host;
}

static bool
IsValidDomainRule(
    const std::string& domain
    )
{
    if (domain.empty() || domain.size() > 253)
    {
        return false;
    }

    for (unsigned char value : domain)
    {
        if (!(
            (value >= 'a' && value <= 'z') ||
            (value >= '0' && value <= '9') ||
            value == '-' ||
            value == '.'
            ))
        {
            return false;
        }
    }

    return domain.front() != '.' && domain.back() != '.';
}

static bool
DomainPolicyHasRules()
{
    AcquireSRWLockShared(&g_DomainPolicyLock);
    bool result = !g_DomainRules.empty();
    ReleaseSRWLockShared(&g_DomainPolicyLock);
    return result;
}

static bool
DomainMatchesPolicy(
    const std::string& rawHost
    )
{
    std::string host = NormalizeHost(rawHost);
    if (host.empty())
    {
        return false;
    }

    bool matched = false;
    AcquireSRWLockShared(&g_DomainPolicyLock);

    for (const DOMAIN_RULE& rule : g_DomainRules)
    {
        if (host == rule.Domain)
        {
            matched = true;
            break;
        }

        if (rule.IncludeSubdomains && host.size() > rule.Domain.size())
        {
            size_t offset = host.size() - rule.Domain.size();
            if (offset > 0 &&
                host[offset - 1] == '.' &&
                host.compare(offset, rule.Domain.size(), rule.Domain) == 0)
            {
                matched = true;
                break;
            }
        }
    }

    ReleaseSRWLockShared(&g_DomainPolicyLock);
    return matched;
}

static unsigned short
ReadNetworkU16(
    const unsigned char* data
    )
{
    return static_cast<unsigned short>(
        (static_cast<unsigned short>(data[0]) << 8) |
        static_cast<unsigned short>(data[1])
        );
}

static unsigned long
ReadNetworkU24(
    const unsigned char* data
    )
{
    return
        (static_cast<unsigned long>(data[0]) << 16) |
        (static_cast<unsigned long>(data[1]) << 8) |
        static_cast<unsigned long>(data[2]);
}

static bool
TryExtractTlsSni(
    const std::vector<unsigned char>& data,
    std::string* host
    )
{
    if (data.size() < 5 || data[0] != 0x16)
    {
        return false;
    }

    std::vector<unsigned char> handshake;
    size_t recordOffset = 0;

    while (recordOffset + 5 <= data.size())
    {
        if (data[recordOffset] != 0x16)
        {
            break;
        }

        size_t recordLength = ReadNetworkU16(&data[recordOffset + 3]);
        if (recordOffset + 5 + recordLength > data.size())
        {
            break;
        }

        handshake.insert(
            handshake.end(),
            data.begin() + static_cast<std::ptrdiff_t>(recordOffset + 5),
            data.begin() + static_cast<std::ptrdiff_t>(recordOffset + 5 + recordLength)
            );
        recordOffset += 5 + recordLength;

        if (handshake.size() >= 4)
        {
            size_t needed = 4 + ReadNetworkU24(&handshake[1]);
            if (handshake.size() >= needed)
            {
                break;
            }
        }
    }

    if (handshake.size() < 4 || handshake[0] != 0x01)
    {
        return false;
    }

    size_t helloLength = ReadNetworkU24(&handshake[1]);
    if (handshake.size() < 4 + helloLength)
    {
        return false;
    }

    size_t offset = 4;
    if (offset + 2 + 32 + 1 > handshake.size())
    {
        return false;
    }

    offset += 2 + 32;
    size_t sessionIdLength = handshake[offset++];
    if (offset + sessionIdLength + 2 > handshake.size())
    {
        return false;
    }
    offset += sessionIdLength;

    size_t cipherLength = ReadNetworkU16(&handshake[offset]);
    offset += 2;
    if (offset + cipherLength + 1 > handshake.size())
    {
        return false;
    }
    offset += cipherLength;

    size_t compressionLength = handshake[offset++];
    if (offset + compressionLength + 2 > handshake.size())
    {
        return false;
    }
    offset += compressionLength;

    size_t extensionsLength = ReadNetworkU16(&handshake[offset]);
    offset += 2;
    size_t extensionsEnd = offset + extensionsLength;
    if (extensionsEnd > handshake.size())
    {
        return false;
    }

    while (offset + 4 <= extensionsEnd)
    {
        unsigned short extensionType = ReadNetworkU16(&handshake[offset]);
        size_t extensionLength = ReadNetworkU16(&handshake[offset + 2]);
        offset += 4;

        if (offset + extensionLength > extensionsEnd)
        {
            return false;
        }

        if (extensionType == 0x0000 && extensionLength >= 5)
        {
            size_t nameOffset = offset;
            size_t listLength = ReadNetworkU16(&handshake[nameOffset]);
            nameOffset += 2;
            size_t listEnd = (std::min)(offset + extensionLength, nameOffset + listLength);

            while (nameOffset + 3 <= listEnd)
            {
                unsigned char nameType = handshake[nameOffset++];
                size_t nameLength = ReadNetworkU16(&handshake[nameOffset]);
                nameOffset += 2;

                if (nameOffset + nameLength > listEnd)
                {
                    return false;
                }

                if (nameType == 0 && nameLength > 0)
                {
                    std::string candidate(
                        reinterpret_cast<const char*>(&handshake[nameOffset]),
                        nameLength
                        );
                    candidate = NormalizeHost(candidate);
                    if (IsValidDomainRule(candidate))
                    {
                        *host = candidate;
                        return true;
                    }
                }

                nameOffset += nameLength;
            }
        }

        offset += extensionLength;
    }

    return false;
}

static bool
TryExtractHttpHost(
    const std::vector<unsigned char>& data,
    std::string* host
    )
{
    if (data.empty())
    {
        return false;
    }

    std::string text(
        reinterpret_cast<const char*>(data.data()),
        data.size()
        );
    size_t headersEnd = text.find("\r\n\r\n");
    if (headersEnd == std::string::npos)
    {
        return false;
    }

    size_t lineStart = 0;
    while (lineStart < headersEnd)
    {
        size_t lineEnd = text.find("\r\n", lineStart);
        if (lineEnd == std::string::npos || lineEnd > headersEnd)
        {
            lineEnd = headersEnd;
        }

        std::string line = text.substr(lineStart, lineEnd - lineStart);
        if (line.size() >= 5)
        {
            std::string key = line.substr(0, 5);
            std::transform(
                key.begin(), key.end(), key.begin(),
                [](unsigned char value) { return static_cast<char>(std::tolower(value)); }
                );
            if (key == "host:")
            {
                std::string candidate = NormalizeHost(line.substr(5));
                if (IsValidDomainRule(candidate))
                {
                    *host = candidate;
                    return true;
                }
            }
        }

        if (lineEnd >= headersEnd)
        {
            break;
        }
        lineStart = lineEnd + 2;
    }

    return false;
}

static bool
ReadInitialClientDataForHost(
    SOCKET client,
    unsigned short remotePort,
    std::vector<unsigned char>* initialData,
    std::string* host
    )
{
    if (remotePort != 80 && remotePort != 443)
    {
        return false;
    }

    const ULONGLONG deadline = GetTickCount64() + 400;
    unsigned char buffer[4096] = {};

    while (initialData->size() < 32768 && GetTickCount64() < deadline)
    {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(client, &readSet);

        timeval timeout = {};
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;

        int selected = select(0, &readSet, nullptr, nullptr, &timeout);
        if (selected == SOCKET_ERROR)
        {
            break;
        }
        if (selected == 0)
        {
            continue;
        }

        int received = recv(
            client,
            reinterpret_cast<char*>(buffer),
            sizeof(buffer),
            0
            );
        if (received <= 0)
        {
            break;
        }

        initialData->insert(
            initialData->end(),
            buffer,
            buffer + received
            );

        if (remotePort == 443)
        {
            if (TryExtractTlsSni(*initialData, host))
            {
                return true;
            }
        }
        else if (TryExtractHttpHost(*initialData, host))
        {
            return true;
        }
    }

    return false;
}

static DWORD WINAPI
DomainPolicyInputThread(
    LPVOID
    )
{
    std::vector<DOMAIN_RULE> pending;
    bool receiving = false;
    unsigned long long sequence = 0;
    std::string line;

    while (std::getline(std::cin, line))
    {
        if (!line.empty() && line.back() == '\r')
        {
            line.pop_back();
        }

        if (line.rfind("POLICY ", 0) == 0)
        {
            char* end = nullptr;
            unsigned long long parsed = _strtoui64(line.c_str() + 7, &end, 10);
            if (end != line.c_str() + 7 && *end == '\0')
            {
                sequence = parsed;
                pending.clear();
                receiving = true;
            }
            continue;
        }

        if (receiving && line == "APPLY")
        {
            AcquireSRWLockExclusive(&g_DomainPolicyLock);
            g_DomainRules.swap(pending);
            size_t appliedCount = g_DomainRules.size();
            ReleaseSRWLockExclusive(&g_DomainPolicyLock);

            std::wprintf(
                L"SERPIUM_WFP4A_DOMAIN_POLICY_APPLIED %llu %zu\n",
                sequence,
                appliedCount
                );
            std::fflush(stdout);
            pending.clear();
            receiving = false;
            continue;
        }

        if (receiving && line.size() > 2 &&
            (line[0] == 'E' || line[0] == 'S') && line[1] == ' ')
        {
            std::string domain = NormalizeHost(line.substr(2));
            if (!IsValidDomainRule(domain))
            {
                continue;
            }

            bool duplicate = false;
            for (const DOMAIN_RULE& rule : pending)
            {
                if (rule.IncludeSubdomains == (line[0] == 'S') &&
                    rule.Domain == domain)
                {
                    duplicate = true;
                    break;
                }
            }

            if (!duplicate && pending.size() < 512)
            {
                pending.push_back({ line[0] == 'S', domain });
            }
        }
    }

    return 0;
}

static bool
PerformSocksGreeting(
    SOCKET socket
    )
{
    const unsigned char greeting[] = { 0x05, 0x01, 0x00 };
    unsigned char response[2] = {};

    return
        SendAll(socket, greeting, sizeof(greeting)) &&
        ReceiveAll(socket, response, sizeof(response)) &&
        response[0] == 0x05 &&
        response[1] == 0x00;
}

static bool
PerformSocksConnect(
    SOCKET socket,
    const SERPIUM_FLOW_REDIRECT_CONTEXT& context
    )
{
    unsigned char request[4 + 16 + 2] = {};
    int requestLength;

    request[0] = 0x05;
    request[1] = 0x01;
    request[2] = 0x00;

    if (context.AddressFamily == AF_INET)
    {
        request[3] = 0x01;
        CopyMemory(request + 4, context.RemoteAddress, 4);
        requestLength = 10;
    }
    else if (context.AddressFamily == AF_INET6)
    {
        request[3] = 0x04;
        CopyMemory(request + 4, context.RemoteAddress, 16);
        requestLength = 22;
    }
    else
    {
        return false;
    }

    request[requestLength - 2] =
        static_cast<unsigned char>(context.RemotePort >> 8);
    request[requestLength - 1] =
        static_cast<unsigned char>(context.RemotePort);

    if (!SendAll(socket, request, requestLength))
    {
        return false;
    }

    unsigned char response[4] = {};

    if (
        !ReceiveAll(socket, response, sizeof(response)) ||
        response[0] != 0x05 ||
        response[1] != 0x00 ||
        response[2] != 0x00
        )
    {
        return false;
    }

    if (response[3] == 0x01)
    {
        unsigned char tail[6] = {};
        return ReceiveAll(socket, tail, sizeof(tail));
    }

    if (response[3] == 0x04)
    {
        unsigned char tail[18] = {};
        return ReceiveAll(socket, tail, sizeof(tail));
    }

    if (response[3] == 0x03)
    {
        unsigned char nameLength = 0;

        if (!ReceiveAll(socket, &nameLength, 1))
        {
            return false;
        }

        std::vector<unsigned char> tail(
            static_cast<size_t>(nameLength) + 2
            );
        return ReceiveAll(
            socket,
            tail.data(),
            static_cast<int>(tail.size())
            );
    }

    return false;
}

static bool
QueryRedirectContext(
    SOCKET socket,
    SERPIUM_FLOW_REDIRECT_CONTEXT* context
    )
{
    ZeroMemory(context, sizeof(*context));
    DWORD bytesReturned = 0;
    int result = WSAIoctl(
        socket,
        SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
        nullptr,
        0,
        context,
        sizeof(*context),
        &bytesReturned,
        nullptr,
        nullptr
        );

    return
        result == 0 &&
        bytesReturned >= sizeof(*context) &&
        context->Size == sizeof(*context) &&
        context->ProtocolVersion == SERPIUM_FLOW_PROTOCOL_VERSION &&
        context->Magic == SERPIUM_FLOW_REDIRECT_CONTEXT_MAGIC &&
        context->Protocol == IPPROTO_TCP &&
        context->RemotePort != 0;
}

static bool
QueryRedirectRecords(
    SOCKET socket,
    std::vector<unsigned char>* records
    )
{
    for (DWORD capacity = 256; capacity <= 65536; capacity *= 2)
    {
        records->assign(capacity, 0);
        DWORD bytesReturned = 0;
        int result = WSAIoctl(
            socket,
            SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
            nullptr,
            0,
            records->data(),
            capacity,
            &bytesReturned,
            nullptr,
            nullptr
            );

        if (result == 0 && bytesReturned > 0)
        {
            records->resize(bytesReturned);
            return true;
        }

        int errorCode = WSAGetLastError();

        if (errorCode != WSAEFAULT && errorCode != WSAENOBUFS)
        {
            break;
        }
    }

    records->clear();
    return false;
}

static SOCKET
ConnectToLocalSocks(
    const std::vector<unsigned char>* redirectRecords
    )
{
    SOCKET socket = WSASocketW(
        AF_INET,
        SOCK_STREAM,
        IPPROTO_TCP,
        nullptr,
        0,
        WSA_FLAG_OVERLAPPED
        );

    if (socket == INVALID_SOCKET)
    {
        return INVALID_SOCKET;
    }

    DWORD timeoutMilliseconds = 5000;
    setsockopt(
        socket,
        SOL_SOCKET,
        SO_RCVTIMEO,
        reinterpret_cast<const char*>(&timeoutMilliseconds),
        sizeof(timeoutMilliseconds)
        );
    setsockopt(
        socket,
        SOL_SOCKET,
        SO_SNDTIMEO,
        reinterpret_cast<const char*>(&timeoutMilliseconds),
        sizeof(timeoutMilliseconds)
        );

    if (redirectRecords != nullptr && !redirectRecords->empty())
    {
        DWORD bytesReturned = 0;
        int result = WSAIoctl(
            socket,
            SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS,
            const_cast<unsigned char*>(redirectRecords->data()),
            static_cast<DWORD>(redirectRecords->size()),
            nullptr,
            0,
            &bytesReturned,
            nullptr,
            nullptr
            );

        if (result != 0)
        {
            closesocket(socket);
            return INVALID_SOCKET;
        }
    }

    sockaddr_in endpoint = {};
    endpoint.sin_family = AF_INET;
    endpoint.sin_port = htons(g_SocksPort);
    endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (
        connect(
            socket,
            reinterpret_cast<const sockaddr*>(&endpoint),
            sizeof(endpoint)
            ) != 0
        )
    {
        closesocket(socket);
        return INVALID_SOCKET;
    }

    return socket;
}

static SOCKET
ConnectToOriginalDestination(
    const std::vector<unsigned char>* redirectRecords,
    const SERPIUM_FLOW_REDIRECT_CONTEXT& context
    )
{
    SOCKET socket = WSASocketW(
        context.AddressFamily,
        SOCK_STREAM,
        IPPROTO_TCP,
        nullptr,
        0,
        WSA_FLAG_OVERLAPPED
        );
    if (socket == INVALID_SOCKET)
    {
        return INVALID_SOCKET;
    }

    if (redirectRecords != nullptr && !redirectRecords->empty())
    {
        DWORD bytesReturned = 0;
        int result = WSAIoctl(
            socket,
            SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS,
            const_cast<unsigned char*>(redirectRecords->data()),
            static_cast<DWORD>(redirectRecords->size()),
            nullptr,
            0,
            &bytesReturned,
            nullptr,
            nullptr
            );
        if (result != 0)
        {
            closesocket(socket);
            return INVALID_SOCKET;
        }
    }

    int result = SOCKET_ERROR;
    if (context.AddressFamily == AF_INET)
    {
        sockaddr_in endpoint = {};
        endpoint.sin_family = AF_INET;
        endpoint.sin_port = htons(context.RemotePort);
        CopyMemory(&endpoint.sin_addr, context.RemoteAddress, 4);
        result = connect(
            socket,
            reinterpret_cast<const sockaddr*>(&endpoint),
            sizeof(endpoint)
            );
    }
    else if (context.AddressFamily == AF_INET6)
    {
        sockaddr_in6 endpoint = {};
        endpoint.sin6_family = AF_INET6;
        endpoint.sin6_port = htons(context.RemotePort);
        CopyMemory(&endpoint.sin6_addr, context.RemoteAddress, 16);
        result = connect(
            socket,
            reinterpret_cast<const sockaddr*>(&endpoint),
            sizeof(endpoint)
            );
    }

    if (result != 0)
    {
        closesocket(socket);
        return INVALID_SOCKET;
    }

    return socket;
}

static bool
RelayBidirectionally(
    SOCKET client,
    SOCKET upstream
    )
{
    unsigned char buffer[16384] = {};

    while (
        g_BridgeStopEvent != nullptr &&
        WaitForSingleObject(g_BridgeStopEvent, 0) == WAIT_TIMEOUT
        )
    {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(client, &readSet);
        FD_SET(upstream, &readSet);

        timeval timeout = {};
        timeout.tv_sec = 1;

        int selected = select(0, &readSet, nullptr, nullptr, &timeout);

        if (selected == SOCKET_ERROR)
        {
            return false;
        }

        if (selected == 0)
        {
            continue;
        }

        if (FD_ISSET(client, &readSet))
        {
            int received = recv(
                client,
                reinterpret_cast<char*>(buffer),
                sizeof(buffer),
                0
                );

            if (received <= 0 || !SendAll(upstream, buffer, received))
            {
                break;
            }
        }

        if (FD_ISSET(upstream, &readSet))
        {
            int received = recv(
                upstream,
                reinterpret_cast<char*>(buffer),
                sizeof(buffer),
                0
                );

            if (received <= 0 || !SendAll(client, buffer, received))
            {
                break;
            }
        }
    }

    return true;
}

static DWORD WINAPI
ConnectionThread(
    LPVOID parameter
    )
{
    CONNECTION_CONTEXT* connection =
        static_cast<CONNECTION_CONTEXT*>(parameter);
    SOCKET client = connection->Client;
    HeapFree(GetProcessHeap(), 0, connection);

    SERPIUM_FLOW_REDIRECT_CONTEXT redirectContext = {};
    std::vector<unsigned char> redirectRecords;
    SOCKET upstream = INVALID_SOCKET;

    try
    {
        if (
            QueryRedirectContext(client, &redirectContext) &&
            QueryRedirectRecords(client, &redirectRecords)
            )
        {
            std::vector<unsigned char> initialData;
            bool proxy = true;

            if (g_DomainAware)
            {
                bool domainPolicyActive = DomainPolicyHasRules();
                bool explicitApplicationVpn =
                    redirectContext.ResolvedRoute == SERPIUM_FLOW_ROUTE_VPN &&
                    redirectContext.RuleId != 0;

                if (domainPolicyActive && !explicitApplicationVpn)
                {
                    std::string host;
                    bool hostFound = ReadInitialClientDataForHost(
                        client,
                        redirectContext.RemotePort,
                        &initialData,
                        &host
                        );
                    proxy = hostFound && DomainMatchesPolicy(host);
                }
                else
                {
                    proxy =
                        redirectContext.ResolvedRoute == SERPIUM_FLOW_ROUTE_VPN;
                }
            }

            if (proxy)
            {
                upstream = ConnectToLocalSocks(&redirectRecords);
                if (
                    upstream != INVALID_SOCKET &&
                    PerformSocksGreeting(upstream) &&
                    PerformSocksConnect(upstream, redirectContext)
                    )
                {
                    if (
                        (initialData.empty() ||
                         SendAll(upstream, initialData.data(), static_cast<int>(initialData.size())))
                        )
                    {
                        RelayBidirectionally(client, upstream);
                    }
                }
            }
            else
            {
                upstream = ConnectToOriginalDestination(
                    &redirectRecords,
                    redirectContext
                    );
                if (upstream != INVALID_SOCKET)
                {
                    if (
                        initialData.empty() ||
                        SendAll(upstream, initialData.data(), static_cast<int>(initialData.size()))
                        )
                    {
                        RelayBidirectionally(client, upstream);
                    }
                }
            }
        }
    }
    catch (...)
    {
    }

    if (upstream != INVALID_SOCKET)
    {
        shutdown(upstream, SD_BOTH);
        closesocket(upstream);
    }

    shutdown(client, SD_BOTH);
    closesocket(client);

    if (InterlockedDecrement(&g_ActiveConnections) == 0)
    {
        SetEvent(g_NoConnectionsEvent);
    }

    return 0;
}

static DWORD WINAPI
ListenerThread(
    LPVOID parameter
    )
{
    LISTENER_CONTEXT* context =
        static_cast<LISTENER_CONTEXT*>(parameter);

    while (
        g_BridgeStopEvent != nullptr &&
        WaitForSingleObject(g_BridgeStopEvent, 0) == WAIT_TIMEOUT
        )
    {
        SOCKET client = accept(context->Listener, nullptr, nullptr);

        if (client == INVALID_SOCKET)
        {
            if (WaitForSingleObject(g_BridgeStopEvent, 0) != WAIT_TIMEOUT)
            {
                break;
            }

            continue;
        }

        ResetEvent(g_NoConnectionsEvent);
        LONG active = InterlockedIncrement(&g_ActiveConnections);

        if (active > kMaximumConnections)
        {
            closesocket(client);

            if (InterlockedDecrement(&g_ActiveConnections) == 0)
            {
                SetEvent(g_NoConnectionsEvent);
            }

            continue;
        }

        CONNECTION_CONTEXT* connection =
            static_cast<CONNECTION_CONTEXT*>(
                HeapAlloc(
                    GetProcessHeap(),
                    HEAP_ZERO_MEMORY,
                    sizeof(CONNECTION_CONTEXT)
                    )
                );

        if (connection == nullptr)
        {
            closesocket(client);

            if (InterlockedDecrement(&g_ActiveConnections) == 0)
            {
                SetEvent(g_NoConnectionsEvent);
            }

            continue;
        }

        connection->Client = client;
        HANDLE thread = CreateThread(
            nullptr,
            0,
            ConnectionThread,
            connection,
            0,
            nullptr
            );

        if (thread == nullptr)
        {
            HeapFree(GetProcessHeap(), 0, connection);
            closesocket(client);

            if (InterlockedDecrement(&g_ActiveConnections) == 0)
            {
                SetEvent(g_NoConnectionsEvent);
            }
        }
        else
        {
            CloseHandle(thread);
        }
    }

    return 0;
}

static SOCKET
CreateLoopbackListener(
    int addressFamily,
    unsigned short* port
    )
{
    SOCKET listener = WSASocketW(
        addressFamily,
        SOCK_STREAM,
        IPPROTO_TCP,
        nullptr,
        0,
        WSA_FLAG_OVERLAPPED
        );

    if (listener == INVALID_SOCKET)
    {
        return INVALID_SOCKET;
    }

    if (addressFamily == AF_INET)
    {
        sockaddr_in endpoint = {};
        endpoint.sin_family = AF_INET;
        endpoint.sin_port = 0;
        endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if (
            bind(
                listener,
                reinterpret_cast<const sockaddr*>(&endpoint),
                sizeof(endpoint)
                ) != 0
            )
        {
            closesocket(listener);
            return INVALID_SOCKET;
        }

        int endpointLength = sizeof(endpoint);

        if (
            getsockname(
                listener,
                reinterpret_cast<sockaddr*>(&endpoint),
                &endpointLength
                ) != 0
            )
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
            sizeof(v6Only)
            );

        sockaddr_in6 endpoint = {};
        endpoint.sin6_family = AF_INET6;
        endpoint.sin6_port = 0;
        endpoint.sin6_addr = in6addr_loopback;

        if (
            bind(
                listener,
                reinterpret_cast<const sockaddr*>(&endpoint),
                sizeof(endpoint)
                ) != 0
            )
        {
            closesocket(listener);
            return INVALID_SOCKET;
        }

        int endpointLength = sizeof(endpoint);

        if (
            getsockname(
                listener,
                reinterpret_cast<sockaddr*>(&endpoint),
                &endpointLength
                ) != 0
            )
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
IsProcessAlive(
    unsigned long long processId
    )
{
    if (processId == 0 || processId > MAXDWORD)
    {
        return false;
    }

    HANDLE process = OpenProcess(
        SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        static_cast<DWORD>(processId)
        );

    if (process == nullptr)
    {
        return false;
    }

    bool alive = WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
    CloseHandle(process);
    return alive;
}

static bool
AreBackendProcessesAlive(
    const std::vector<unsigned long long>& backendProcessIds
    )
{
    for (unsigned long long processId : backendProcessIds)
    {
        if (!IsProcessAlive(processId))
        {
            return false;
        }
    }

    return true;
}

static bool
ProbeLocalSocks()
{
    SOCKET socket = ConnectToLocalSocks(nullptr);

    if (socket == INVALID_SOCKET)
    {
        return false;
    }

    bool result = PerformSocksGreeting(socket);
    shutdown(socket, SD_BOTH);
    closesocket(socket);
    return result;
}


static const size_t kUdpMaximumSessions = 48;
static const ULONGLONG kUdpSessionIdleMilliseconds = 60000;
static const size_t kUdpMaximumDatagram = 65507;
static const size_t kUdpControlBufferBytes = 4096;

struct UDP_LISTENER_CONTEXT
{
    SOCKET Listener;
    int AddressFamily;
    LPFN_WSARECVMSG RecvMsg;
};

struct UDP_SESSION
{
    sockaddr_storage ClientAddress;
    int ClientAddressLength;
    SERPIUM_FLOW_REDIRECT_CONTEXT RedirectContext;
    bool Proxy;
    SOCKET Upstream;
    SOCKET SocksControl;
    sockaddr_storage SocksRelayAddress;
    int SocksRelayAddressLength;
    unsigned char RedirectRecords[kUdpControlBufferBytes];
    DWORD RedirectRecordsLength;
    bool RedirectRecordsPending;
    ULONGLONG LastActivity;
};

static LPFN_WSARECVMSG
ResolveWsaRecvMsg(
    SOCKET socket
    )
{
    GUID functionId = WSAID_WSARECVMSG;
    LPFN_WSARECVMSG functionPointer = nullptr;
    DWORD bytesReturned = 0;

    int result = WSAIoctl(
        socket,
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        &functionId,
        sizeof(functionId),
        &functionPointer,
        sizeof(functionPointer),
        &bytesReturned,
        nullptr,
        nullptr
        );

    return result == 0 ? functionPointer : nullptr;
}

static bool
SockaddrEquals(
    const sockaddr_storage& left,
    int leftLength,
    const sockaddr_storage& right,
    int rightLength
    )
{
    if (left.ss_family != right.ss_family)
    {
        return false;
    }

    if (left.ss_family == AF_INET &&
        leftLength >= static_cast<int>(sizeof(sockaddr_in)) &&
        rightLength >= static_cast<int>(sizeof(sockaddr_in)))
    {
        const sockaddr_in* a = reinterpret_cast<const sockaddr_in*>(&left);
        const sockaddr_in* b = reinterpret_cast<const sockaddr_in*>(&right);
        return a->sin_port == b->sin_port &&
            a->sin_addr.s_addr == b->sin_addr.s_addr;
    }

    if (left.ss_family == AF_INET6 &&
        leftLength >= static_cast<int>(sizeof(sockaddr_in6)) &&
        rightLength >= static_cast<int>(sizeof(sockaddr_in6)))
    {
        const sockaddr_in6* a = reinterpret_cast<const sockaddr_in6*>(&left);
        const sockaddr_in6* b = reinterpret_cast<const sockaddr_in6*>(&right);
        return a->sin6_port == b->sin6_port &&
            a->sin6_scope_id == b->sin6_scope_id &&
            std::memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(in6_addr)) == 0;
    }

    return false;
}

static bool
RedirectContextRemoteEquals(
    const SERPIUM_FLOW_REDIRECT_CONTEXT& left,
    const SERPIUM_FLOW_REDIRECT_CONTEXT& right
    )
{
    if (left.AddressFamily != right.AddressFamily ||
        left.RemotePort != right.RemotePort)
    {
        return false;
    }

    size_t addressLength = left.AddressFamily == AF_INET ? 4u : 16u;
    return std::memcmp(
        left.RemoteAddress,
        right.RemoteAddress,
        addressLength
        ) == 0;
}

static bool
BuildRemoteEndpoint(
    const SERPIUM_FLOW_REDIRECT_CONTEXT& context,
    sockaddr_storage* endpoint,
    int* endpointLength
    )
{
    ZeroMemory(endpoint, sizeof(*endpoint));

    if (context.AddressFamily == AF_INET)
    {
        sockaddr_in* address = reinterpret_cast<sockaddr_in*>(endpoint);
        address->sin_family = AF_INET;
        address->sin_port = htons(context.RemotePort);
        CopyMemory(&address->sin_addr, context.RemoteAddress, 4);
        *endpointLength = sizeof(*address);
        return true;
    }

    if (context.AddressFamily == AF_INET6)
    {
        sockaddr_in6* address = reinterpret_cast<sockaddr_in6*>(endpoint);
        address->sin6_family = AF_INET6;
        address->sin6_port = htons(context.RemotePort);
        CopyMemory(&address->sin6_addr, context.RemoteAddress, 16);
        *endpointLength = sizeof(*address);
        return true;
    }

    return false;
}

static bool
ReadSocksUdpRelayEndpoint(
    SOCKET control,
    sockaddr_storage* relayAddress,
    int* relayAddressLength
    )
{
    unsigned char header[4] = {};
    if (!ReceiveAll(control, header, sizeof(header)) ||
        header[0] != 0x05 ||
        header[1] != 0x00 ||
        header[2] != 0x00)
    {
        return false;
    }

    ZeroMemory(relayAddress, sizeof(*relayAddress));

    if (header[3] == 0x01)
    {
        unsigned char tail[6] = {};
        if (!ReceiveAll(control, tail, sizeof(tail)))
        {
            return false;
        }

        sockaddr_in* address = reinterpret_cast<sockaddr_in*>(relayAddress);
        address->sin_family = AF_INET;
        CopyMemory(&address->sin_addr, tail, 4);
        CopyMemory(&address->sin_port, tail + 4, 2);
        if (address->sin_addr.s_addr == INADDR_ANY)
        {
            address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        }
        if (address->sin_port == 0)
        {
            return false;
        }
        *relayAddressLength = sizeof(*address);
        return true;
    }

    if (header[3] == 0x04)
    {
        unsigned char tail[18] = {};
        if (!ReceiveAll(control, tail, sizeof(tail)))
        {
            return false;
        }

        sockaddr_in6* address = reinterpret_cast<sockaddr_in6*>(relayAddress);
        address->sin6_family = AF_INET6;
        CopyMemory(&address->sin6_addr, tail, 16);
        CopyMemory(&address->sin6_port, tail + 16, 2);

        static const in6_addr zeroAddress = {};
        if (std::memcmp(&address->sin6_addr, &zeroAddress, sizeof(zeroAddress)) == 0)
        {
            address->sin6_addr = in6addr_loopback;
        }
        if (address->sin6_port == 0)
        {
            return false;
        }
        *relayAddressLength = sizeof(*address);
        return true;
    }

    if (header[3] == 0x03)
    {
        unsigned char nameLength = 0;
        if (!ReceiveAll(control, &nameLength, 1) || nameLength == 0)
        {
            return false;
        }

        std::vector<char> name(static_cast<size_t>(nameLength) + 1, 0);
        unsigned char portBytes[2] = {};
        if (!ReceiveAll(
                control,
                reinterpret_cast<unsigned char*>(name.data()),
                nameLength) ||
            !ReceiveAll(control, portBytes, sizeof(portBytes)))
        {
            return false;
        }

        unsigned short port =
            static_cast<unsigned short>((portBytes[0] << 8) | portBytes[1]);
        if (port == 0)
        {
            return false;
        }

        char portText[8] = {};
        _snprintf_s(portText, sizeof(portText), _TRUNCATE, "%u", port);
        addrinfo hints = {};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
        addrinfo* resolved = nullptr;
        if (getaddrinfo(name.data(), portText, &hints, &resolved) != 0 ||
            resolved == nullptr)
        {
            if (resolved != nullptr)
            {
                freeaddrinfo(resolved);
            }
            return false;
        }

        bool copied = resolved->ai_addrlen <= sizeof(*relayAddress);
        if (copied)
        {
            CopyMemory(relayAddress, resolved->ai_addr, resolved->ai_addrlen);
            *relayAddressLength = static_cast<int>(resolved->ai_addrlen);
        }
        freeaddrinfo(resolved);
        return copied;
    }

    return false;
}

static bool
PerformSocksUdpAssociate(
    SOCKET control,
    sockaddr_storage* relayAddress,
    int* relayAddressLength
    )
{
    const unsigned char request[] = {
        0x05, 0x03, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    };

    return SendAll(control, request, sizeof(request)) &&
        ReadSocksUdpRelayEndpoint(
            control,
            relayAddress,
            relayAddressLength
            );
}

static bool
ProbeLocalSocksUdp()
{
    SOCKET control = ConnectToLocalSocks(nullptr);
    if (control == INVALID_SOCKET)
    {
        return false;
    }

    sockaddr_storage relay = {};
    int relayLength = 0;
    bool result = PerformSocksGreeting(control) &&
        PerformSocksUdpAssociate(control, &relay, &relayLength);

    shutdown(control, SD_BOTH);
    closesocket(control);
    return result;
}

static SOCKET
CreateLoopbackDatagramSocket(
    int addressFamily,
    unsigned short port
    )
{
    SOCKET socket = WSASocketW(
        addressFamily,
        SOCK_DGRAM,
        IPPROTO_UDP,
        nullptr,
        0,
        WSA_FLAG_OVERLAPPED
        );
    if (socket == INVALID_SOCKET)
    {
        return INVALID_SOCKET;
    }

    if (addressFamily == AF_INET)
    {
        sockaddr_in endpoint = {};
        endpoint.sin_family = AF_INET;
        endpoint.sin_port = htons(port);
        endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(
                socket,
                reinterpret_cast<const sockaddr*>(&endpoint),
                sizeof(endpoint)) != 0)
        {
            closesocket(socket);
            return INVALID_SOCKET;
        }
    }
    else
    {
        DWORD v6Only = 1;
        setsockopt(
            socket,
            IPPROTO_IPV6,
            IPV6_V6ONLY,
            reinterpret_cast<const char*>(&v6Only),
            sizeof(v6Only)
            );

        sockaddr_in6 endpoint = {};
        endpoint.sin6_family = AF_INET6;
        endpoint.sin6_port = htons(port);
        endpoint.sin6_addr = in6addr_loopback;
        if (bind(
                socket,
                reinterpret_cast<const sockaddr*>(&endpoint),
                sizeof(endpoint)) != 0)
        {
            closesocket(socket);
            return INVALID_SOCKET;
        }
    }

    return socket;
}

static bool
ParseUdpRedirectAncillary(
    WSAMSG* message,
    SERPIUM_FLOW_REDIRECT_CONTEXT* context,
    bool* contextPresent,
    unsigned char* redirectRecords,
    DWORD redirectRecordsCapacity,
    DWORD* redirectRecordsLength
    )
{
    *contextPresent = false;
    *redirectRecordsLength = 0;
    ZeroMemory(context, sizeof(*context));

    for (
        WSACMSGHDR* header = WSA_CMSG_FIRSTHDR(message);
        header != nullptr;
        header = WSA_CMSG_NXTHDR(message, header)
        )
    {
        if (header->cmsg_len < WSA_CMSG_LEN(0))
        {
            continue;
        }

        UINT dataLength = header->cmsg_len - WSA_CMSG_LEN(0);
        if (header->cmsg_type == IP_WFP_REDIRECT_CONTEXT &&
            dataLength >= sizeof(*context))
        {
            CopyMemory(context, WSA_CMSG_DATA(header), sizeof(*context));
            *contextPresent =
                context->Size == sizeof(*context) &&
                context->ProtocolVersion == SERPIUM_FLOW_PROTOCOL_VERSION &&
                context->Magic == SERPIUM_FLOW_REDIRECT_CONTEXT_MAGIC &&
                context->Protocol == IPPROTO_UDP &&
                context->RemotePort != 0 &&
                (context->AddressFamily == AF_INET ||
                 context->AddressFamily == AF_INET6);
        }
        else if (header->cmsg_type == IP_WFP_REDIRECT_RECORDS &&
                 dataLength > 0 &&
                 dataLength <= redirectRecordsCapacity)
        {
            CopyMemory(
                redirectRecords,
                WSA_CMSG_DATA(header),
                dataLength
                );
            *redirectRecordsLength = dataLength;
        }
    }

    return *contextPresent;
}

static bool
CreateUdpSession(
    const sockaddr_storage& clientAddress,
    int clientAddressLength,
    const SERPIUM_FLOW_REDIRECT_CONTEXT& redirectContext,
    bool proxy,
    const unsigned char* redirectRecords,
    DWORD redirectRecordsLength,
    UDP_SESSION* session
    )
{
    ZeroMemory(session, sizeof(*session));
    session->ClientAddress = clientAddress;
    session->ClientAddressLength = clientAddressLength;
    session->RedirectContext = redirectContext;
    session->Proxy = proxy;
    session->Upstream = INVALID_SOCKET;
    session->SocksControl = INVALID_SOCKET;
    session->RedirectRecordsLength = 0;
    session->RedirectRecordsPending = false;
    if (redirectRecords != nullptr &&
        redirectRecordsLength > 0 &&
        redirectRecordsLength <= sizeof(session->RedirectRecords))
    {
        CopyMemory(
            session->RedirectRecords,
            redirectRecords,
            redirectRecordsLength
            );
        session->RedirectRecordsLength = redirectRecordsLength;
        session->RedirectRecordsPending = true;
    }
    session->LastActivity = GetTickCount64();

    if (!proxy)
    {
        session->Upstream = WSASocketW(
            redirectContext.AddressFamily,
            SOCK_DGRAM,
            IPPROTO_UDP,
            nullptr,
            0,
            WSA_FLAG_OVERLAPPED
            );
        return session->Upstream != INVALID_SOCKET;
    }

    session->SocksControl = ConnectToLocalSocks(nullptr);
    if (session->SocksControl == INVALID_SOCKET ||
        !PerformSocksGreeting(session->SocksControl) ||
        !PerformSocksUdpAssociate(
            session->SocksControl,
            &session->SocksRelayAddress,
            &session->SocksRelayAddressLength))
    {
        if (session->SocksControl != INVALID_SOCKET)
        {
            shutdown(session->SocksControl, SD_BOTH);
            closesocket(session->SocksControl);
            session->SocksControl = INVALID_SOCKET;
        }
        return false;
    }

    session->Upstream = WSASocketW(
        session->SocksRelayAddress.ss_family,
        SOCK_DGRAM,
        IPPROTO_UDP,
        nullptr,
        0,
        WSA_FLAG_OVERLAPPED
        );

    if (session->Upstream == INVALID_SOCKET)
    {
        shutdown(session->SocksControl, SD_BOTH);
        closesocket(session->SocksControl);
        session->SocksControl = INVALID_SOCKET;
        return false;
    }

    return true;
}

static void
CloseUdpSession(
    UDP_SESSION* session
    )
{
    if (session->Upstream != INVALID_SOCKET)
    {
        closesocket(session->Upstream);
        session->Upstream = INVALID_SOCKET;
    }
    if (session->SocksControl != INVALID_SOCKET)
    {
        shutdown(session->SocksControl, SD_BOTH);
        closesocket(session->SocksControl);
        session->SocksControl = INVALID_SOCKET;
    }
}

static int
FindUdpSession(
    const std::vector<UDP_SESSION>& sessions,
    const sockaddr_storage& clientAddress,
    int clientAddressLength,
    const SERPIUM_FLOW_REDIRECT_CONTEXT* redirectContext
    )
{
    int sourceMatch = -1;
    bool sourceAmbiguous = false;

    for (size_t index = 0; index < sessions.size(); index++)
    {
        if (!SockaddrEquals(
                sessions[index].ClientAddress,
                sessions[index].ClientAddressLength,
                clientAddress,
                clientAddressLength))
        {
            continue;
        }

        if (redirectContext != nullptr &&
            RedirectContextRemoteEquals(
                sessions[index].RedirectContext,
                *redirectContext))
        {
            return static_cast<int>(index);
        }

        if (sourceMatch < 0)
        {
            sourceMatch = static_cast<int>(index);
        }
        else
        {
            sourceAmbiguous = true;
        }
    }

    return redirectContext == nullptr && !sourceAmbiguous
        ? sourceMatch
        : -1;
}

static int
SendUdpDatagram(
    UDP_SESSION* session,
    const unsigned char* data,
    int dataLength,
    const sockaddr* destination,
    int destinationLength
    )
{
    if (session->RedirectRecordsPending &&
        session->RedirectRecordsLength > 0)
    {
        std::vector<char> control(
            WSA_CMSG_SPACE(session->RedirectRecordsLength),
            0
            );
        WSABUF buffer = {};
        buffer.buf = reinterpret_cast<char*>(
            const_cast<unsigned char*>(data));
        buffer.len = static_cast<ULONG>(dataLength);
        WSAMSG message = {};
        message.name = const_cast<LPSOCKADDR>(destination);
        message.namelen = destinationLength;
        message.lpBuffers = &buffer;
        message.dwBufferCount = 1;
        message.Control.buf = control.data();
        message.Control.len = static_cast<ULONG>(control.size());

        WSACMSGHDR* header = WSA_CMSG_FIRSTHDR(&message);
        if (header != nullptr)
        {
            header->cmsg_len =
                WSA_CMSG_LEN(session->RedirectRecordsLength);
            header->cmsg_level = IPPROTO_IP;
            header->cmsg_type = IP_WFP_REDIRECT_RECORDS;
            CopyMemory(
                WSA_CMSG_DATA(header),
                session->RedirectRecords,
                session->RedirectRecordsLength
                );

            DWORD bytesSent = 0;
            int sendResult = WSASendMsg(
                session->Upstream,
                &message,
                0,
                &bytesSent,
                nullptr,
                nullptr
                );
            session->RedirectRecordsPending = false;
            session->RedirectRecordsLength = 0;
            if (sendResult == 0)
            {
                return static_cast<int>(bytesSent);
            }
        }

        // Backend PIDs and the bridge PID are kernel bypass identities, so a
        // provider that rejects ancillary WFP records must still fail open to
        // ordinary connectionless sendto rather than blackholing UDP.
        session->RedirectRecordsPending = false;
        session->RedirectRecordsLength = 0;
    }

    return sendto(
        session->Upstream,
        reinterpret_cast<const char*>(data),
        dataLength,
        0,
        destination,
        destinationLength
        );
}

static bool
SendUdpDirect(
    UDP_SESSION* session,
    const unsigned char* data,
    int dataLength
    )
{
    sockaddr_storage destination = {};
    int destinationLength = 0;
    if (!BuildRemoteEndpoint(
            session->RedirectContext,
            &destination,
            &destinationLength))
    {
        return false;
    }

    return SendUdpDatagram(
        session,
        data,
        dataLength,
        reinterpret_cast<const sockaddr*>(&destination),
        destinationLength
        ) == dataLength;
}

static bool
SendUdpViaSocks(
    UDP_SESSION* session,
    const unsigned char* data,
    int dataLength
    )
{
    size_t addressLength =
        session->RedirectContext.AddressFamily == AF_INET ? 4u : 16u;
    size_t headerLength = 4u + addressLength + 2u;
    if (static_cast<size_t>(dataLength) + headerLength > 65535u)
    {
        return false;
    }

    std::vector<unsigned char> packet(headerLength + dataLength, 0);
    packet[0] = 0x00;
    packet[1] = 0x00;
    packet[2] = 0x00;
    packet[3] = session->RedirectContext.AddressFamily == AF_INET
        ? 0x01
        : 0x04;
    CopyMemory(
        packet.data() + 4,
        session->RedirectContext.RemoteAddress,
        addressLength
        );
    size_t portOffset = 4u + addressLength;
    packet[portOffset] =
        static_cast<unsigned char>(session->RedirectContext.RemotePort >> 8);
    packet[portOffset + 1] =
        static_cast<unsigned char>(session->RedirectContext.RemotePort);
    CopyMemory(packet.data() + headerLength, data, dataLength);

    int sent = SendUdpDatagram(
        session,
        packet.data(),
        static_cast<int>(packet.size()),
        reinterpret_cast<const sockaddr*>(&session->SocksRelayAddress),
        session->SocksRelayAddressLength
        );
    return sent == static_cast<int>(packet.size());
}

static bool
ExtractSocksUdpPayload(
    const unsigned char* packet,
    int packetLength,
    const unsigned char** payload,
    int* payloadLength
    )
{
    if (packetLength < 10 ||
        packet[0] != 0x00 ||
        packet[1] != 0x00 ||
        packet[2] != 0x00)
    {
        return false;
    }

    size_t offset = 4;
    if (packet[3] == 0x01)
    {
        offset += 4;
    }
    else if (packet[3] == 0x04)
    {
        offset += 16;
    }
    else if (packet[3] == 0x03)
    {
        if (offset >= static_cast<size_t>(packetLength))
        {
            return false;
        }
        offset += 1u + packet[offset];
    }
    else
    {
        return false;
    }

    offset += 2;
    if (offset > static_cast<size_t>(packetLength))
    {
        return false;
    }

    *payload = packet + offset;
    *payloadLength = packetLength - static_cast<int>(offset);
    return true;
}

static void
PurgeIdleUdpSessions(
    std::vector<UDP_SESSION>* sessions
    )
{
    ULONGLONG now = GetTickCount64();
    for (size_t index = sessions->size(); index > 0; index--)
    {
        UDP_SESSION& session = (*sessions)[index - 1];
        if (now - session.LastActivity >= kUdpSessionIdleMilliseconds)
        {
            CloseUdpSession(&session);
            sessions->erase(sessions->begin() + static_cast<ptrdiff_t>(index - 1));
        }
    }
}

static DWORD WINAPI
UdpListenerThread(
    LPVOID parameter
    )
{
    UDP_LISTENER_CONTEXT* context =
        static_cast<UDP_LISTENER_CONTEXT*>(parameter);
    if (context == nullptr ||
        context->Listener == INVALID_SOCKET ||
        context->RecvMsg == nullptr)
    {
        return 2;
    }

    std::vector<UDP_SESSION> sessions;
    sessions.reserve(kUdpMaximumSessions);

    while (g_BridgeStopEvent != nullptr &&
           WaitForSingleObject(g_BridgeStopEvent, 0) == WAIT_TIMEOUT)
    {
        PurgeIdleUdpSessions(&sessions);

        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(context->Listener, &readSet);
        for (const UDP_SESSION& session : sessions)
        {
            if (session.Upstream != INVALID_SOCKET)
            {
                FD_SET(session.Upstream, &readSet);
            }
        }

        timeval timeout = {};
        timeout.tv_usec = 500000;
        int selected = select(0, &readSet, nullptr, nullptr, &timeout);
        if (selected == SOCKET_ERROR)
        {
            int selectError = WSAGetLastError();
            if (WaitForSingleObject(g_BridgeStopEvent, 0) != WAIT_TIMEOUT ||
                selectError == WSAENOTSOCK ||
                selectError == WSAEINVAL)
            {
                break;
            }
            continue;
        }

        if (selected == 0)
        {
            continue;
        }

        if (FD_ISSET(context->Listener, &readSet))
        {
            unsigned char payload[kUdpMaximumDatagram] = {};
            char controlBuffer[kUdpControlBufferBytes] = {};
            sockaddr_storage clientAddress = {};
            WSABUF buffer = {};
            buffer.buf = reinterpret_cast<char*>(payload);
            buffer.len = static_cast<ULONG>(sizeof(payload));
            WSAMSG message = {};
            message.name = reinterpret_cast<LPSOCKADDR>(&clientAddress);
            message.namelen = sizeof(clientAddress);
            message.lpBuffers = &buffer;
            message.dwBufferCount = 1;
            message.Control.buf = controlBuffer;
            message.Control.len = sizeof(controlBuffer);
            DWORD bytesReceived = 0;

            int receiveResult = context->RecvMsg(
                context->Listener,
                &message,
                &bytesReceived,
                nullptr,
                nullptr
                );

            if (receiveResult == 0 && bytesReceived > 0)
            {
                SERPIUM_FLOW_REDIRECT_CONTEXT redirectContext = {};
                bool contextPresent = false;
                unsigned char redirectRecords[kUdpControlBufferBytes] = {};
                DWORD redirectRecordsLength = 0;
                ParseUdpRedirectAncillary(
                    &message,
                    &redirectContext,
                    &contextPresent,
                    redirectRecords,
                    sizeof(redirectRecords),
                    &redirectRecordsLength
                    );

                int sessionIndex = FindUdpSession(
                    sessions,
                    clientAddress,
                    message.namelen,
                    contextPresent ? &redirectContext : nullptr
                    );

                if (sessionIndex < 0 && contextPresent)
                {
                    bool domainPolicyActive =
                        g_DomainAware && DomainPolicyHasRules();
                    bool explicitAppVpn =
                        redirectContext.ResolvedRoute == SERPIUM_FLOW_ROUTE_VPN &&
                        redirectContext.RuleId != 0;
                    bool proxy =
                        redirectContext.ResolvedRoute == SERPIUM_FLOW_ROUTE_VPN &&
                        (!domainPolicyActive || explicitAppVpn);

                    if (sessions.size() >= kUdpMaximumSessions)
                    {
                        size_t oldestIndex = 0;
                        for (size_t index = 1; index < sessions.size(); index++)
                        {
                            if (sessions[index].LastActivity < sessions[oldestIndex].LastActivity)
                            {
                                oldestIndex = index;
                            }
                        }
                        CloseUdpSession(&sessions[oldestIndex]);
                        sessions.erase(
                            sessions.begin() + static_cast<ptrdiff_t>(oldestIndex));
                    }

                    UDP_SESSION newSession = {};
                    if (CreateUdpSession(
                            clientAddress,
                            message.namelen,
                            redirectContext,
                            proxy,
                            redirectRecords,
                            redirectRecordsLength,
                            &newSession))
                    {
                        sessions.push_back(newSession);
                        sessionIndex = static_cast<int>(sessions.size() - 1);
                    }
                }

                if (sessionIndex >= 0)
                {
                    UDP_SESSION& session = sessions[sessionIndex];
                    session.LastActivity = GetTickCount64();
                    bool sent = session.Proxy
                        ? SendUdpViaSocks(
                            &session,
                            payload,
                            static_cast<int>(bytesReceived))
                        : SendUdpDirect(
                            &session,
                            payload,
                            static_cast<int>(bytesReceived));
                    if (!sent)
                    {
                        CloseUdpSession(&session);
                        sessions.erase(
                            sessions.begin() + static_cast<ptrdiff_t>(sessionIndex));
                    }
                }
            }
        }

        for (size_t index = sessions.size(); index > 0; index--)
        {
            UDP_SESSION& session = sessions[index - 1];
            if (session.Upstream == INVALID_SOCKET ||
                !FD_ISSET(session.Upstream, &readSet))
            {
                continue;
            }

            unsigned char response[kUdpMaximumDatagram] = {};
            sockaddr_storage source = {};
            int sourceLength = sizeof(source);
            int received = recvfrom(
                session.Upstream,
                reinterpret_cast<char*>(response),
                sizeof(response),
                0,
                reinterpret_cast<sockaddr*>(&source),
                &sourceLength
                );
            if (received <= 0)
            {
                continue;
            }

            const unsigned char* replyPayload = response;
            int replyLength = received;
            if (session.Proxy &&
                !ExtractSocksUdpPayload(
                    response,
                    received,
                    &replyPayload,
                    &replyLength))
            {
                continue;
            }

            int sent = sendto(
                context->Listener,
                reinterpret_cast<const char*>(replyPayload),
                replyLength,
                0,
                reinterpret_cast<const sockaddr*>(&session.ClientAddress),
                session.ClientAddressLength
                );
            if (sent == replyLength)
            {
                session.LastActivity = GetTickCount64();
            }
        }
    }

    for (UDP_SESSION& session : sessions)
    {
        CloseUdpSession(&session);
    }
    sessions.clear();
    return 0;
}

static BOOL WINAPI
BridgeConsoleHandler(
    DWORD controlType
    )
{
    if (
        controlType == CTRL_C_EVENT ||
        controlType == CTRL_BREAK_EVENT ||
        controlType == CTRL_CLOSE_EVENT ||
        controlType == CTRL_SHUTDOWN_EVENT
        )
    {
        if (g_BridgeStopEvent != nullptr)
        {
            SetEvent(g_BridgeStopEvent);
        }

        return TRUE;
    }

    return FALSE;
}

static bool
ParseUnsignedLong(
    const wchar_t* text,
    unsigned long long minimum,
    unsigned long long maximum,
    unsigned long long* value
    )
{
    if (text == nullptr || *text == L'\0')
    {
        return false;
    }

    wchar_t* end = nullptr;
    unsigned long long parsed = _wcstoui64(text, &end, 10);

    if (
        end == text ||
        *end != L'\0' ||
        parsed < minimum ||
        parsed > maximum
        )
    {
        return false;
    }

    *value = parsed;
    return true;
}

int
DisarmTcpRouteCommand()
{
    SERPIUM_FLOW_ROUTE_CONFIG_RESULT result = {};
    DWORD errorCode = ERROR_SUCCESS;

    if (!DisarmRoute(&result, &errorCode))
    {
        std::fwprintf(
            stderr,
            L"Route disarm failed. Win32 error=%lu\n",
            errorCode
            );
        return 2;
    }

    std::wprintf(
        L"SERPIUM_WFP4A_ROUTE_DISARMED\n"
        L"Config generation: %lu\n"
        L"Redirected: %llu\n"
        L"Redirect failures: %llu\n"
        L"Fail-open: %llu\n",
        result.ConfigGeneration,
        result.TotalRedirected,
        result.TotalRedirectFailures,
        result.TotalFailOpen
        );
    return 0;
}

static int
RunTcpRouteBridgeCommandInternal(
    int argumentCount,
    wchar_t** arguments,
    bool domainAware
    )
{
    if (
        argumentCount < 2 ||
        argumentCount >
            static_cast<int>(SERPIUM_FLOW_BYPASS_PID_CAPACITY + 1)
        )
    {
        std::fwprintf(
            stderr,
            domainAware
                ? L"Usage: bridge-domain <local-socks5-port> <backend-pid> [backend-pid ...]\n"
                : L"Usage: bridge <local-socks5-port> <backend-pid> [backend-pid ...]\n"
            );
        return 1;
    }

    g_DomainAware = domainAware;
    unsigned long long parsedPort = 0;

    if (!ParseUnsignedLong(arguments[0], 1, 65535, &parsedPort))
    {
        std::fwprintf(stderr, L"SOCKS5 port must be 1..65535.\n");
        return 1;
    }

    g_SocksPort = static_cast<unsigned short>(parsedPort);
    std::vector<unsigned long long> backendProcessIds;

    for (int index = 1; index < argumentCount; index++)
    {
        unsigned long long processId = 0;

        if (!ParseUnsignedLong(arguments[index], 1, MAXDWORD, &processId))
        {
            std::fwprintf(stderr, L"Backend PID is invalid.\n");
            return 1;
        }

        if (processId == GetCurrentProcessId())
        {
            std::fwprintf(
                stderr,
                L"Backend PID must not be the bridge PID.\n"
                );
            return 1;
        }

        for (unsigned long long existing : backendProcessIds)
        {
            if (existing == processId)
            {
                std::fwprintf(stderr, L"Backend PID values must be unique.\n");
                return 1;
            }
        }

        backendProcessIds.push_back(processId);
    }

    if (!AreBackendProcessesAlive(backendProcessIds))
    {
        std::fwprintf(stderr, L"A backend PID is not alive or cannot be queried.\n");
        return 2;
    }

    WSADATA winsock = {};

    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0)
    {
        std::fwprintf(stderr, L"WSAStartup failed.\n");
        return 2;
    }

    int exitCode = 2;
    SOCKET listenerV4 = INVALID_SOCKET;
    SOCKET listenerV6 = INVALID_SOCKET;
    SOCKET udpListenerV4 = INVALID_SOCKET;
    SOCKET udpListenerV6 = INVALID_SOCKET;
    HANDLE listenerThreadV4 = nullptr;
    HANDLE listenerThreadV6 = nullptr;
    HANDLE udpThreadV4 = nullptr;
    HANDLE udpThreadV6 = nullptr;
    bool udpAppRouting = false;
    bool routeArmed = false;
    unsigned short listenPortV4 = 0;
    unsigned short listenPortV6 = 0;
    LISTENER_CONTEXT contextV4 = {};
    LISTENER_CONTEXT contextV6 = {};
    UDP_LISTENER_CONTEXT udpContextV4 = {};
    UDP_LISTENER_CONTEXT udpContextV6 = {};
    SERPIUM_FLOW_ROUTE_CONFIG_RESULT routeResult = {};
    DWORD errorCode = ERROR_SUCCESS;
    bool connectionsStopped = true;

    g_BridgeStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_NoConnectionsEvent = CreateEventW(nullptr, TRUE, TRUE, nullptr);

    if (
        g_BridgeStopEvent == nullptr ||
        g_NoConnectionsEvent == nullptr
        )
    {
        std::fwprintf(stderr, L"Bridge event creation failed.\n");
        goto Cleanup;
    }

    if (!ProbeLocalSocks())
    {
        std::fwprintf(
            stderr,
            L"Local SOCKS5 no-auth preflight failed on 127.0.0.1:%u.\n",
            g_SocksPort
            );
        goto Cleanup;
    }

    listenerV4 = CreateLoopbackListener(AF_INET, &listenPortV4);
    listenerV6 = CreateLoopbackListener(AF_INET6, &listenPortV6);

    if (listenerV4 == INVALID_SOCKET || listenerV6 == INVALID_SOCKET)
    {
        std::fwprintf(stderr, L"Loopback listener creation failed.\n");
        goto Cleanup;
    }

    contextV4.Listener = listenerV4;
    contextV6.Listener = listenerV6;

    listenerThreadV4 = CreateThread(
        nullptr,
        0,
        ListenerThread,
        &contextV4,
        0,
        nullptr
        );
    listenerThreadV6 = CreateThread(
        nullptr,
        0,
        ListenerThread,
        &contextV6,
        0,
        nullptr
        );

    if (listenerThreadV4 == nullptr || listenerThreadV6 == nullptr)
    {
        std::fwprintf(stderr, L"Listener thread creation failed.\n");
        goto Cleanup;
    }

    // UDP/QUIC is an additive capability. If local SOCKS UDP ASSOCIATE or
    // WSARecvMsg ancillary-data support is unavailable, TCP routing remains
    // active and the kernel flag stays disabled.
    udpListenerV4 = CreateLoopbackDatagramSocket(AF_INET, listenPortV4);
    udpListenerV6 = CreateLoopbackDatagramSocket(AF_INET6, listenPortV6);

    if (udpListenerV4 != INVALID_SOCKET &&
        udpListenerV6 != INVALID_SOCKET &&
        ProbeLocalSocksUdp())
    {
        udpContextV4.Listener = udpListenerV4;
        udpContextV4.AddressFamily = AF_INET;
        udpContextV4.RecvMsg = ResolveWsaRecvMsg(udpListenerV4);
        udpContextV6.Listener = udpListenerV6;
        udpContextV6.AddressFamily = AF_INET6;
        udpContextV6.RecvMsg = ResolveWsaRecvMsg(udpListenerV6);

        if (udpContextV4.RecvMsg != nullptr &&
            udpContextV6.RecvMsg != nullptr)
        {
            udpThreadV4 = CreateThread(
                nullptr,
                0,
                UdpListenerThread,
                &udpContextV4,
                0,
                nullptr
                );
            udpThreadV6 = CreateThread(
                nullptr,
                0,
                UdpListenerThread,
                &udpContextV6,
                0,
                nullptr
                );

            udpAppRouting =
                udpThreadV4 != nullptr && udpThreadV6 != nullptr;
        }
    }

    if (!udpAppRouting)
    {
        std::wprintf(
            L"SERPIUM_WFP4A_UDP_APP_ROUTING_UNAVAILABLE\n"
            L"UDP/QUIC remains DIRECT; TCP routing continues.\n"
            );

        if (udpListenerV4 != INVALID_SOCKET)
        {
            closesocket(udpListenerV4);
            udpListenerV4 = INVALID_SOCKET;
        }
        if (udpListenerV6 != INVALID_SOCKET)
        {
            closesocket(udpListenerV6);
            udpListenerV6 = INVALID_SOCKET;
        }
        if (udpThreadV4 != nullptr)
        {
            CloseHandle(udpThreadV4);
            udpThreadV4 = nullptr;
        }
        if (udpThreadV6 != nullptr)
        {
            CloseHandle(udpThreadV6);
            udpThreadV6 = nullptr;
        }
    }

    if (!SendRouteConfiguration(
            backendProcessIds,
            listenPortV4,
            listenPortV6,
            domainAware,
            udpAppRouting,
            true,
            domainAware,
            &routeResult,
            &errorCode
            ))
    {
        std::fwprintf(
            stderr,
            L"Route arm failed. Win32 error=%lu\n",
            errorCode
            );
        goto Cleanup;
    }

    routeArmed = true;
    SetConsoleCtrlHandler(BridgeConsoleHandler, TRUE);

    if (domainAware)
    {
        HANDLE policyThread = CreateThread(
            nullptr,
            0,
            DomainPolicyInputThread,
            nullptr,
            0,
            nullptr
            );
        if (policyThread != nullptr)
        {
            CloseHandle(policyThread);
        }
    }

    if (udpAppRouting)
    {
        std::wprintf(L"SERPIUM_WFP4A_UDP_APP_ROUTING_ACTIVE\n");
    }

    if ((routeResult.Flags &
         SERPIUM_FLOW_ROUTE_CONFIG_FLAG_QUIC_TCP_FALLBACK) != 0)
    {
        std::wprintf(L"SERPIUM_WFP4A_QUIC_TCP_FALLBACK_ACTIVE\n");
    }

    if ((routeResult.Flags &
         SERPIUM_FLOW_ROUTE_CONFIG_FLAG_DOMAIN_QUIC_FALLBACK) != 0)
    {
        std::wprintf(L"SERPIUM_WFP4A_DOMAIN_QUIC_FALLBACK_ACTIVE\n");
    }

    std::wprintf(
        L"SERPIUM_WFP4A_BRIDGE_READY\n"
        L"Bridge PID: %lu\n"
        L"TCP listener V4: 127.0.0.1:%u\n"
        L"TCP listener V6: [::1]:%u\n"
        L"UDP listener V4: %ls\n"
        L"UDP listener V6: %ls\n"
        L"SOCKS5 backend: 127.0.0.1:%u\n"
        L"Backend bypass PIDs: %lu\n"
        L"Domain inspection: %ls\n"
        L"Lease: %lu ms\n"
        L"Press Ctrl+C to disarm and stop.\n",
        GetCurrentProcessId(),
        listenPortV4,
        listenPortV6,
        udpAppRouting ? L"enabled on TCP V4 port" : L"disabled",
        udpAppRouting ? L"enabled on TCP V6 port" : L"disabled",
        g_SocksPort,
        static_cast<unsigned long>(backendProcessIds.size()),
        domainAware ? L"enabled" : L"disabled",
        kLeaseMilliseconds
        );

    exitCode = 0;

    while (
        WaitForSingleObject(
            g_BridgeStopEvent,
            kLeaseRenewMilliseconds
            ) == WAIT_TIMEOUT
        )
    {
        if (
            !AreBackendProcessesAlive(backendProcessIds) ||
            !ProbeLocalSocks() ||
            (udpAppRouting &&
             (!ProbeLocalSocksUdp() ||
              udpThreadV4 == nullptr ||
              udpThreadV6 == nullptr ||
              WaitForSingleObject(udpThreadV4, 0) != WAIT_TIMEOUT ||
              WaitForSingleObject(udpThreadV6, 0) != WAIT_TIMEOUT))
            )
        {
            std::fwprintf(
                stderr,
                L"Backend health check failed; route is being disarmed.\n"
                );
            exitCode = 3;
            break;
        }

        if (!SendRouteConfiguration(
                backendProcessIds,
                listenPortV4,
                listenPortV6,
                domainAware,
                udpAppRouting,
                true,
                domainAware,
                &routeResult,
                &errorCode
                ))
        {
            std::fwprintf(
                stderr,
                L"Route lease renewal failed. Win32 error=%lu\n",
                errorCode
                );
            exitCode = 3;
            break;
        }
    }

Cleanup:
    if (g_BridgeStopEvent != nullptr)
    {
        SetEvent(g_BridgeStopEvent);
    }

    if (routeArmed)
    {
        SERPIUM_FLOW_ROUTE_CONFIG_RESULT disarmResult = {};
        DWORD disarmError = ERROR_SUCCESS;

        if (!DisarmRoute(&disarmResult, &disarmError))
        {
            std::fwprintf(
                stderr,
                L"Route disarm failed during bridge shutdown. Win32 error=%lu\n",
                disarmError
                );
            exitCode = 4;
        }
        else
        {
            std::wprintf(
                L"SERPIUM_WFP4A_BRIDGE_DISARMED\n"
                L"Redirected: %llu\n"
                L"Redirect failures: %llu\n"
                L"Fail-open: %llu\n",
                disarmResult.TotalRedirected,
                disarmResult.TotalRedirectFailures,
                disarmResult.TotalFailOpen
                );
        }
    }

    if (listenerV4 != INVALID_SOCKET)
    {
        shutdown(listenerV4, SD_BOTH);
        closesocket(listenerV4);
    }

    if (listenerV6 != INVALID_SOCKET)
    {
        shutdown(listenerV6, SD_BOTH);
        closesocket(listenerV6);
    }

    if (udpListenerV4 != INVALID_SOCKET)
    {
        closesocket(udpListenerV4);
        udpListenerV4 = INVALID_SOCKET;
    }
    if (udpListenerV6 != INVALID_SOCKET)
    {
        closesocket(udpListenerV6);
        udpListenerV6 = INVALID_SOCKET;
    }

    if (listenerThreadV4 != nullptr)
    {
        WaitForSingleObject(listenerThreadV4, 5000);
        CloseHandle(listenerThreadV4);
    }

    if (listenerThreadV6 != nullptr)
    {
        WaitForSingleObject(listenerThreadV6, 5000);
        CloseHandle(listenerThreadV6);
    }

    if (udpThreadV4 != nullptr)
    {
        WaitForSingleObject(udpThreadV4, 5000);
        CloseHandle(udpThreadV4);
    }
    if (udpThreadV6 != nullptr)
    {
        WaitForSingleObject(udpThreadV6, 5000);
        CloseHandle(udpThreadV6);
    }

    if (g_NoConnectionsEvent != nullptr)
    {
        connectionsStopped =
            WaitForSingleObject(g_NoConnectionsEvent, 15000) ==
                WAIT_OBJECT_0;

        if (connectionsStopped)
        {
            CloseHandle(g_NoConnectionsEvent);
            g_NoConnectionsEvent = nullptr;
        }
    }

    if (g_BridgeStopEvent != nullptr && connectionsStopped)
    {
        CloseHandle(g_BridgeStopEvent);
        g_BridgeStopEvent = nullptr;
    }

    SetConsoleCtrlHandler(BridgeConsoleHandler, FALSE);

    if (connectionsStopped)
    {
        g_ActiveConnections = 0;
        g_SocksPort = 0;
        g_DomainAware = false;
        AcquireSRWLockExclusive(&g_DomainPolicyLock);
        g_DomainRules.clear();
        ReleaseSRWLockExclusive(&g_DomainPolicyLock);
        WSACleanup();
    }

    return exitCode;
}

int
RunTcpRouteBridgeCommand(
    int argumentCount,
    wchar_t** arguments
    )
{
    return RunTcpRouteBridgeCommandInternal(
        argumentCount,
        arguments,
        false
        );
}

int
RunTcpDomainRouteBridgeCommand(
    int argumentCount,
    wchar_t** arguments
    )
{
    return RunTcpRouteBridgeCommandInternal(
        argumentCount,
        arguments,
        true
        );
}

