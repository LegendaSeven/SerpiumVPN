#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "..\Serpium.Wfp.Protocol\serpium_wfp_protocol.h"

static std::wstring EventTypeName(unsigned long type)
{
    switch (type)
    {
        case SERPIUM_WFP_EVENT_CONNECT_ATTEMPT:
            return L"CONNECT";
        case SERPIUM_WFP_EVENT_FLOW_OPEN:
            return L"OPEN";
        case SERPIUM_WFP_EVENT_FLOW_CLOSE:
            return L"CLOSE";
        default:
            return L"UNKNOWN";
    }
}

static std::wstring ProtocolName(unsigned char protocol)
{
    switch (protocol)
    {
        case IPPROTO_TCP:
            return L"TCP";
        case IPPROTO_UDP:
            return L"UDP";
        case IPPROTO_ICMP:
            return L"ICMP";
        case IPPROTO_ICMPV6:
            return L"ICMPv6";
        default:
            return std::to_wstring(protocol);
    }
}

static std::wstring FormatAddress(
    unsigned short family,
    const unsigned char bytes[16])
{
    wchar_t buffer[INET6_ADDRSTRLEN] = {};

    if (family == AF_INET)
    {
        IN_ADDR address = {};
        memcpy(&address, bytes, sizeof(address));

        if (InetNtopW(
                AF_INET,
                &address,
                buffer,
                static_cast<DWORD>(std::size(buffer))) != nullptr)
        {
            return buffer;
        }
    }
    else if (family == AF_INET6)
    {
        IN6_ADDR address = {};
        memcpy(&address, bytes, sizeof(address));

        if (InetNtopW(
                AF_INET6,
                &address,
                buffer,
                static_cast<DWORD>(std::size(buffer))) != nullptr)
        {
            return buffer;
        }
    }

    return L"?";
}

static std::wstring AppPath(
    const SERPIUM_WFP_EVENT& event)
{
    if ((event.Flags & SERPIUM_WFP_EVENT_FLAG_APP_ID) == 0 ||
        event.AppIdByteLength == 0)
    {
        return L"<unknown>";
    }

    size_t chars =
        std::min<size_t>(
            event.AppIdByteLength / sizeof(wchar_t),
            SERPIUM_WFP_APP_ID_MAX_CHARS - 1);

    return std::wstring(
        reinterpret_cast<const wchar_t*>(event.AppId),
        chars);
}

static HANDLE OpenDriver()
{
    return CreateFileW(
        SERPIUM_WFP_WIN32_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
}

static int PrintStatus(HANDLE device)
{
    SERPIUM_WFP_STATUS status = {};
    DWORD returned = 0;

    if (!DeviceIoControl(
            device,
            IOCTL_SERPIUM_WFP_GET_STATUS,
            nullptr,
            0,
            &status,
            sizeof(status),
            &returned,
            nullptr))
    {
        std::wcerr
            << L"GET_STATUS failed: "
            << GetLastError()
            << L"\n";

        return 2;
    }

    std::wcout
        << L"protocol=0x"
        << std::hex
        << status.ProtocolVersion
        << std::dec
        << L"\nversion="
        << status.DriverVersionMajor
        << L"."
        << status.DriverVersionMinor
        << L"."
        << status.DriverVersionPatch
        << L"\nqueue="
        << status.QueueCount
        << L"/"
        << status.QueueCapacity
        << L"\ntotal="
        << status.TotalEvents
        << L"\ndropped="
        << status.DroppedEvents
        << L"\nauth4="
        << status.AuthCalloutIdV4
        << L" auth6="
        << status.AuthCalloutIdV6
        << L" flow4="
        << status.FlowCalloutIdV4
        << L" flow6="
        << status.FlowCalloutIdV6
        << L"\n";

    return 0;
}

static int Stream(HANDLE device)
{
    std::wcout
        << L"Serpium WFP realtime stream. Ctrl+C to stop.\n";

    for (;;)
    {
        SERPIUM_WFP_EVENT event = {};
        DWORD read = 0;

        BOOL ok = ReadFile(
            device,
            &event,
            sizeof(event),
            &read,
            nullptr);

        if (!ok)
        {
            DWORD error = GetLastError();

            if (error == ERROR_OPERATION_ABORTED)
            {
                return 0;
            }

            std::wcerr
                << L"ReadFile failed: "
                << error
                << L"\n";

            return 3;
        }

        if (read != sizeof(event) ||
            event.ProtocolVersion != SERPIUM_WFP_PROTOCOL_VERSION)
        {
            std::wcerr
                << L"Protocol/event size mismatch.\n";

            return 4;
        }

        std::wcout
            << L"#"
            << event.Sequence
            << L" "
            << EventTypeName(event.Type)
            << L" pid="
            << event.ProcessId
            << L" flow="
            << event.FlowId
            << L" "
            << ProtocolName(event.Protocol)
            << L" "
            << FormatAddress(event.AddressFamily, event.LocalAddress)
            << L":"
            << event.LocalPort
            << L" -> "
            << FormatAddress(event.AddressFamily, event.RemoteAddress)
            << L":"
            << event.RemotePort
            << L" app=\""
            << AppPath(event)
            << L"\""
            << std::endl;
    }
}

int wmain(int argc, wchar_t** argv)
{
    std::wstring command =
        argc > 1
            ? argv[1]
            : L"stream";

    HANDLE device = OpenDriver();

    if (device == INVALID_HANDLE_VALUE)
    {
        std::wcerr
            << L"Cannot open "
            << SERPIUM_WFP_WIN32_DEVICE_NAME
            << L". Win32="
            << GetLastError()
            << L"\n";

        return 1;
    }

    int result = 0;

    if (_wcsicmp(command.c_str(), L"status") == 0)
    {
        result = PrintStatus(device);
    }
    else if (_wcsicmp(command.c_str(), L"stream") == 0)
    {
        result = Stream(device);
    }
    else
    {
        std::wcerr
            << L"Usage: Serpium.Wfp.Monitor.exe [status|stream]\n";

        result = 5;
    }

    CloseHandle(device);
    return result;
}
