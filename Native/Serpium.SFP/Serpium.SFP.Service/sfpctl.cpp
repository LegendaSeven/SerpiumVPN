#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <fwpmu.h>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

#include "..\Serpium.SFP.Protocol\serpium_sfp_protocol.h"

static const wchar_t* RouteName(unsigned long route)
{
    switch (route)
    {
        case SERPIUM_SFP_ROUTE_DIRECT:
            return L"DIRECT";
        case SERPIUM_SFP_ROUTE_VPN:
            return L"VPN";
        default:
            return L"UNSPECIFIED";
    }
}

static unsigned long ParseRoute(const std::wstring& text)
{
    if (_wcsicmp(text.c_str(), L"DIRECT") == 0)
        return SERPIUM_SFP_ROUTE_DIRECT;

    if (_wcsicmp(text.c_str(), L"VPN") == 0)
        return SERPIUM_SFP_ROUTE_VPN;

    throw std::runtime_error("route must be DIRECT or VPN");
}

static std::wstring EventTypeName(unsigned long type)
{
    switch (type)
    {
        case SERPIUM_SFP_EVENT_CONNECT_ATTEMPT:
            return L"CONNECT";
        case SERPIUM_SFP_EVENT_FLOW_OPEN:
            return L"OPEN";
        case SERPIUM_SFP_EVENT_FLOW_CLOSE:
            return L"CLOSE";
        case SERPIUM_SFP_EVENT_POLICY_REPLACED:
            return L"POLICY";
        default:
            return L"UNKNOWN";
    }
}

static std::wstring ProtocolName(unsigned char protocol)
{
    switch (protocol)
    {
        case IPPROTO_TCP: return L"TCP";
        case IPPROTO_UDP: return L"UDP";
        case IPPROTO_ICMP: return L"ICMP";
        case IPPROTO_ICMPV6: return L"ICMPv6";
        default: return std::to_wstring(protocol);
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
            return buffer;
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
            return buffer;
    }

    return L"?";
}

static std::wstring AppPath(const SERPIUM_SFP_EVENT& event)
{
    if ((event.Flags & SERPIUM_SFP_EVENT_FLAG_APP_ID) == 0 ||
        event.AppIdByteLength == 0)
        return L"<unknown>";

    size_t chars =
        std::min<size_t>(
            event.AppIdByteLength / sizeof(wchar_t),
            SERPIUM_SFP_APP_ID_MAX_CHARS - 1);

    return std::wstring(
        reinterpret_cast<const wchar_t*>(event.AppId),
        chars);
}

static HANDLE OpenKernel()
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

static uint64_t HashBytes(const unsigned char* data, size_t size)
{
    uint64_t hash = 14695981039346656037ull;

    for (size_t index = 0; index < size; index++)
    {
        hash ^= data[index];
        hash *= 1099511628211ull;
    }

    return hash;
}

static uint64_t HashAppPath(const std::wstring& path)
{
    FWP_BYTE_BLOB* appId = nullptr;

    DWORD result =
        FwpmGetAppIdFromFileName0(
            path.c_str(),
            &appId);

    if (result != ERROR_SUCCESS || appId == nullptr)
    {
        std::ostringstream message;
        message
            << "FwpmGetAppIdFromFileName0 failed: 0x"
            << std::hex
            << result;

        throw std::runtime_error(message.str());
    }

    uint64_t hash =
        HashBytes(
            appId->data,
            appId->size);

    FwpmFreeMemory0(
        reinterpret_cast<void**>(&appId));

    return hash;
}

static int PrintStatus(HANDLE device)
{
    SERPIUM_SFP_STATUS status = {};
    DWORD returned = 0;

    if (!DeviceIoControl(
            device,
            IOCTL_SERPIUM_SFP_GET_STATUS,
            nullptr,
            0,
            &status,
            sizeof(status),
            &returned,
            nullptr))
    {
        std::wcerr << L"GET_STATUS failed: " << GetLastError() << L"\n";
        return 2;
    }

    std::wcout
        << L"protocol=0x"
        << std::hex << status.ProtocolVersion << std::dec
        << L"\nkernel="
        << status.KernelVersionMajor << L"."
        << status.KernelVersionMinor << L"."
        << status.KernelVersionPatch
        << L"\npolicyGeneration=" << status.PolicyGeneration
        << L"\npolicyCount=" << status.PolicyCount
        << L"\ndefaultRoute=" << RouteName(status.DefaultRoute)
        << L"\nactiveFlows=" << status.ActiveFlowCount
        << L"\nqueue=" << status.QueueCount
        << L"/" << status.QueueCapacity
        << L"\ntotalEvents=" << status.TotalEvents
        << L"\ndroppedEvents=" << status.DroppedEvents
        << L"\nauth4=" << status.AuthCalloutIdV4
        << L" auth6=" << status.AuthCalloutIdV6
        << L" flow4=" << status.FlowCalloutIdV4
        << L" flow6=" << status.FlowCalloutIdV6
        << L"\nredirect4=" << status.RedirectCalloutIdV4
        << L" redirect6=" << status.RedirectCalloutIdV6
        << L"\nbridgeArmed=" << status.BridgeArmed
        << L" bridgePid=" << status.BridgeProcessId
        << L" listen4=" << status.BridgeListenPortV4
        << L" listen6=" << status.BridgeListenPortV6
        << L"\nredirected=" << status.TotalRedirected
        << L" failOpen=" << status.TotalRedirectFailOpen
        << L"\n";

    return 0;
}

static int Stream(HANDLE device)
{
    std::wcout << L"SFP realtime stream. Ctrl+C to stop.\n";

    for (;;)
    {
        SERPIUM_SFP_EVENT event = {};
        DWORD read = 0;

        BOOL ok =
            ReadFile(
                device,
                &event,
                sizeof(event),
                &read,
                nullptr);

        if (!ok)
        {
            DWORD error = GetLastError();

            if (error == ERROR_OPERATION_ABORTED)
                return 0;

            std::wcerr << L"ReadFile failed: " << error << L"\n";
            return 3;
        }

        if (read != sizeof(event) ||
            event.ProtocolVersion != SERPIUM_SFP_PROTOCOL_VERSION)
        {
            std::wcerr << L"Protocol/event size mismatch.\n";
            return 4;
        }

        std::wcout
            << L"#" << event.Sequence
            << L" " << EventTypeName(event.Type)
            << L" route=" << RouteName(event.Route)
            << L" gen=" << event.PolicyGeneration
            << L" pid=" << event.ProcessId
            << L" flow=" << event.FlowId
            << L" appHash=0x"
            << std::hex << event.AppIdHash << std::dec
            << L" " << ProtocolName(event.Protocol);

        if (event.AddressFamily == AF_INET ||
            event.AddressFamily == AF_INET6)
        {
            std::wcout
                << L" "
                << FormatAddress(event.AddressFamily, event.LocalAddress)
                << L":" << event.LocalPort
                << L" -> "
                << FormatAddress(event.AddressFamily, event.RemoteAddress)
                << L":" << event.RemotePort;
        }

        if ((event.Flags & SERPIUM_SFP_EVENT_FLAG_APP_ID) != 0)
            std::wcout << L" app=\"" << AppPath(event) << L"\"";

        std::wcout << std::endl;
    }
}

static int HashAppCommand(const std::wstring& path)
{
    uint64_t hash = HashAppPath(path);

    std::wcout
        << L"0x"
        << std::hex
        << hash
        << std::dec
        << L"  "
        << path
        << L"\n";

    return 0;
}

static std::wstring Trim(std::wstring value)
{
    while (!value.empty() && iswspace(value.front()))
        value.erase(value.begin());

    while (!value.empty() && iswspace(value.back()))
        value.pop_back();

    return value;
}

static int ReplacePolicy(
    HANDLE device,
    uint64_t generation,
    unsigned long defaultRoute,
    const std::wstring& filePath)
{
    std::wifstream file(filePath);

    if (!file)
    {
        std::wcerr << L"Cannot open policy file: " << filePath << L"\n";
        return 10;
    }

    std::vector<SERPIUM_SFP_POLICY_ENTRY> entries;
    std::unordered_set<uint64_t> unique;

    std::wstring line;
    unsigned long lineNumber = 0;

    while (std::getline(file, line))
    {
        lineNumber++;
        line = Trim(line);

        if (line.empty() || line[0] == L'#')
            continue;

        size_t split = line.find(L'|');

        if (split == std::wstring::npos)
        {
            std::wcerr
                << L"Policy line "
                << lineNumber
                << L": expected ROUTE|C:\\path\\app.exe\n";
            return 11;
        }

        std::wstring routeText =
            Trim(line.substr(0, split));
        std::wstring path =
            Trim(line.substr(split + 1));

        if (path.empty())
        {
            std::wcerr << L"Policy line " << lineNumber << L": empty path\n";
            return 12;
        }

        unsigned long route = 0;

        try
        {
            route = ParseRoute(routeText);
        }
        catch (const std::exception&)
        {
            std::wcerr << L"Policy line " << lineNumber << L": invalid route\n";
            return 13;
        }

        uint64_t hash = 0;

        try
        {
            hash = HashAppPath(path);
        }
        catch (const std::exception& ex)
        {
            std::cerr << "Policy app-id error: " << ex.what() << "\n";
            return 14;
        }

        if (!unique.insert(hash).second)
        {
            std::wcerr
                << L"Policy line "
                << lineNumber
                << L": duplicate app id\n";
            return 15;
        }

        SERPIUM_SFP_POLICY_ENTRY entry = {};
        entry.AppIdHash = hash;
        entry.Route = route;
        entries.push_back(entry);
    }

    if (entries.size() > SERPIUM_SFP_MAX_POLICY_ENTRIES)
    {
        std::wcerr << L"Too many policy entries.\n";
        return 16;
    }

    size_t bytes =
        offsetof(SERPIUM_SFP_POLICY_REPLACE_REQUEST, Entries) +
        entries.size() * sizeof(SERPIUM_SFP_POLICY_ENTRY);

    std::vector<unsigned char> buffer(bytes, 0);

    auto* request =
        reinterpret_cast<SERPIUM_SFP_POLICY_REPLACE_REQUEST*>(
            buffer.data());

    request->Size = static_cast<unsigned long>(bytes);
    request->ProtocolVersion =
        SERPIUM_SFP_PROTOCOL_VERSION;
    request->Generation = generation;
    request->DefaultRoute = defaultRoute;
    request->EntryCount =
        static_cast<unsigned long>(entries.size());

    if (!entries.empty())
    {
        memcpy(
            request->Entries,
            entries.data(),
            entries.size() * sizeof(SERPIUM_SFP_POLICY_ENTRY));
    }

    DWORD returned = 0;

    if (!DeviceIoControl(
            device,
            IOCTL_SERPIUM_SFP_REPLACE_POLICY,
            request,
            static_cast<DWORD>(bytes),
            nullptr,
            0,
            &returned,
            nullptr))
    {
        std::wcerr
            << L"REPLACE_POLICY failed: "
            << GetLastError()
            << L"\n";

        return 17;
    }

    std::wcout
        << L"policy replaced: gen="
        << generation
        << L" default="
        << RouteName(defaultRoute)
        << L" entries="
        << entries.size()
        << L"\n";

    return 0;
}

static int QueryFlows(HANDLE device)
{
    constexpr DWORD BufferSize = 1024 * 1024;
    std::vector<unsigned char> buffer(BufferSize, 0);
    DWORD returned = 0;

    if (!DeviceIoControl(
            device,
            IOCTL_SERPIUM_SFP_QUERY_FLOWS,
            nullptr,
            0,
            buffer.data(),
            BufferSize,
            &returned,
            nullptr))
    {
        std::wcerr
            << L"QUERY_FLOWS failed: "
            << GetLastError()
            << L"\n";

        return 20;
    }

    const auto* response =
        reinterpret_cast<const SERPIUM_SFP_FLOW_QUERY_RESPONSE*>(
            buffer.data());

    std::wcout
        << L"active="
        << response->TotalFlowCount
        << L" returned="
        << response->ReturnedFlowCount
        << L" truncated="
        << response->Truncated
        << L"\n";

    for (unsigned long i = 0; i < response->ReturnedFlowCount; i++)
    {
        const auto& flow = response->Flows[i];

        std::wcout
            << L"flow=" << flow.FlowId
            << L" pid=" << flow.ProcessId
            << L" appHash=0x"
            << std::hex << flow.AppIdHash << std::dec
            << L" route=" << RouteName(flow.Route)
            << L" gen=" << flow.PolicyGeneration
            << L" " << ProtocolName(flow.Protocol)
            << L" "
            << flow.LocalPort
            << L" -> "
            << flow.RemotePort
            << L"\n";
    }

    return 0;
}

static int AbortStale(
    HANDLE device,
    const std::wstring& appPath,
    uint64_t keepGeneration)
{
    uint64_t hash = 0;

    try
    {
        hash = HashAppPath(appPath);
    }
    catch (const std::exception& ex)
    {
        std::cerr << "App-id error: " << ex.what() << "\n";
        return 30;
    }

    SERPIUM_SFP_ABORT_STALE_REQUEST request = {};
    request.Size = sizeof(request);
    request.ProtocolVersion =
        SERPIUM_SFP_PROTOCOL_VERSION;
    request.AppIdHash = hash;
    request.KeepGeneration = keepGeneration;

    SERPIUM_SFP_ABORT_STALE_RESPONSE response = {};
    DWORD returned = 0;

    if (!DeviceIoControl(
            device,
            IOCTL_SERPIUM_SFP_ABORT_STALE,
            &request,
            sizeof(request),
            &response,
            sizeof(response),
            &returned,
            nullptr))
    {
        std::wcerr
            << L"ABORT_STALE failed: "
            << GetLastError()
            << L"\n";

        return 31;
    }

    std::wcout
        << L"matched=" << response.Matched
        << L" aborted=" << response.Aborted
        << L" failed=" << response.Failed
        << L"\n";

    return response.Failed == 0 ? 0 : 32;
}

static void Usage()
{
    std::wcerr
        << L"Serpium.SFP.Service.exe commands:\n"
        << L"  status\n"
        << L"  stream\n"
        << L"  hash-app <exe>\n"
        << L"  replace <generation> <DIRECT|VPN> <policy.txt>\n"
        << L"  flows\n"
        << L"  abort-stale <exe> <keep-generation>\n\n"
        << L"policy.txt format:\n"
        << L"  VPN|C:\\Program Files\\Browser\\browser.exe\n"
        << L"  DIRECT|C:\\Program Files\\Other\\other.exe\n";
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2)
    {
        Usage();
        return 1;
    }

    std::wstring command = argv[1];

    if (_wcsicmp(command.c_str(), L"hash-app") == 0)
    {
        if (argc != 3)
        {
            Usage();
            return 1;
        }

        try
        {
            return HashAppCommand(argv[2]);
        }
        catch (const std::exception& ex)
        {
            std::cerr << ex.what() << "\n";
            return 40;
        }
    }

    HANDLE device = OpenKernel();

    if (device == INVALID_HANDLE_VALUE)
    {
        std::wcerr
            << L"Cannot open "
            << SERPIUM_SFP_WIN32_DEVICE_NAME
            << L". Win32="
            << GetLastError()
            << L"\n";

        return 1;
    }

    int result = 0;

    try
    {
        if (_wcsicmp(command.c_str(), L"status") == 0)
        {
            result = PrintStatus(device);
        }
        else if (_wcsicmp(command.c_str(), L"stream") == 0)
        {
            result = Stream(device);
        }
        else if (_wcsicmp(command.c_str(), L"replace") == 0)
        {
            if (argc != 5)
            {
                Usage();
                result = 1;
            }
            else
            {
                uint64_t generation =
                    _wcstoui64(argv[2], nullptr, 10);

                unsigned long route =
                    ParseRoute(argv[3]);

                result =
                    ReplacePolicy(
                        device,
                        generation,
                        route,
                        argv[4]);
            }
        }
        else if (_wcsicmp(command.c_str(), L"flows") == 0)
        {
            result = QueryFlows(device);
        }
        else if (_wcsicmp(command.c_str(), L"abort-stale") == 0)
        {
            if (argc != 4)
            {
                Usage();
                result = 1;
            }
            else
            {
                uint64_t generation =
                    _wcstoui64(argv[3], nullptr, 10);

                result =
                    AbortStale(
                        device,
                        argv[2],
                        generation);
            }
        }
        else
        {
            Usage();
            result = 1;
        }
    }
    catch (const std::exception& ex)
    {
        std::cerr << ex.what() << "\n";
        result = 41;
    }

    CloseHandle(device);
    return result;
}
