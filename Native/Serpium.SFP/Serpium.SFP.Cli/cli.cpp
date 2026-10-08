#define WIN32_LEAN_AND_MEAN

#include <windows.h>

#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "..\Serpium.SFP.Api\serpium_sfp_api_protocol.h"
#include "..\Serpium.SFP.Protocol\serpium_sfp_protocol.h"

static uint64_t g_RequestId = 1;

static const wchar_t* RouteName(uint32_t route)
{
    if (route ==
        SERPIUM_SFP_API_ROUTE_DIRECT)
    {
        return L"DIRECT";
    }

    if (route ==
        SERPIUM_SFP_API_ROUTE_VPN)
    {
        return L"VPN";
    }

    return L"?";
}

static uint32_t ParseRoute(const std::wstring& value)
{
    if (_wcsicmp(
            value.c_str(),
            L"direct") == 0)
    {
        return
            SERPIUM_SFP_API_ROUTE_DIRECT;
    }

    if (_wcsicmp(
            value.c_str(),
            L"vpn") == 0)
    {
        return
            SERPIUM_SFP_API_ROUTE_VPN;
    }

    return 0;
}

static bool HasHardFlag(
    int argc,
    wchar_t** argv)
{
    for (int index = 1;
         index < argc;
         ++index)
    {
        if (_wcsicmp(
                argv[index],
                L"--hard") == 0)
        {
            return true;
        }
    }

    return false;
}

static bool ReadExact(
    HANDLE pipe,
    void* buffer,
    DWORD size)
{
    BYTE* cursor =
        static_cast<BYTE*>(
            buffer);

    DWORD total = 0;

    while (total < size)
    {
        DWORD read = 0;

        if (!ReadFile(
                pipe,
                cursor + total,
                size - total,
                &read,
                nullptr))
        {
            return false;
        }

        if (read == 0)
            return false;

        total += read;
    }

    return true;
}

static bool WriteExact(
    HANDLE pipe,
    const void* buffer,
    DWORD size)
{
    const BYTE* cursor =
        static_cast<const BYTE*>(
            buffer);

    DWORD total = 0;

    while (total < size)
    {
        DWORD written = 0;

        if (!WriteFile(
                pipe,
                cursor + total,
                size - total,
                &written,
                nullptr))
        {
            return false;
        }

        if (written == 0)
            return false;

        total += written;
    }

    return true;
}

static bool SendRequest(
    uint32_t command,
    uint32_t flags,
    const std::vector<BYTE>& payload,
    SERPIUM_SFP_API_RESPONSE_HEADER* response,
    std::vector<BYTE>* responsePayload)
{
    HANDLE pipe =
        CreateFileW(
            SERPIUM_SFP_API_PIPE_NAME,
            GENERIC_READ |
            GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr);

    if (pipe ==
        INVALID_HANDLE_VALUE)
    {
        std::wcerr
            << L"Cannot connect to SFP API. Win32="
            << GetLastError()
            << L"\n";

        return false;
    }

    SERPIUM_SFP_API_REQUEST_HEADER request = {};
    request.Magic =
        SERPIUM_SFP_API_MAGIC;
    request.Version =
        SERPIUM_SFP_API_VERSION;
    request.Command = command;
    request.Flags = flags;
    request.RequestId =
        g_RequestId++;
    request.PayloadBytes =
        static_cast<uint32_t>(
            payload.size());

    bool ok =
        WriteExact(
            pipe,
            &request,
            sizeof(request));

    if (ok &&
        !payload.empty())
    {
        ok =
            WriteExact(
                pipe,
                payload.data(),
                static_cast<DWORD>(
                    payload.size()));
    }

    if (ok)
    {
        ok =
            ReadExact(
                pipe,
                response,
                sizeof(*response));
    }

    if (ok &&
        response->Magic ==
            SERPIUM_SFP_API_MAGIC &&
        response->Version ==
            SERPIUM_SFP_API_VERSION &&
        response->PayloadBytes <=
            SERPIUM_SFP_API_MAX_PAYLOAD)
    {
        responsePayload->resize(
            response->PayloadBytes);

        if (!responsePayload->empty())
        {
            ok =
                ReadExact(
                    pipe,
                    responsePayload->data(),
                    static_cast<DWORD>(
                        responsePayload->size()));
        }
    }
    else if (ok)
    {
        ok = false;
    }

    CloseHandle(pipe);
    return ok;
}

static int CheckResult(
    const SERPIUM_SFP_API_RESPONSE_HEADER& response)
{
    if (response.Result ==
        SERPIUM_SFP_API_OK)
    {
        return 0;
    }

    std::wcerr
        << L"SFP API error="
        << response.Result
        << L" Win32="
        << response.Win32Error
        << L"\n";

    switch (response.Result)
    {
    case SERPIUM_SFP_API_E_POLICY_NOT_PERSISTED:
        std::wcerr << L"Policy applied, but not saved.\n";
        break;
    case SERPIUM_SFP_API_E_CUTOVER_INCOMPLETE:
        std::wcerr << L"Policy applied and saved, but flow cutover is incomplete.\n";
        break;
    case SERPIUM_SFP_API_E_PERSIST_AND_CUTOVER:
        std::wcerr << L"Policy applied, but not saved; flow cutover is incomplete.\n";
        break;
    case SERPIUM_SFP_API_E_ABORT_INCOMPLETE:
        std::wcerr << L"Flow abort is incomplete; no policy change requested.\n";
        break;
    }

    return
        static_cast<int>(
            response.Result);
}

static std::vector<BYTE> AppPathPayload(
    const std::wstring& path)
{
    size_t bytes =
        sizeof(
            SERPIUM_SFP_API_APP_PATH_REQUEST) +
        path.size() *
            sizeof(wchar_t);

    std::vector<BYTE> payload(
        bytes,
        0);

    auto* request =
        reinterpret_cast<
            SERPIUM_SFP_API_APP_PATH_REQUEST*>(
                payload.data());

    request->PathChars =
        static_cast<uint32_t>(
            path.size());

    memcpy(
        payload.data() +
            sizeof(*request),
        path.data(),
        path.size() *
            sizeof(wchar_t));

    return payload;
}

static std::vector<BYTE> AppRoutePayload(
    const std::wstring& path,
    uint32_t route)
{
    size_t bytes =
        sizeof(
            SERPIUM_SFP_API_APP_ROUTE_REQUEST) +
        path.size() *
            sizeof(wchar_t);

    std::vector<BYTE> payload(
        bytes,
        0);

    auto* request =
        reinterpret_cast<
            SERPIUM_SFP_API_APP_ROUTE_REQUEST*>(
                payload.data());

    request->Route = route;
    request->PathChars =
        static_cast<uint32_t>(
            path.size());

    memcpy(
        payload.data() +
            sizeof(*request),
        path.data(),
        path.size() *
            sizeof(wchar_t));

    return payload;
}

static int Status()
{
    SERPIUM_SFP_API_RESPONSE_HEADER response = {};
    std::vector<BYTE> payload;

    if (!SendRequest(
            SERPIUM_SFP_API_CMD_GET_STATUS,
            0,
            {},
            &response,
            &payload))
    {
        return 100;
    }

    int result =
        CheckResult(response);

    if (result != 0)
        return result;

    if (payload.size() !=
        sizeof(
            SERPIUM_SFP_API_STATUS))
    {
        return 101;
    }

    const auto* status =
        reinterpret_cast<
            const SERPIUM_SFP_API_STATUS*>(
                payload.data());

    std::wcout
        << L"api=0x"
        << std::hex
        << status->ApiVersion
        << L" kernel=0x"
        << status->KernelProtocolVersion
        << std::dec
        << L"\ngeneration="
        << status->PolicyGeneration
        << L"\ndefault="
        << RouteName(
            status->DefaultRoute)
        << L"\nrules="
        << status->PolicyCount
        << L"\nactiveFlows="
        << status->ActiveFlowCount
        << L"\nbridgeArmed="
        << status->BridgeArmed
        << L"\nredirected="
        << status->TotalRedirected
        << L" failOpen="
        << status->TotalRedirectFailOpen
        << L"\n";

    return 0;
}

static int Policy()
{
    SERPIUM_SFP_API_RESPONSE_HEADER response = {};
    std::vector<BYTE> payload;

    if (!SendRequest(
            SERPIUM_SFP_API_CMD_GET_POLICY,
            0,
            {},
            &response,
            &payload))
    {
        return 100;
    }

    int result =
        CheckResult(response);

    if (result != 0)
        return result;

    if (payload.size() <
        sizeof(
            SERPIUM_SFP_API_POLICY_HEADER))
    {
        return 101;
    }

    const auto* header =
        reinterpret_cast<
            const SERPIUM_SFP_API_POLICY_HEADER*>(
                payload.data());

    std::wcout
        << L"generation="
        << header->Generation
        << L" default="
        << RouteName(
            header->DefaultRoute)
        << L" entries="
        << header->EntryCount
        << L"\n";

    size_t offset =
        sizeof(*header);

    for (uint32_t index = 0;
         index < header->EntryCount;
         ++index)
    {
        if (offset +
            sizeof(
                SERPIUM_SFP_API_POLICY_ENTRY) >
            payload.size())
        {
            return 102;
        }

        const auto* entry =
            reinterpret_cast<
                const SERPIUM_SFP_API_POLICY_ENTRY*>(
                    payload.data() +
                    offset);

        offset += sizeof(*entry);

        size_t pathBytes =
            static_cast<size_t>(
                entry->PathChars) *
            sizeof(wchar_t);

        if (offset +
            pathBytes >
            payload.size())
        {
            return 103;
        }

        std::wstring path(
            reinterpret_cast<
                const wchar_t*>(
                    payload.data() +
                    offset),
            entry->PathChars);

        offset += pathBytes;

        std::wcout
            << L"0x"
            << std::hex
            << entry->AppIdHash
            << std::dec
            << L" "
            << RouteName(
                entry->Route)
            << L" "
            << path
            << L"\n";
    }

    return 0;
}

static int Flows()
{
    SERPIUM_SFP_API_RESPONSE_HEADER response = {};
    std::vector<BYTE> payload;

    if (!SendRequest(
            SERPIUM_SFP_API_CMD_GET_FLOWS,
            0,
            {},
            &response,
            &payload))
    {
        return 100;
    }

    int result =
        CheckResult(response);

    if (result != 0)
        return result;

    if (payload.size() <
        sizeof(
            SERPIUM_SFP_API_FLOWS_HEADER))
    {
        return 101;
    }

    const auto* header =
        reinterpret_cast<
            const SERPIUM_SFP_API_FLOWS_HEADER*>(
                payload.data());

    size_t expected =
        sizeof(*header) +
        static_cast<size_t>(
            header->Count) *
        sizeof(
            SERPIUM_SFP_FLOW_RECORD);

    if (expected !=
        payload.size())
    {
        return 102;
    }

    const auto* flows =
        reinterpret_cast<
            const SERPIUM_SFP_FLOW_RECORD*>(
                payload.data() +
                sizeof(*header));

    std::wcout
        << L"count="
        << header->Count
        << L" truncated="
        << header->Truncated
        << L"\n";

    for (uint32_t index = 0;
         index < header->Count;
         ++index)
    {
        std::wcout
            << L"flow="
            << flows[index].FlowId
            << L" pid="
            << flows[index].ProcessId
            << L" appHash=0x"
            << std::hex
            << flows[index].AppIdHash
            << std::dec
            << L" route="
            << RouteName(
                flows[index].Route)
            << L" gen="
            << flows[index].PolicyGeneration
            << L"\n";
    }

    return 0;
}

static int SimpleCommand(
    uint32_t command,
    uint32_t flags,
    const std::vector<BYTE>& payload)
{
    SERPIUM_SFP_API_RESPONSE_HEADER response = {};
    std::vector<BYTE> responsePayload;

    if (!SendRequest(
            command,
            flags,
            payload,
            &response,
            &responsePayload))
    {
        return 100;
    }

    return
        CheckResult(response);
}

static void Usage()
{
    std::wcerr
        << L"Serpium.SFP.Cli.exe commands:\n"
        << L"  status\n"
        << L"  policy\n"
        << L"  flows\n"
        << L"  set-default <direct|vpn> [--hard]\n"
        << L"  set-app <exe> <direct|vpn> [--hard]\n"
        << L"  remove-app <exe> [--hard]\n"
        << L"  abort-app <exe>\n"
        << L"  reset [--hard]\n";
}

int wmain(
    int argc,
    wchar_t** argv)
{
    if (argc < 2)
    {
        Usage();
        return 1;
    }

    std::wstring command =
        argv[1];

    uint32_t flags =
        HasHardFlag(
            argc,
            argv)
            ? SERPIUM_SFP_API_FLAG_HARD_CUTOVER
            : 0u;

    if (_wcsicmp(
            command.c_str(),
            L"status") == 0)
    {
        return Status();
    }

    if (_wcsicmp(
            command.c_str(),
            L"policy") == 0)
    {
        return Policy();
    }

    if (_wcsicmp(
            command.c_str(),
            L"flows") == 0)
    {
        return Flows();
    }

    if (_wcsicmp(
            command.c_str(),
            L"set-default") == 0)
    {
        if (argc < 3)
        {
            Usage();
            return 1;
        }

        uint32_t route =
            ParseRoute(
                argv[2]);

        if (route == 0)
            return 2;

        SERPIUM_SFP_API_SET_DEFAULT_REQUEST input = {};
        input.Route = route;

        std::vector<BYTE> payload(
            sizeof(input));

        memcpy(
            payload.data(),
            &input,
            sizeof(input));

        return
            SimpleCommand(
                SERPIUM_SFP_API_CMD_SET_DEFAULT,
                flags,
                payload);
    }

    if (_wcsicmp(
            command.c_str(),
            L"set-app") == 0)
    {
        if (argc < 4)
        {
            Usage();
            return 1;
        }

        uint32_t route =
            ParseRoute(
                argv[3]);

        if (route == 0)
            return 2;

        return
            SimpleCommand(
                SERPIUM_SFP_API_CMD_SET_APP_ROUTE,
                flags,
                AppRoutePayload(
                    argv[2],
                    route));
    }

    if (_wcsicmp(
            command.c_str(),
            L"remove-app") == 0)
    {
        if (argc < 3)
        {
            Usage();
            return 1;
        }

        return
            SimpleCommand(
                SERPIUM_SFP_API_CMD_REMOVE_APP,
                flags,
                AppPathPayload(
                    argv[2]));
    }

    if (_wcsicmp(
            command.c_str(),
            L"abort-app") == 0)
    {
        if (argc < 3)
        {
            Usage();
            return 1;
        }

        SERPIUM_SFP_API_RESPONSE_HEADER response = {};
        std::vector<BYTE> responsePayload;

        if (!SendRequest(
                SERPIUM_SFP_API_CMD_ABORT_APP,
                0,
                AppPathPayload(
                    argv[2]),
                &response,
                &responsePayload))
        {
            return 100;
        }

        int result =
            CheckResult(response);

        if (result != 0)
            return result;

        if (responsePayload.size() !=
            sizeof(
                SERPIUM_SFP_API_ABORT_RESPONSE))
        {
            return 101;
        }

        const auto* abort =
            reinterpret_cast<
                const SERPIUM_SFP_API_ABORT_RESPONSE*>(
                    responsePayload.data());

        std::wcout
            << L"matched="
            << abort->Matched
            << L" aborted="
            << abort->Aborted
            << L" failed="
            << abort->Failed
            << L"\n";

        return
            abort->Failed == 0
                ? 0
                : 3;
    }

    if (_wcsicmp(
            command.c_str(),
            L"reset") == 0)
    {
        return
            SimpleCommand(
                SERPIUM_SFP_API_CMD_RESET_POLICY,
                flags,
                {});
    }

    Usage();
    return 1;
}
