#define UNICODE
#define _UNICODE

#include <windows.h>
#include <winsvc.h>
#include <fwpmu.h>
#include <strsafe.h>

#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

#include "..\Serpium.Flow.Protocol\serpium_flow_protocol.h"
#include "bridge.h"

static const wchar_t* kServiceName = L"SerpiumFlowService";
static const wchar_t* kServiceDisplayName = L"Serpium Flow Service";

static SERVICE_STATUS_HANDLE g_ServiceStatusHandle = nullptr;
static SERVICE_STATUS g_ServiceStatus = {};
static HANDLE g_StopEvent = nullptr;

static std::wstring
GetProgramDataLogPath()
{
    wchar_t programData[MAX_PATH] = {};
    DWORD length = GetEnvironmentVariableW(
        L"ProgramData",
        programData,
        ARRAYSIZE(programData)
        );

    std::wstring root =
        length > 0 && length < ARRAYSIZE(programData)
            ? std::wstring(programData)
            : std::wstring(L"C:\\ProgramData");

    std::wstring directory = root + L"\\Serpium\\Flow";
    CreateDirectoryW((root + L"\\Serpium").c_str(), nullptr);
    CreateDirectoryW(directory.c_str(), nullptr);

    return directory + L"\\service.log";
}

static void
LogLine(
    const std::wstring& line
    )
{
    SYSTEMTIME time = {};
    GetLocalTime(&time);

    wchar_t prefix[96] = {};
    StringCchPrintfW(
        prefix,
        ARRAYSIZE(prefix),
        L"%04u-%02u-%02u %02u:%02u:%02u.%03u ",
        time.wYear,
        time.wMonth,
        time.wDay,
        time.wHour,
        time.wMinute,
        time.wSecond,
        time.wMilliseconds
        );

    std::wstring text = prefix + line + L"\r\n";
    std::wstring path = GetProgramDataLogPath();

    HANDLE file = CreateFileW(
        path.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
        );

    if (file == INVALID_HANDLE_VALUE)
    {
        return;
    }

    DWORD bytesWritten = 0;
    WriteFile(
        file,
        text.data(),
        static_cast<DWORD>(text.size() * sizeof(wchar_t)),
        &bytesWritten,
        nullptr
        );

    CloseHandle(file);
}

static bool
QueryDriverStatus(
    SERPIUM_FLOW_STATUS* status,
    DWORD* errorCode
    )
{
    if (status == nullptr)
    {
        if (errorCode != nullptr)
        {
            *errorCode = ERROR_INVALID_PARAMETER;
        }

        return false;
    }

    HANDLE device = CreateFileW(
        SERPIUM_FLOW_WIN32_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
        );

    if (device == INVALID_HANDLE_VALUE)
    {
        if (errorCode != nullptr)
        {
            *errorCode = GetLastError();
        }

        return false;
    }

    ZeroMemory(status, sizeof(*status));

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        device,
        IOCTL_SERPIUM_FLOW_GET_STATUS,
        nullptr,
        0,
        status,
        sizeof(*status),
        &bytesReturned,
        nullptr
        );

    DWORD localError = result ? ERROR_SUCCESS : GetLastError();
    CloseHandle(device);

    if (errorCode != nullptr)
    {
        *errorCode = localError;
    }

    return
        result &&
        bytesReturned >= sizeof(*status) &&
        status->Size == sizeof(*status) &&
        status->ProtocolVersion == SERPIUM_FLOW_PROTOCOL_VERSION;
}

static bool
PingDriver(
    unsigned long sequence,
    SERPIUM_FLOW_PING* pingResult,
    DWORD* errorCode
    )
{
    HANDLE device = CreateFileW(
        SERPIUM_FLOW_WIN32_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
        );

    if (device == INVALID_HANDLE_VALUE)
    {
        if (errorCode != nullptr)
        {
            *errorCode = GetLastError();
        }

        return false;
    }

    SERPIUM_FLOW_PING ping = {};
    ping.Size = sizeof(ping);
    ping.ProtocolVersion = SERPIUM_FLOW_PROTOCOL_VERSION;
    ping.Sequence = sequence;
    ping.ClientTimestamp = GetTickCount64();

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        device,
        IOCTL_SERPIUM_FLOW_PING,
        &ping,
        sizeof(ping),
        &ping,
        sizeof(ping),
        &bytesReturned,
        nullptr
        );

    DWORD localError = result ? ERROR_SUCCESS : GetLastError();
    CloseHandle(device);

    if (pingResult != nullptr)
    {
        *pingResult = ping;
    }

    if (errorCode != nullptr)
    {
        *errorCode = localError;
    }

    return result && bytesReturned >= sizeof(ping);
}

static const wchar_t*
GetRouteName(
    unsigned long route
    )
{
    switch (route)
    {
        case SERPIUM_FLOW_ROUTE_DIRECT:
            return L"DIRECT";

        case SERPIUM_FLOW_ROUTE_VPN:
            return L"VPN";

        default:
            return L"UNSPECIFIED";
    }
}

static std::wstring
GetAppNameFromId(
    const unsigned short* appId,
    unsigned long appIdByteLength
    )
{
    if (appId == nullptr || appIdByteLength == 0)
    {
        return L"<unavailable>";
    }

    size_t characterCount =
        appIdByteLength / sizeof(unsigned short);

    if (characterCount >= SERPIUM_FLOW_APP_ID_MAX_CHARS)
    {
        characterCount = SERPIUM_FLOW_APP_ID_MAX_CHARS - 1;
    }

    const wchar_t* characters =
        reinterpret_cast<const wchar_t*>(appId);
    std::wstring value(characters, characterCount);

    while (!value.empty() && value.back() == L'\0')
    {
        value.pop_back();
    }

    size_t separator = value.find_last_of(L"\\/");
    std::wstring name =
        separator == std::wstring::npos
            ? value
            : value.substr(separator + 1);

    if (name.empty())
    {
        name = L"<unnamed>";
    }

    for (wchar_t& character : name)
    {
        if (character < L' ' || character == 0x7f)
        {
            character = L'?';
        }
    }

    return name;
}

static std::wstring
GetObservationAppName(
    const SERPIUM_FLOW_OBSERVATION& observation
    )
{
    if (
        (observation.Flags &
         SERPIUM_FLOW_OBSERVATION_FLAG_APP_ID_PRESENT) == 0
        )
    {
        return L"<unavailable>";
    }

    return GetAppNameFromId(
        observation.AppId,
        observation.AppIdByteLength
        );
}

static std::wstring
FormatRemoteAddressBytes(
    const unsigned char* remoteAddress,
    bool ipv6
    )
{
    wchar_t address[96] = {};

    if (ipv6)
    {
        StringCchPrintfW(
            address,
            ARRAYSIZE(address),
            L"%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
            L"%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            remoteAddress[0],
            remoteAddress[1],
            remoteAddress[2],
            remoteAddress[3],
            remoteAddress[4],
            remoteAddress[5],
            remoteAddress[6],
            remoteAddress[7],
            remoteAddress[8],
            remoteAddress[9],
            remoteAddress[10],
            remoteAddress[11],
            remoteAddress[12],
            remoteAddress[13],
            remoteAddress[14],
            remoteAddress[15]
            );
    }
    else
    {
        StringCchPrintfW(
            address,
            ARRAYSIZE(address),
            L"%u.%u.%u.%u",
            remoteAddress[0],
            remoteAddress[1],
            remoteAddress[2],
            remoteAddress[3]
            );
    }

    return address;
}

static std::wstring
FormatRemoteAddress(
    const SERPIUM_FLOW_OBSERVATION& observation
    )
{
    return FormatRemoteAddressBytes(
        observation.RemoteAddress,
        (observation.Flags &
         SERPIUM_FLOW_OBSERVATION_FLAG_IPV6) != 0
        );
}

static std::wstring
FormatObservation(
    const SERPIUM_FLOW_OBSERVATION& observation
    )
{
    const wchar_t* protocol = L"OTHER";

    if (observation.Protocol == 6)
    {
        protocol = L"TCP";
    }
    else if (observation.Protocol == 17)
    {
        protocol = L"UDP";
    }

    std::wstring appName = GetObservationAppName(observation);
    std::wstring remoteAddress = FormatRemoteAddress(observation);
    wchar_t message[768] = {};

    StringCchPrintfW(
        message,
        ARRAYSIZE(message),
        L"Observe seq=%llu layer=ALE_CONNECT_V%lu pid=%llu "
        L"app=%s appIdPresent=%s localPort=%u remote=%s:%u protocol=%s(%u) "
        L"policyGeneration=%lu route=%s ruleId=%llu matched=%s redirected=%s failOpen=%s",
        observation.Sequence,
        observation.Layer,
        observation.ProcessId,
        appName.c_str(),
        (observation.Flags & SERPIUM_FLOW_OBSERVATION_FLAG_APP_ID_PRESENT)
            ? L"true"
            : L"false",
        observation.LocalPort,
        remoteAddress.c_str(),
        observation.RemotePort,
        protocol,
        observation.Protocol,
        observation.PolicyGeneration,
        GetRouteName(observation.Route),
        observation.RuleId,
        (observation.Flags &
         SERPIUM_FLOW_OBSERVATION_FLAG_POLICY_MATCH)
            ? L"true"
            : L"false",
        (observation.Flags &
         SERPIUM_FLOW_OBSERVATION_FLAG_ROUTE_REDIRECTED)
            ? L"true"
            : L"false",
        (observation.Flags &
         SERPIUM_FLOW_OBSERVATION_FLAG_ROUTE_FAIL_OPEN)
            ? L"true"
            : L"false"
        );

    return message;
}

static bool
DrainDriverObservations(
    bool writeLog,
    bool writeConsole,
    unsigned long long* drainedCount,
    DWORD* errorCode
    )
{
    HANDLE device = CreateFileW(
        SERPIUM_FLOW_WIN32_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
        );

    if (device == INVALID_HANDLE_VALUE)
    {
        if (errorCode != nullptr)
        {
            *errorCode = GetLastError();
        }

        return false;
    }

    auto batch = static_cast<PSERPIUM_FLOW_OBSERVATION_BATCH>(
        HeapAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            sizeof(SERPIUM_FLOW_OBSERVATION_BATCH)
            )
        );

    if (batch == nullptr)
    {
        CloseHandle(device);

        if (errorCode != nullptr)
        {
            *errorCode = ERROR_OUTOFMEMORY;
        }

        return false;
    }

    bool success = true;
    DWORD localError = ERROR_SUCCESS;
    unsigned long long totalDrained = 0;

    for (unsigned long pass = 0; pass < 16; pass++)
    {
        ZeroMemory(batch, sizeof(*batch));

        DWORD bytesReturned = 0;
        BOOL result = DeviceIoControl(
            device,
            IOCTL_SERPIUM_FLOW_DRAIN_OBSERVATIONS,
            nullptr,
            0,
            batch,
            sizeof(*batch),
            &bytesReturned,
            nullptr
            );

        if (!result)
        {
            success = false;
            localError = GetLastError();
            break;
        }

        if (
            bytesReturned <
                FIELD_OFFSET(SERPIUM_FLOW_OBSERVATION_BATCH, Events) ||
            batch->ProtocolVersion != SERPIUM_FLOW_PROTOCOL_VERSION ||
            batch->EventSize != sizeof(SERPIUM_FLOW_OBSERVATION) ||
            batch->EventCount > SERPIUM_FLOW_OBSERVATION_BATCH_MAX ||
            batch->Size > bytesReturned
            )
        {
            success = false;
            localError = ERROR_INVALID_DATA;
            break;
        }

        for (unsigned long index = 0; index < batch->EventCount; index++)
        {
            const SERPIUM_FLOW_OBSERVATION& observation =
                batch->Events[index];

            if (
                observation.Size != sizeof(SERPIUM_FLOW_OBSERVATION) ||
                observation.ProtocolVersion != SERPIUM_FLOW_PROTOCOL_VERSION
                )
            {
                success = false;
                localError = ERROR_INVALID_DATA;
                break;
            }

            std::wstring line = FormatObservation(observation);

            if (writeLog)
            {
                LogLine(line);
            }

            if (writeConsole)
            {
                std::wprintf(L"%s\n", line.c_str());
            }

            totalDrained++;
        }

        if (!success || batch->RemainingObservations == 0)
        {
            break;
        }
    }

    HeapFree(GetProcessHeap(), 0, batch);
    CloseHandle(device);

    if (drainedCount != nullptr)
    {
        *drainedCount = totalDrained;
    }

    if (errorCode != nullptr)
    {
        *errorCode = localError;
    }

    return success;
}

static unsigned long long
ComputeRuleId(
    const unsigned char* data,
    unsigned long byteLength
    )
{
    unsigned long long value = 14695981039346656037ull;

    for (unsigned long index = 0; index < byteLength; index++)
    {
        value ^= data[index];
        value *= 1099511628211ull;
    }

    return value == 0 ? 1ull : value;
}

static bool
ResolveApplicationRule(
    const wchar_t* fileName,
    unsigned long route,
    SERPIUM_FLOW_RULE_REQUEST* request,
    DWORD* errorCode
    )
{
    if (
        fileName == nullptr ||
        *fileName == L'\0' ||
        request == nullptr
        )
    {
        if (errorCode != nullptr)
        {
            *errorCode = ERROR_INVALID_PARAMETER;
        }

        return false;
    }

    std::vector<wchar_t> fullPath(32768);
    DWORD length = GetFullPathNameW(
        fileName,
        static_cast<DWORD>(fullPath.size()),
        fullPath.data(),
        nullptr
        );

    if (length == 0 || length >= fullPath.size())
    {
        if (errorCode != nullptr)
        {
            *errorCode = length == 0 ? GetLastError() : ERROR_BUFFER_OVERFLOW;
        }

        return false;
    }

    DWORD attributes = GetFileAttributesW(fullPath.data());

    if (
        attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0
        )
    {
        if (errorCode != nullptr)
        {
            *errorCode =
                attributes == INVALID_FILE_ATTRIBUTES
                    ? GetLastError()
                    : ERROR_FILE_NOT_FOUND;
        }

        return false;
    }

    FWP_BYTE_BLOB* appId = nullptr;
    DWORD result = FwpmGetAppIdFromFileName0(
        fullPath.data(),
        &appId
        );

    if (result != ERROR_SUCCESS)
    {
        if (errorCode != nullptr)
        {
            *errorCode = result;
        }

        return false;
    }

    bool valid =
        appId != nullptr &&
        appId->data != nullptr &&
        appId->size > 0 &&
        appId->size <= SERPIUM_FLOW_APP_ID_MAX_BYTES &&
        (appId->size & 1u) == 0;

    if (!valid)
    {
        FwpmFreeMemory0(reinterpret_cast<void**>(&appId));

        if (errorCode != nullptr)
        {
            *errorCode = ERROR_INVALID_DATA;
        }

        return false;
    }

    ZeroMemory(request, sizeof(*request));
    request->Size = sizeof(*request);
    request->ProtocolVersion = SERPIUM_FLOW_PROTOCOL_VERSION;
    request->Route = route;
    request->AppIdByteLength = appId->size;
    CopyMemory(
        request->AppId,
        appId->data,
        appId->size
        );
    request->RuleId = ComputeRuleId(
        appId->data,
        appId->size
        );

    FwpmFreeMemory0(reinterpret_cast<void**>(&appId));

    if (errorCode != nullptr)
    {
        *errorCode = ERROR_SUCCESS;
    }

    return true;
}

static bool
SendPolicyMutation(
    DWORD controlCode,
    const void* input,
    DWORD inputSize,
    SERPIUM_FLOW_MUTATION_RESULT* mutation,
    DWORD* errorCode
    )
{
    HANDLE device = CreateFileW(
        SERPIUM_FLOW_WIN32_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
        );

    if (device == INVALID_HANDLE_VALUE)
    {
        if (errorCode != nullptr)
        {
            *errorCode = GetLastError();
        }

        return false;
    }

    SERPIUM_FLOW_MUTATION_RESULT localMutation = {};
    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        device,
        controlCode,
        const_cast<void*>(input),
        inputSize,
        &localMutation,
        sizeof(localMutation),
        &bytesReturned,
        nullptr
        );

    DWORD localError = result ? ERROR_SUCCESS : GetLastError();
    CloseHandle(device);

    bool valid =
        result &&
        bytesReturned >= sizeof(localMutation) &&
        localMutation.Size == sizeof(localMutation) &&
        localMutation.ProtocolVersion == SERPIUM_FLOW_PROTOCOL_VERSION;

    if (valid && mutation != nullptr)
    {
        *mutation = localMutation;
    }

    if (errorCode != nullptr)
    {
        *errorCode = valid ? ERROR_SUCCESS :
            (localError == ERROR_SUCCESS ? ERROR_INVALID_DATA : localError);
    }

    return valid;
}

static void
PrintMutationResult(
    const wchar_t* marker,
    const SERPIUM_FLOW_MUTATION_RESULT& mutation
    )
{
    std::wprintf(
        L"%s\n"
        L"Changed: %s\n"
        L"Policy generation: %lu\n"
        L"Rules: %lu/%u\n"
        L"Observed flows: %lu/%u\n",
        marker,
        (mutation.Flags & SERPIUM_FLOW_MUTATION_FLAG_CHANGED)
            ? L"true"
            : L"false",
        mutation.PolicyGeneration,
        mutation.RuleCount,
        SERPIUM_FLOW_RULE_CAPACITY,
        mutation.FlowCount,
        SERPIUM_FLOW_FLOW_CAPACITY
        );
}

static int
AddApplicationRule(
    const wchar_t* routeText,
    const wchar_t* fileName
    )
{
    unsigned long route = SERPIUM_FLOW_ROUTE_UNSPECIFIED;

    if (_wcsicmp(routeText, L"vpn") == 0)
    {
        route = SERPIUM_FLOW_ROUTE_VPN;
    }
    else if (_wcsicmp(routeText, L"direct") == 0)
    {
        route = SERPIUM_FLOW_ROUTE_DIRECT;
    }
    else
    {
        std::fwprintf(stderr, L"Route must be VPN or DIRECT.\n");
        return 1;
    }

    SERPIUM_FLOW_RULE_REQUEST request = {};
    DWORD errorCode = ERROR_SUCCESS;

    if (!ResolveApplicationRule(
            fileName,
            route,
            &request,
            &errorCode
            ))
    {
        std::fwprintf(
            stderr,
            L"Application AppId resolution failed. Win32/WFP error=%lu\n",
            errorCode
            );
        return 2;
    }

    SERPIUM_FLOW_MUTATION_RESULT mutation = {};

    if (!SendPolicyMutation(
            IOCTL_SERPIUM_FLOW_ADD_RULE,
            &request,
            sizeof(request),
            &mutation,
            &errorCode
            ))
    {
        std::fwprintf(
            stderr,
            L"ADD_RULE failed. Win32 error=%lu\n",
            errorCode
            );
        return 2;
    }

    std::wprintf(
        L"Rule id: %llu\nRoute intent: %s\nApplication: %s\n",
        request.RuleId,
        GetRouteName(request.Route),
        GetAppNameFromId(request.AppId, request.AppIdByteLength).c_str()
        );
    PrintMutationResult(L"SERPIUM_WFP4A_ADD_RULE_PASS", mutation);
    return 0;
}

static int
RemoveApplicationRule(
    const wchar_t* fileName
    )
{
    SERPIUM_FLOW_RULE_REQUEST resolved = {};
    DWORD errorCode = ERROR_SUCCESS;

    if (!ResolveApplicationRule(
            fileName,
            SERPIUM_FLOW_ROUTE_UNSPECIFIED,
            &resolved,
            &errorCode
            ))
    {
        std::fwprintf(
            stderr,
            L"Application AppId resolution failed. Win32/WFP error=%lu\n",
            errorCode
            );
        return 2;
    }

    SERPIUM_FLOW_REMOVE_RULE_REQUEST request = {};
    request.Size = sizeof(request);
    request.ProtocolVersion = SERPIUM_FLOW_PROTOCOL_VERSION;
    request.RuleId = resolved.RuleId;

    SERPIUM_FLOW_MUTATION_RESULT mutation = {};

    if (!SendPolicyMutation(
            IOCTL_SERPIUM_FLOW_REMOVE_RULE,
            &request,
            sizeof(request),
            &mutation,
            &errorCode
            ))
    {
        std::fwprintf(
            stderr,
            L"REMOVE_RULE failed. Win32 error=%lu\n",
            errorCode
            );
        return 2;
    }

    std::wprintf(
        L"Rule id: %llu\nApplication: %s\n",
        request.RuleId,
        GetAppNameFromId(resolved.AppId, resolved.AppIdByteLength).c_str()
        );
    PrintMutationResult(L"SERPIUM_WFP4A_REMOVE_RULE_PASS", mutation);
    return 0;
}

static int
ClearApplicationRules()
{
    SERPIUM_FLOW_MUTATION_RESULT mutation = {};
    DWORD errorCode = ERROR_SUCCESS;

    if (!SendPolicyMutation(
            IOCTL_SERPIUM_FLOW_CLEAR_RULES,
            nullptr,
            0,
            &mutation,
            &errorCode
            ))
    {
        std::fwprintf(
            stderr,
            L"CLEAR_RULES failed. Win32 error=%lu\n",
            errorCode
            );
        return 2;
    }

    PrintMutationResult(L"SERPIUM_WFP4A_CLEAR_RULES_PASS", mutation);
    return 0;
}

static int
SyncVpnApplicationRules(
    int applicationCount,
    wchar_t** applicationPaths
    )
{
    if (
        applicationCount < 0 ||
        applicationCount > static_cast<int>(SERPIUM_FLOW_RULE_CAPACITY)
        )
    {
        std::fwprintf(
            stderr,
            L"Application count must be 0..%u.\n",
            SERPIUM_FLOW_RULE_CAPACITY
            );
        return 1;
    }

    auto request = static_cast<PSERPIUM_FLOW_REPLACE_RULES_REQUEST>(
        HeapAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            sizeof(SERPIUM_FLOW_REPLACE_RULES_REQUEST)
            )
        );

    if (request == nullptr)
    {
        std::fwprintf(stderr, L"Rule batch allocation failed.\n");
        return 2;
    }

    request->Size = sizeof(*request);
    request->ProtocolVersion = SERPIUM_FLOW_PROTOCOL_VERSION;

    DWORD errorCode = ERROR_SUCCESS;
    unsigned long uniqueCount = 0;
    int exitCode = 2;

    for (int index = 0; index < applicationCount; index++)
    {
        SERPIUM_FLOW_RULE_REQUEST resolved = {};

        if (!ResolveApplicationRule(
                applicationPaths[index],
                SERPIUM_FLOW_ROUTE_VPN,
                &resolved,
                &errorCode
                ))
        {
            std::fwprintf(
                stderr,
                L"Application AppId resolution failed. Win32/WFP error=%lu\n",
                errorCode
                );
            goto Cleanup;
        }

        bool duplicate = false;

        for (unsigned long existing = 0; existing < uniqueCount; existing++)
        {
            const SERPIUM_FLOW_RULE_ENTRY& current =
                request->Rules[existing];

            if (
                current.RuleId == resolved.RuleId ||
                (
                    current.AppIdByteLength == resolved.AppIdByteLength &&
                    current.AppIdByteLength > 0 &&
                    std::memcmp(
                        current.AppId,
                        resolved.AppId,
                        current.AppIdByteLength
                        ) == 0
                )
                )
            {
                duplicate = true;
                break;
            }
        }

        if (duplicate)
        {
            continue;
        }

        SERPIUM_FLOW_RULE_ENTRY& entry = request->Rules[uniqueCount];
        entry.Size = sizeof(entry);
        entry.ProtocolVersion = SERPIUM_FLOW_PROTOCOL_VERSION;
        entry.RuleId = resolved.RuleId;
        entry.Route = SERPIUM_FLOW_ROUTE_VPN;
        entry.AppIdByteLength = resolved.AppIdByteLength;
        std::memcpy(
            entry.AppId,
            resolved.AppId,
            resolved.AppIdByteLength
            );

        uniqueCount++;
    }

    request->RuleCount = uniqueCount;

    {
        SERPIUM_FLOW_MUTATION_RESULT mutation = {};

        if (!SendPolicyMutation(
                IOCTL_SERPIUM_FLOW_REPLACE_RULES,
                request,
                sizeof(*request),
                &mutation,
                &errorCode
                ))
        {
            std::fwprintf(
                stderr,
                L"REPLACE_RULES failed. Win32 error=%lu\n",
                errorCode
                );
            goto Cleanup;
        }

        std::wprintf(
            L"SERPIUM_WFP4A_SYNC_RULES_PASS\n"
            L"Applications: %lu\n",
            uniqueCount
            );
        PrintMutationResult(
            L"SERPIUM_WFP4A_SYNC_RULES_RESULT",
            mutation
            );
        exitCode = 0;
    }

Cleanup:
    SecureZeroMemory(
        request,
        sizeof(*request)
        );
    HeapFree(
        GetProcessHeap(),
        0,
        request
        );
    return exitCode;
}

static int
ListApplicationRules()
{
    HANDLE device = CreateFileW(
        SERPIUM_FLOW_WIN32_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
        );

    if (device == INVALID_HANDLE_VALUE)
    {
        std::fwprintf(
            stderr,
            L"Driver open failed. Win32 error=%lu\n",
            GetLastError()
            );
        return 2;
    }

    auto batch = static_cast<PSERPIUM_FLOW_RULE_BATCH>(
        HeapAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            sizeof(SERPIUM_FLOW_RULE_BATCH)
            )
        );

    if (batch == nullptr)
    {
        CloseHandle(device);
        return 2;
    }

    unsigned long startIndex = 0;
    unsigned long totalPrinted = 0;
    unsigned long generation = 0;
    int exitCode = 0;

    while (true)
    {
        SERPIUM_FLOW_ENUM_REQUEST request = {};
        request.Size = sizeof(request);
        request.ProtocolVersion = SERPIUM_FLOW_PROTOCOL_VERSION;
        request.StartIndex = startIndex;
        ZeroMemory(batch, sizeof(*batch));

        DWORD bytesReturned = 0;
        BOOL result = DeviceIoControl(
            device,
            IOCTL_SERPIUM_FLOW_ENUM_RULES,
            &request,
            sizeof(request),
            batch,
            sizeof(*batch),
            &bytesReturned,
            nullptr
            );

        if (
            !result ||
            bytesReturned < FIELD_OFFSET(SERPIUM_FLOW_RULE_BATCH, Entries) ||
            batch->ProtocolVersion != SERPIUM_FLOW_PROTOCOL_VERSION ||
            batch->EntrySize != sizeof(SERPIUM_FLOW_RULE_ENTRY) ||
            batch->EntryCount > SERPIUM_FLOW_RULE_BATCH_MAX ||
            batch->Size > bytesReturned
            )
        {
            std::fwprintf(
                stderr,
                L"Rule enumeration failed. Win32 error=%lu\n",
                result ? ERROR_INVALID_DATA : GetLastError()
                );
            exitCode = 2;
            break;
        }

        generation = batch->PolicyGeneration;

        for (unsigned long index = 0; index < batch->EntryCount; index++)
        {
            const SERPIUM_FLOW_RULE_ENTRY& rule = batch->Entries[index];

            if (
                rule.Size != sizeof(rule) ||
                rule.ProtocolVersion != SERPIUM_FLOW_PROTOCOL_VERSION ||
                rule.RuleId == 0 ||
                (rule.Route != SERPIUM_FLOW_ROUTE_DIRECT &&
                 rule.Route != SERPIUM_FLOW_ROUTE_VPN) ||
                rule.AppIdByteLength == 0 ||
                rule.AppIdByteLength > SERPIUM_FLOW_APP_ID_MAX_BYTES ||
                (rule.AppIdByteLength & 1u) != 0
                )
            {
                std::fwprintf(stderr, L"Invalid rule entry returned by driver.\n");
                exitCode = 2;
                break;
            }

            std::wprintf(
                L"Rule id=%llu route=%s app=%s\n",
                rule.RuleId,
                GetRouteName(rule.Route),
                GetAppNameFromId(rule.AppId, rule.AppIdByteLength).c_str()
                );
            totalPrinted++;
        }

        if (exitCode != 0)
        {
            break;
        }

        if (batch->NextIndex >= batch->TotalCount)
        {
            break;
        }

        if (batch->NextIndex <= startIndex)
        {
            std::fwprintf(stderr, L"Rule enumeration did not advance.\n");
            exitCode = 2;
            break;
        }

        startIndex = batch->NextIndex;
    }

    HeapFree(GetProcessHeap(), 0, batch);
    CloseHandle(device);

    if (exitCode == 0)
    {
        std::wprintf(
            L"SERPIUM_WFP4A_LIST_RULES_PASS\n"
            L"Policy generation: %lu\n"
            L"Rules listed: %lu\n",
            generation,
            totalPrinted
            );
    }

    return exitCode;
}

static int
ListObservedFlows()
{
    HANDLE device = CreateFileW(
        SERPIUM_FLOW_WIN32_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
        );

    if (device == INVALID_HANDLE_VALUE)
    {
        std::fwprintf(
            stderr,
            L"Driver open failed. Win32 error=%lu\n",
            GetLastError()
            );
        return 2;
    }

    auto batch = static_cast<PSERPIUM_FLOW_FLOW_BATCH>(
        HeapAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            sizeof(SERPIUM_FLOW_FLOW_BATCH)
            )
        );

    if (batch == nullptr)
    {
        CloseHandle(device);
        return 2;
    }

    unsigned long startIndex = 0;
    unsigned long totalPrinted = 0;
    int exitCode = 0;

    while (true)
    {
        SERPIUM_FLOW_ENUM_REQUEST request = {};
        request.Size = sizeof(request);
        request.ProtocolVersion = SERPIUM_FLOW_PROTOCOL_VERSION;
        request.StartIndex = startIndex;
        ZeroMemory(batch, sizeof(*batch));

        DWORD bytesReturned = 0;
        BOOL result = DeviceIoControl(
            device,
            IOCTL_SERPIUM_FLOW_ENUM_FLOWS,
            &request,
            sizeof(request),
            batch,
            sizeof(*batch),
            &bytesReturned,
            nullptr
            );

        if (
            !result ||
            bytesReturned < FIELD_OFFSET(SERPIUM_FLOW_FLOW_BATCH, Entries) ||
            batch->ProtocolVersion != SERPIUM_FLOW_PROTOCOL_VERSION ||
            batch->EntrySize != sizeof(SERPIUM_FLOW_FLOW_ENTRY) ||
            batch->EntryCount > SERPIUM_FLOW_FLOW_BATCH_MAX ||
            batch->Size > bytesReturned
            )
        {
            std::fwprintf(
                stderr,
                L"Flow enumeration failed. Win32 error=%lu\n",
                result ? ERROR_INVALID_DATA : GetLastError()
                );
            exitCode = 2;
            break;
        }

        for (unsigned long index = 0; index < batch->EntryCount; index++)
        {
            const SERPIUM_FLOW_FLOW_ENTRY& flow = batch->Entries[index];

            if (
                flow.Size != sizeof(flow) ||
                flow.ProtocolVersion != SERPIUM_FLOW_PROTOCOL_VERSION ||
                flow.AppIdByteLength > SERPIUM_FLOW_APP_ID_MAX_BYTES ||
                (flow.AppIdByteLength & 1u) != 0 ||
                flow.Route > SERPIUM_FLOW_ROUTE_VPN
                )
            {
                std::fwprintf(stderr, L"Invalid flow entry returned by driver.\n");
                exitCode = 2;
                break;
            }

            std::wstring address = FormatRemoteAddressBytes(
                flow.RemoteAddress,
                (flow.Flags & SERPIUM_FLOW_OBSERVATION_FLAG_IPV6) != 0
                );
            std::wprintf(
                L"Flow id=%llu pid=%llu app=%s localPort=%u remote=%s:%u "
                L"protocol=%u route=%s ruleId=%llu generation=%lu seen=%llu\n",
                flow.FlowId,
                flow.ProcessId,
                GetAppNameFromId(flow.AppId, flow.AppIdByteLength).c_str(),
                flow.LocalPort,
                address.c_str(),
                flow.RemotePort,
                flow.Protocol,
                GetRouteName(flow.Route),
                flow.RuleId,
                flow.PolicyGeneration,
                flow.ObservationCount
                );
            totalPrinted++;
        }

        if (exitCode != 0)
        {
            break;
        }

        if (batch->NextIndex >= batch->TotalCount)
        {
            break;
        }

        if (batch->NextIndex <= startIndex)
        {
            std::fwprintf(stderr, L"Flow enumeration did not advance.\n");
            exitCode = 2;
            break;
        }

        startIndex = batch->NextIndex;
    }

    HeapFree(GetProcessHeap(), 0, batch);
    CloseHandle(device);

    if (exitCode == 0)
    {
        std::wprintf(
            L"SERPIUM_WFP4A_LIST_FLOWS_PASS\n"
            L"Flows listed: %lu\n",
            totalPrinted
            );
    }

    return exitCode;
}

static void
SetServiceState(
    DWORD state,
    DWORD win32ExitCode,
    DWORD waitHint
    )
{
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = state;
    g_ServiceStatus.dwWin32ExitCode = win32ExitCode;
    g_ServiceStatus.dwWaitHint = waitHint;

    g_ServiceStatus.dwControlsAccepted =
        state == SERVICE_START_PENDING
            ? 0
            : SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

    if (g_ServiceStatusHandle != nullptr)
    {
        SetServiceStatus(
            g_ServiceStatusHandle,
            &g_ServiceStatus
            );
    }
}

static DWORD WINAPI
ServiceControlHandler(
    DWORD control,
    DWORD eventType,
    LPVOID eventData,
    LPVOID context
    )
{
    UNREFERENCED_PARAMETER(eventType);
    UNREFERENCED_PARAMETER(eventData);
    UNREFERENCED_PARAMETER(context);

    switch (control)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
        {
            SetServiceState(
                SERVICE_STOP_PENDING,
                ERROR_SUCCESS,
                3000
                );

            if (g_StopEvent != nullptr)
            {
                SetEvent(g_StopEvent);
            }

            return NO_ERROR;
        }

        default:
        {
            return NO_ERROR;
        }
    }
}

static void WINAPI
ServiceMain(
    DWORD argumentCount,
    wchar_t** arguments
    )
{
    UNREFERENCED_PARAMETER(argumentCount);
    UNREFERENCED_PARAMETER(arguments);

    g_ServiceStatusHandle = RegisterServiceCtrlHandlerExW(
        kServiceName,
        ServiceControlHandler,
        nullptr
        );

    if (g_ServiceStatusHandle == nullptr)
    {
        return;
    }

    SetServiceState(
        SERVICE_START_PENDING,
        ERROR_SUCCESS,
        3000
        );

    g_StopEvent = CreateEventW(
        nullptr,
        TRUE,
        FALSE,
        nullptr
        );

    if (g_StopEvent == nullptr)
    {
        SetServiceState(
            SERVICE_STOPPED,
            GetLastError(),
            0
            );

        return;
    }

    LogLine(L"Service started.");
    SetServiceState(
        SERVICE_RUNNING,
        ERROR_SUCCESS,
        0
        );

    unsigned long sequence = 1;

    while (WaitForSingleObject(g_StopEvent, 3000) == WAIT_TIMEOUT)
    {
        SERPIUM_FLOW_PING ping = {};
        DWORD errorCode = ERROR_SUCCESS;
        unsigned long long drainedCount = 0;

        if (!DrainDriverObservations(
                true,
                false,
                &drainedCount,
                &errorCode
                ))
        {
            wchar_t message[256] = {};
            StringCchPrintfW(
                message,
                ARRAYSIZE(message),
                L"Observation drain failed. Win32 error=%lu",
                errorCode
                );

            LogLine(message);
        }

        if (PingDriver(sequence++, &ping, &errorCode))
        {
            wchar_t message[256] = {};
            StringCchPrintfW(
                message,
                ARRAYSIZE(message),
                L"Driver ping OK. sequence=%lu uptime=%llu ms",
                ping.Sequence,
                ping.DriverTimestamp
                );

            LogLine(message);
        }
        else
        {
            wchar_t message[256] = {};
            StringCchPrintfW(
                message,
                ARRAYSIZE(message),
                L"Driver ping failed. Win32 error=%lu",
                errorCode
                );

            LogLine(message);
        }
    }

    LogLine(L"Service stopped.");

    CloseHandle(g_StopEvent);
    g_StopEvent = nullptr;

    SetServiceState(
        SERVICE_STOPPED,
        ERROR_SUCCESS,
        0
        );
}

static bool
InstallService()
{
    wchar_t modulePath[MAX_PATH] = {};

    if (GetModuleFileNameW(
            nullptr,
            modulePath,
            ARRAYSIZE(modulePath)
            ) == 0)
    {
        std::fwprintf(stderr, L"GetModuleFileName failed: %lu\n", GetLastError());
        return false;
    }

    SC_HANDLE manager = OpenSCManagerW(
        nullptr,
        nullptr,
        SC_MANAGER_CREATE_SERVICE
        );

    if (manager == nullptr)
    {
        std::fwprintf(stderr, L"OpenSCManager failed: %lu\n", GetLastError());
        return false;
    }

    std::wstring quotedPath = L"\"" + std::wstring(modulePath) + L"\"";

    SC_HANDLE service = CreateServiceW(
        manager,
        kServiceName,
        kServiceDisplayName,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        quotedPath.c_str(),
        nullptr,
        nullptr,
        nullptr,
        L"LocalSystem",
        nullptr
        );

    if (service == nullptr)
    {
        DWORD errorCode = GetLastError();

        if (errorCode != ERROR_SERVICE_EXISTS)
        {
            std::fwprintf(stderr, L"CreateService failed: %lu\n", errorCode);
            CloseServiceHandle(manager);
            return false;
        }

        service = OpenServiceW(
            manager,
            kServiceName,
            SERVICE_ALL_ACCESS
            );
    }

    if (service == nullptr)
    {
        std::fwprintf(stderr, L"OpenService failed: %lu\n", GetLastError());
        CloseServiceHandle(manager);
        return false;
    }

    SERVICE_DESCRIPTIONW description = {};
    description.lpDescription =
        const_cast<wchar_t*>(
            L"Serpium WFP-4A guarded TCP/UDP route service and transparent SOCKS5 bridge."
            );

    ChangeServiceConfig2W(
        service,
        SERVICE_CONFIG_DESCRIPTION,
        &description
        );

    std::wprintf(L"Service installed: %s\n", kServiceName);

    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return true;
}

static bool
ControlServiceState(
    bool start
    )
{
    SC_HANDLE manager = OpenSCManagerW(
        nullptr,
        nullptr,
        SC_MANAGER_CONNECT
        );

    if (manager == nullptr)
    {
        std::fwprintf(stderr, L"OpenSCManager failed: %lu\n", GetLastError());
        return false;
    }

    SC_HANDLE service = OpenServiceW(
        manager,
        kServiceName,
        SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS
        );

    if (service == nullptr)
    {
        std::fwprintf(stderr, L"OpenService failed: %lu\n", GetLastError());
        CloseServiceHandle(manager);
        return false;
    }

    bool result = false;

    if (start)
    {
        if (StartServiceW(service, 0, nullptr))
        {
            result = true;
        }
        else
        {
            DWORD errorCode = GetLastError();
            result = errorCode == ERROR_SERVICE_ALREADY_RUNNING;

            if (!result)
            {
                std::fwprintf(stderr, L"StartService failed: %lu\n", errorCode);
            }
        }
    }
    else
    {
        SERVICE_STATUS status = {};

        if (ControlService(
                service,
                SERVICE_CONTROL_STOP,
                &status
                ))
        {
            result = true;
        }
        else
        {
            DWORD errorCode = GetLastError();
            result = errorCode == ERROR_SERVICE_NOT_ACTIVE;

            if (!result)
            {
                std::fwprintf(stderr, L"ControlService failed: %lu\n", errorCode);
            }
        }
    }

    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return result;
}

static bool
UninstallService()
{
    SC_HANDLE manager = OpenSCManagerW(
        nullptr,
        nullptr,
        SC_MANAGER_CONNECT
        );

    if (manager == nullptr)
    {
        std::fwprintf(stderr, L"OpenSCManager failed: %lu\n", GetLastError());
        return false;
    }

    SC_HANDLE service = OpenServiceW(
        manager,
        kServiceName,
        DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS
        );

    if (service == nullptr)
    {
        DWORD errorCode = GetLastError();
        CloseServiceHandle(manager);

        if (errorCode == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            return true;
        }

        std::fwprintf(stderr, L"OpenService failed: %lu\n", errorCode);
        return false;
    }

    SERVICE_STATUS status = {};
    ControlService(
        service,
        SERVICE_CONTROL_STOP,
        &status
        );

    bool result = DeleteService(service) != FALSE;

    if (!result && GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE)
    {
        result = true;
    }

    if (result)
    {
        std::wprintf(L"Service removed: %s\n", kServiceName);
    }

    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return result;
}

static int
PrintDriverStatus()
{
    SERPIUM_FLOW_STATUS status = {};
    DWORD errorCode = ERROR_SUCCESS;

    if (!QueryDriverStatus(&status, &errorCode))
    {
        std::fwprintf(
            stderr,
            L"Driver status query failed. Win32 error=%lu\n",
            errorCode
            );

        return 2;
    }

    const unsigned long requiredFlags =
        SERPIUM_FLOW_STATUS_FLAG_DRIVER_READY |
        SERPIUM_FLOW_STATUS_FLAG_CONTROL_DEVICE |
        SERPIUM_FLOW_STATUS_FLAG_CALLOUTS_REGISTERED |
        SERPIUM_FLOW_STATUS_FLAG_FILTERS_ACTIVE |
        SERPIUM_FLOW_STATUS_FLAG_EVENT_QUEUE |
        SERPIUM_FLOW_STATUS_FLAG_FAIL_OPEN |
        SERPIUM_FLOW_STATUS_FLAG_POLICY_TRANSPORT |
        SERPIUM_FLOW_STATUS_FLAG_ROUTE_ENFORCEMENT_AVAILABLE |
        SERPIUM_FLOW_STATUS_FLAG_TCP_CONNECT_REDIRECT |
        SERPIUM_FLOW_STATUS_FLAG_UDP_CONNECT_REDIRECT |
        SERPIUM_FLOW_STATUS_FLAG_APP_RULE_TABLE |
        SERPIUM_FLOW_STATUS_FLAG_FLOW_TABLE;

    bool routeStateValid =
        (status.Flags &
         SERPIUM_FLOW_STATUS_FLAG_ROUTE_ENFORCEMENT_DISABLED) != 0 ||
        (status.Flags &
         (SERPIUM_FLOW_STATUS_FLAG_ROUTE_ENFORCEMENT_ARMED |
          SERPIUM_FLOW_STATUS_FLAG_ROUTE_LEASE_ACTIVE)) ==
            (SERPIUM_FLOW_STATUS_FLAG_ROUTE_ENFORCEMENT_ARMED |
             SERPIUM_FLOW_STATUS_FLAG_ROUTE_LEASE_ACTIVE);

    if (
        (status.Flags & requiredFlags) != requiredFlags ||
        (status.Flags & SERPIUM_FLOW_STATUS_FLAG_WFP_DISABLED) != 0 ||
        !routeStateValid ||
        status.CalloutIdV4 == 0 ||
        status.CalloutIdV6 == 0 ||
        status.RedirectCalloutIdV4 == 0 ||
        status.RedirectCalloutIdV6 == 0
        )
    {
        std::fwprintf(
            stderr,
            L"Driver is not in the complete WFP-4A TCP/UDP route state. Flags=0x%08lX\n",
            status.Flags
            );

        return 3;
    }

    std::wprintf(
        L"SERPIUM_WFP4A_ROUTE_CORE_READY\n"
        L"SERPIUM_WFP4A_UDP_APP_ROUTING_READY\n"
        L"Protocol: 0x%08lX\n"
        L"Driver: %lu.%lu.%lu\n"
        L"Flags: 0x%08lX\n"
        L"Uptime: %llu ms\n"
        L"Total observed: %llu\n"
        L"Queued: %lu/%lu\n"
        L"Dropped: %llu\n"
        L"Callout V4: %lu\n"
        L"Callout V6: %lu\n"
        L"Redirect callout V4: %lu\n"
        L"Redirect callout V6: %lu\n"
        L"Policy generation: %lu\n"
        L"Rules: %lu/%lu\n"
        L"Observed flows: %lu/%lu\n"
        L"Policy matches: %llu\n"
        L"Policy misses: %llu\n"
        L"Route config generation: %lu\n"
        L"Route lease remaining: %lu ms\n"
        L"Redirected: %llu\n"
        L"Redirect failures: %llu\n"
        L"Route fail-open: %llu\n"
        L"Route enforcement: %s\n",
        status.ProtocolVersion,
        status.DriverVersionMajor,
        status.DriverVersionMinor,
        status.DriverVersionPatch,
        status.Flags,
        status.UptimeMilliseconds,
        status.TotalObserved,
        status.QueuedObservations,
        status.QueueCapacity,
        status.DroppedObservations,
        status.CalloutIdV4,
        status.CalloutIdV6,
        status.RedirectCalloutIdV4,
        status.RedirectCalloutIdV6,
        status.PolicyGeneration,
        status.RuleCount,
        status.RuleCapacity,
        status.FlowCount,
        status.FlowCapacity,
        status.TotalPolicyMatches,
        status.TotalPolicyMisses,
        status.RouteConfigGeneration,
        status.RouteLeaseRemainingMilliseconds,
        status.TotalRedirected,
        status.TotalRedirectFailures,
        status.TotalRouteFailOpen,
        (status.Flags & SERPIUM_FLOW_STATUS_FLAG_ROUTE_ENFORCEMENT_ARMED)
            ? L"armed"
            : L"disarmed"
        );

    if ((status.Flags & SERPIUM_FLOW_STATUS_FLAG_DATAGRAM_DATA_CORE) != 0)
    {
        std::wprintf(L"SERPIUM_WFP4A_DATAGRAM_DATA_CORE_READY\n");
    }

    if ((status.Flags & SERPIUM_FLOW_STATUS_FLAG_QUIC_TCP_FALLBACK) != 0)
    {
        std::wprintf(L"SERPIUM_WFP4A_QUIC_TCP_FALLBACK_READY\n");
    }

    return 0;
}

static int
PrintPing()
{
    SERPIUM_FLOW_PING ping = {};
    DWORD errorCode = ERROR_SUCCESS;

    if (!PingDriver(1, &ping, &errorCode))
    {
        std::fwprintf(
            stderr,
            L"Driver ping failed. Win32 error=%lu\n",
            errorCode
            );

        return 2;
    }

    std::wprintf(
        L"SERPIUM_WFP4A_PING_PASS\n"
        L"Sequence: %lu\n"
        L"Driver uptime: %llu ms\n",
        ping.Sequence,
        ping.DriverTimestamp
        );

    return 0;
}

static int
PrintObservations(
    unsigned long durationSeconds
    )
{
    ULONGLONG deadline =
        GetTickCount64() +
        (static_cast<ULONGLONG>(durationSeconds) * 1000);
    unsigned long long totalDrained = 0;

    do
    {
        unsigned long long drained = 0;
        DWORD errorCode = ERROR_SUCCESS;

        if (!DrainDriverObservations(
                false,
                true,
                &drained,
                &errorCode
                ))
        {
            std::fwprintf(
                stderr,
                L"Observation drain failed. Win32 error=%lu\n",
                errorCode
                );

            return 2;
        }

        totalDrained += drained;

        if (GetTickCount64() >= deadline)
        {
            break;
        }

        Sleep(250);
    }
    while (true);

    SERPIUM_FLOW_STATUS status = {};
    DWORD errorCode = ERROR_SUCCESS;

    if (!QueryDriverStatus(&status, &errorCode))
    {
        std::fwprintf(
            stderr,
            L"Driver status query failed after observation. Win32 error=%lu\n",
            errorCode
            );

        return 2;
    }

    if (totalDrained == 0 && status.TotalObserved == 0)
    {
        std::fwprintf(
            stderr,
            L"SERPIUM_WFP4A_OBSERVE_NO_EVENTS\n"
            );

        return 3;
    }

    std::wprintf(
        L"SERPIUM_WFP4A_OBSERVE_PASS\n"
        L"Drained this command: %llu\n"
        L"Driver total observed: %llu\n"
        L"Driver dropped: %llu\n",
        totalDrained,
        status.TotalObserved,
        status.DroppedObservations
        );

    return 0;
}

int wmain(
    int argc,
    wchar_t** argv
    )
{
    if (argc > 1)
    {
        std::wstring command = argv[1];

        if (command == L"install")
        {
            return InstallService() ? 0 : 1;
        }

        if (command == L"uninstall")
        {
            return UninstallService() ? 0 : 1;
        }

        if (command == L"start")
        {
            return ControlServiceState(true) ? 0 : 1;
        }

        if (command == L"stop")
        {
            return ControlServiceState(false) ? 0 : 1;
        }

        if (command == L"status")
        {
            return PrintDriverStatus();
        }

        if (command == L"ping")
        {
            return PrintPing();
        }

        if (command == L"observe")
        {
            unsigned long durationSeconds = 5;

            if (argc > 2)
            {
                wchar_t* end = nullptr;
                unsigned long parsed = std::wcstoul(argv[2], &end, 10);

                if (
                    end == argv[2] ||
                    *end != L'\0' ||
                    parsed == 0 ||
                    parsed > 60
                    )
                {
                    std::fwprintf(
                        stderr,
                        L"Observe duration must be 1..60 seconds.\n"
                        );

                    return 1;
                }

                durationSeconds = parsed;
            }

            return PrintObservations(durationSeconds);
        }

        if (command == L"bridge")
        {
            return RunTcpRouteBridgeCommand(
                argc - 2,
                argv + 2
                );
        }

        if (command == L"bridge-domain")
        {
            return RunTcpDomainRouteBridgeCommand(
                argc - 2,
                argv + 2
                );
        }

        if (command == L"disarm-route")
        {
            if (argc != 2)
            {
                std::fwprintf(
                    stderr,
                    L"Usage: Serpium.Flow.Service.exe disarm-route\n"
                    );
                return 1;
            }

            return DisarmTcpRouteCommand();
        }

        if (command == L"sync-vpn-rules")
        {
            if (
                argc - 2 >
                    static_cast<int>(SERPIUM_FLOW_RULE_CAPACITY)
                )
            {
                std::fwprintf(
                    stderr,
                    L"Usage: Serpium.Flow.Service.exe sync-vpn-rules [absolute-exe-path ...]\n"
                    );
                return 1;
            }

            return SyncVpnApplicationRules(
                argc - 2,
                argv + 2
                );
        }

        if (command == L"add-rule")
        {
            if (argc != 4)
            {
                std::fwprintf(
                    stderr,
                    L"Usage: Serpium.Flow.Service.exe add-rule <VPN|DIRECT> <absolute-exe-path>\n"
                    );
                return 1;
            }

            return AddApplicationRule(argv[2], argv[3]);
        }

        if (command == L"remove-rule")
        {
            if (argc != 3)
            {
                std::fwprintf(
                    stderr,
                    L"Usage: Serpium.Flow.Service.exe remove-rule <absolute-exe-path>\n"
                    );
                return 1;
            }

            return RemoveApplicationRule(argv[2]);
        }

        if (command == L"clear-rules")
        {
            return ClearApplicationRules();
        }

        if (command == L"list-rules")
        {
            return ListApplicationRules();
        }

        if (command == L"list-flows")
        {
            return ListObservedFlows();
        }

        std::fwprintf(
            stderr,
            L"Usage: Serpium.Flow.Service.exe [install|uninstall|start|stop|status|ping|observe [seconds]|bridge <local-socks5-port> <backend-pid> [backend-pid ...]|bridge-domain <local-socks5-port> <backend-pid> [backend-pid ...]|disarm-route|sync-vpn-rules [absolute-exe-path ...]|add-rule <VPN|DIRECT> <absolute-exe-path>|remove-rule <absolute-exe-path>|clear-rules|list-rules|list-flows]\n"
            );

        return 1;
    }

    SERVICE_TABLE_ENTRYW dispatchTable[] =
    {
        {
            const_cast<wchar_t*>(kServiceName),
            ServiceMain
        },
        {
            nullptr,
            nullptr
        }
    };

    if (!StartServiceCtrlDispatcherW(dispatchTable))
    {
        DWORD errorCode = GetLastError();

        if (errorCode == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
        {
            return PrintDriverStatus();
        }

        std::fwprintf(
            stderr,
            L"StartServiceCtrlDispatcher failed: %lu\n",
            errorCode
            );

        return 1;
    }

    return 0;
}
