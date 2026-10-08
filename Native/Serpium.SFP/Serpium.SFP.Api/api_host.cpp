#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsvc.h>
#include <sddl.h>
#include <fwpmu.h>

#include <algorithm>
#include <cstdint>
#include <cwchar>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "serpium_sfp_api_protocol.h"
#include "..\Serpium.SFP.Protocol\serpium_sfp_protocol.h"

static const wchar_t* kServiceName = L"SerpiumSfpApi";
static const uint32_t kStateMagic = 0x31535053u;
static const uint32_t kStateVersion = 1u;

struct PolicyEntry
{
    uint64_t Hash = 0;
    uint32_t Route = SERPIUM_SFP_ROUTE_DIRECT;
    std::wstring Path;
};

struct PolicyState
{
    uint64_t Generation = 0;
    uint32_t DefaultRoute = SERPIUM_SFP_ROUTE_DIRECT;
    std::map<uint64_t, PolicyEntry> Entries;
};

#pragma pack(push, 1)
struct StateFileHeader
{
    uint32_t Magic;
    uint32_t Version;
    uint64_t Generation;
    uint32_t DefaultRoute;
    uint32_t Count;
};

struct StateFileEntry
{
    uint64_t Hash;
    uint32_t Route;
    uint32_t PathChars;
};
#pragma pack(pop)

static std::mutex g_StateLock;
// Serialize the complete read/apply/save/cutover operation across clients.
static std::mutex g_MutationLock;
static PolicyState g_State;
static HANDLE g_StopEvent = nullptr;
static SERVICE_STATUS_HANDLE g_ServiceStatusHandle = nullptr;
static SERVICE_STATUS g_ServiceStatus = {};

static bool ReadExact(HANDLE pipe, void* buffer, DWORD size)
{
    BYTE* cursor = static_cast<BYTE*>(buffer);
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

static bool WriteExact(HANDLE pipe, const void* buffer, DWORD size)
{
    const BYTE* cursor = static_cast<const BYTE*>(buffer);
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

static bool IsValidRoute(uint32_t route)
{
    return
        route == SERPIUM_SFP_ROUTE_DIRECT ||
        route == SERPIUM_SFP_ROUTE_VPN;
}

static std::wstring ProgramDataStatePath()
{
    wchar_t root[MAX_PATH] = {};

    DWORD count =
        GetEnvironmentVariableW(
            L"ProgramData",
            root,
            static_cast<DWORD>(std::size(root)));

    if (count == 0 ||
        count >= std::size(root))
    {
        return L"";
    }

    std::wstring serpium =
        std::wstring(root) +
        L"\\Serpium";

    std::wstring directory =
        serpium +
        L"\\SFP";

    CreateDirectoryW(
        serpium.c_str(),
        nullptr);

    CreateDirectoryW(
        directory.c_str(),
        nullptr);

    return directory +
        L"\\policy.state";
}

static bool SaveStateLocked(DWORD* error = nullptr)
{
    // C++ streams do not guarantee a meaningful GetLastError() value.
    if (error != nullptr)
        *error = ERROR_WRITE_FAULT;
    std::wstring target =
        ProgramDataStatePath();

    if (target.empty())
        return false;

    std::wstring temp =
        target + L".tmp";

    std::ofstream stream(
        temp.c_str(),
        std::ios::binary |
        std::ios::trunc);

    if (!stream)
        return false;

    StateFileHeader header = {};
    header.Magic = kStateMagic;
    header.Version = kStateVersion;
    header.Generation =
        g_State.Generation;
    header.DefaultRoute =
        g_State.DefaultRoute;
    header.Count =
        static_cast<uint32_t>(
            g_State.Entries.size());

    stream.write(
        reinterpret_cast<const char*>(
            &header),
        sizeof(header));

    for (const auto& pair :
         g_State.Entries)
    {
        const PolicyEntry& item =
            pair.second;

        StateFileEntry entry = {};
        entry.Hash = item.Hash;
        entry.Route = item.Route;
        entry.PathChars =
            static_cast<uint32_t>(
                item.Path.size());

        stream.write(
            reinterpret_cast<const char*>(
                &entry),
            sizeof(entry));

        if (!item.Path.empty())
        {
            stream.write(
                reinterpret_cast<const char*>(
                    item.Path.data()),
                item.Path.size() *
                    sizeof(wchar_t));
        }
    }

    stream.flush();

    if (!stream.good())
    {
        stream.close();
        DeleteFileW(
            temp.c_str());

        return false;
    }

    stream.close();

    BOOL moved = MoveFileExW(
            temp.c_str(),
            target.c_str(),
            MOVEFILE_REPLACE_EXISTING |
            MOVEFILE_WRITE_THROUGH);

    DWORD moveError = moved ? ERROR_SUCCESS : GetLastError();
    if (!moved)
        DeleteFileW(temp.c_str());
    if (error != nullptr)
        *error = moveError;
    return moved != FALSE;
}

static void LoadState()
{
    std::lock_guard<std::mutex> guard(
        g_StateLock);

    g_State = PolicyState{};

    std::wstring path =
        ProgramDataStatePath();

    if (path.empty())
        return;

    std::ifstream stream(
        path.c_str(),
        std::ios::binary);

    if (!stream)
        return;

    StateFileHeader header = {};

    stream.read(
        reinterpret_cast<char*>(
            &header),
        sizeof(header));

    if (!stream ||
        header.Magic != kStateMagic ||
        header.Version != kStateVersion ||
        !IsValidRoute(
            header.DefaultRoute) ||
        header.Count >
            SERPIUM_SFP_MAX_POLICY_ENTRIES)
    {
        g_State = PolicyState{};
        return;
    }

    PolicyState loaded;
    loaded.Generation =
        header.Generation;
    loaded.DefaultRoute =
        header.DefaultRoute;

    for (uint32_t index = 0;
         index < header.Count;
         ++index)
    {
        StateFileEntry disk = {};

        stream.read(
            reinterpret_cast<char*>(
                &disk),
            sizeof(disk));

        if (!stream ||
            disk.Hash == 0 ||
            !IsValidRoute(disk.Route) ||
            disk.PathChars > 32768)
        {
            g_State = PolicyState{};
            return;
        }

        std::wstring value;
        value.resize(
            disk.PathChars);

        if (disk.PathChars > 0)
        {
            stream.read(
                reinterpret_cast<char*>(
                    value.data()),
                disk.PathChars *
                    sizeof(wchar_t));

            if (!stream)
            {
                g_State = PolicyState{};
                return;
            }
        }

        PolicyEntry item;
        item.Hash = disk.Hash;
        item.Route = disk.Route;
        item.Path = std::move(value);

        loaded.Entries[item.Hash] =
            std::move(item);
    }

    g_State = std::move(loaded);
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

static bool QueryKernelStatus(
    SERPIUM_SFP_STATUS* status,
    DWORD* error)
{
    HANDLE device = OpenKernel();

    if (device ==
        INVALID_HANDLE_VALUE)
    {
        if (error != nullptr)
            *error = GetLastError();

        return false;
    }

    DWORD returned = 0;

    BOOL ok =
        DeviceIoControl(
            device,
            IOCTL_SERPIUM_SFP_GET_STATUS,
            nullptr,
            0,
            status,
            sizeof(*status),
            &returned,
            nullptr);

    DWORD localError =
        ok ? ERROR_SUCCESS :
        GetLastError();

    CloseHandle(device);

    if (!ok)
    {
        if (error != nullptr)
            *error = localError;

        return false;
    }

    if (status->ProtocolVersion !=
        SERPIUM_SFP_PROTOCOL_VERSION)
    {
        if (error != nullptr)
            *error =
                ERROR_REVISION_MISMATCH;

        return false;
    }

    if (error != nullptr)
        *error = ERROR_SUCCESS;

    return true;
}

static uint64_t HashAppPath(
    const std::wstring& path,
    DWORD* error)
{
    FWP_BYTE_BLOB* appId = nullptr;

    DWORD result =
        FwpmGetAppIdFromFileName0(
            path.c_str(),
            &appId);

    if (result != ERROR_SUCCESS ||
        appId == nullptr ||
        appId->data == nullptr ||
        appId->size == 0)
    {
        if (error != nullptr)
        {
            *error =
                result != ERROR_SUCCESS
                    ? result
                    : ERROR_INVALID_DATA;
        }

        if (appId != nullptr)
        {
            FwpmFreeMemory0(
                reinterpret_cast<void**>(
                    &appId));
        }

        return 0;
    }

    uint64_t hash =
        14695981039346656037ull;

    for (UINT32 index = 0;
         index < appId->size;
         ++index)
    {
        hash ^= appId->data[index];
        hash *= 1099511628211ull;
    }

    FwpmFreeMemory0(
        reinterpret_cast<void**>(
            &appId));

    if (error != nullptr)
        *error = ERROR_SUCCESS;

    return hash;
}

static bool ApplyPolicy(
    const PolicyState& state,
    DWORD* error)
{
    size_t bytes =
        FIELD_OFFSET(
            SERPIUM_SFP_POLICY_REPLACE_REQUEST,
            Entries) +
        state.Entries.size() *
            sizeof(
                SERPIUM_SFP_POLICY_ENTRY);

    std::vector<BYTE> buffer(
        bytes,
        0);

    auto* request =
        reinterpret_cast<
            SERPIUM_SFP_POLICY_REPLACE_REQUEST*>(
                buffer.data());

    request->Size =
        static_cast<ULONG>(bytes);
    request->ProtocolVersion =
        SERPIUM_SFP_PROTOCOL_VERSION;
    request->Generation =
        state.Generation;
    request->DefaultRoute =
        state.DefaultRoute;
    request->EntryCount =
        static_cast<ULONG>(
            state.Entries.size());

    size_t index = 0;

    for (const auto& pair :
         state.Entries)
    {
        request->Entries[index].AppIdHash =
            pair.second.Hash;
        request->Entries[index].Route =
            pair.second.Route;

        ++index;
    }

    HANDLE device = OpenKernel();

    if (device ==
        INVALID_HANDLE_VALUE)
    {
        if (error != nullptr)
            *error = GetLastError();

        return false;
    }

    DWORD returned = 0;

    BOOL ok =
        DeviceIoControl(
            device,
            IOCTL_SERPIUM_SFP_REPLACE_POLICY,
            request,
            static_cast<DWORD>(
                bytes),
            nullptr,
            0,
            &returned,
            nullptr);

    DWORD localError =
        ok ? ERROR_SUCCESS :
        GetLastError();

    CloseHandle(device);

    if (error != nullptr)
        *error = localError;

    return ok != FALSE;
}

static bool AbortHash(
    uint64_t hash,
    uint64_t keepGeneration,
    SERPIUM_SFP_ABORT_STALE_RESPONSE* response,
    DWORD* error)
{
    HANDLE device = OpenKernel();

    if (device ==
        INVALID_HANDLE_VALUE)
    {
        if (error != nullptr)
            *error = GetLastError();

        return false;
    }

    SERPIUM_SFP_ABORT_STALE_REQUEST request = {};
    request.Size =
        sizeof(request);
    request.ProtocolVersion =
        SERPIUM_SFP_PROTOCOL_VERSION;
    request.AppIdHash = hash;
    request.KeepGeneration =
        keepGeneration;

    DWORD returned = 0;

    BOOL ok =
        DeviceIoControl(
            device,
            IOCTL_SERPIUM_SFP_ABORT_STALE,
            &request,
            sizeof(request),
            response,
            sizeof(*response),
            &returned,
            nullptr);

    DWORD localError =
        ok ? ERROR_SUCCESS :
        GetLastError();

    CloseHandle(device);

    if (ok)
    {
        if (returned < sizeof(*response) ||
            response->Size < sizeof(*response) ||
            response->ProtocolVersion != SERPIUM_SFP_PROTOCOL_VERSION)
        {
            ok = FALSE;
            localError = ERROR_INVALID_DATA;
        }
        else if (response->Failed != 0 || response->Aborted != response->Matched)
        {
            ok = FALSE;
            localError = ERROR_PARTIAL_COPY;
        }
        else if (response->Matched >= SERPIUM_SFP_MAX_ABORT_SNAPSHOT)
        {
            // The frozen ABI cannot tell whether a full snapshot omitted flows.
            ok = FALSE;
            localError = ERROR_MORE_DATA;
        }
    }

    if (error != nullptr)
        *error = localError;

    return ok != FALSE;
}

static bool QueryFlows(
    std::vector<SERPIUM_SFP_FLOW_RECORD>* flows,
    bool* truncated,
    DWORD* error)
{
    constexpr DWORD kBufferSize =
        1024 * 1024;

    std::vector<BYTE> buffer(
        kBufferSize,
        0);

    HANDLE device = OpenKernel();

    if (device ==
        INVALID_HANDLE_VALUE)
    {
        if (error != nullptr)
            *error = GetLastError();

        return false;
    }

    DWORD returned = 0;

    BOOL ok =
        DeviceIoControl(
            device,
            IOCTL_SERPIUM_SFP_QUERY_FLOWS,
            nullptr,
            0,
            buffer.data(),
            static_cast<DWORD>(
                buffer.size()),
            &returned,
            nullptr);

    DWORD localError =
        ok ? ERROR_SUCCESS :
        GetLastError();

    CloseHandle(device);

    if (!ok)
    {
        if (error != nullptr)
            *error = localError;

        return false;
    }

    if (returned <
        FIELD_OFFSET(
            SERPIUM_SFP_FLOW_QUERY_RESPONSE,
            Flows))
    {
        if (error != nullptr)
            *error = ERROR_INVALID_DATA;

        return false;
    }

    auto* response =
        reinterpret_cast<
            SERPIUM_SFP_FLOW_QUERY_RESPONSE*>(
                buffer.data());

    const size_t headerBytes = FIELD_OFFSET(SERPIUM_SFP_FLOW_QUERY_RESPONSE, Flows);
    if (returned > buffer.size() ||
        response->ProtocolVersion != SERPIUM_SFP_PROTOCOL_VERSION ||
        response->ReturnedFlowCount > (returned - headerBytes) / sizeof(SERPIUM_SFP_FLOW_RECORD))
    {
        if (error != nullptr)
            *error = ERROR_INVALID_DATA;
        return false;
    }

    flows->assign(
        response->Flows,
        response->Flows +
            response->ReturnedFlowCount);

    if (truncated != nullptr)
    {
        *truncated =
            response->Truncated != 0;
    }

    if (error != nullptr)
        *error = ERROR_SUCCESS;

    return true;
}

static bool AbortAllActiveApps(
    uint64_t generation,
    DWORD* error)
{
    std::vector<
        SERPIUM_SFP_FLOW_RECORD> flows;

    bool truncated = false;

    if (!QueryFlows(
            &flows,
            &truncated,
            error))
    {
        return false;
    }

    std::set<uint64_t> hashes;

    for (const auto& flow :
         flows)
    {
        if (flow.AppIdHash != 0)
            hashes.insert(
                flow.AppIdHash);
    }

    DWORD firstError = truncated ? ERROR_MORE_DATA : ERROR_SUCCESS;
    for (uint64_t hash :
         hashes)
    {
        SERPIUM_SFP_ABORT_STALE_RESPONSE response = {};

        DWORD abortError = ERROR_SUCCESS;
        if (!AbortHash(
            hash,
            generation,
            &response,
            &abortError) && firstError == ERROR_SUCCESS)
        {
            firstError = abortError;
        }
    }

    if (error != nullptr)
        *error = firstError;
    return firstError == ERROR_SUCCESS;
}

static void SynchronizeSavedStateToKernel()
{
    std::lock_guard<std::mutex> mutationGuard(g_MutationLock);
    PolicyState candidate;

    {
        std::lock_guard<std::mutex> guard(
            g_StateLock);

        candidate = g_State;
    }

    SERPIUM_SFP_STATUS kernel = {};

    if (!QueryKernelStatus(
            &kernel,
            nullptr))
    {
        return;
    }

    candidate.Generation =
        std::max<uint64_t>(
            candidate.Generation,
            kernel.PolicyGeneration) + 1;

    if (!ApplyPolicy(
            candidate,
            nullptr))
    {
        return;
    }

    {
        std::lock_guard<std::mutex> guard(
            g_StateLock);

        g_State = candidate;
        DWORD error = ERROR_SUCCESS;
        if (!SaveStateLocked(&error))
        {
            std::wcerr << L"SFP startup policy applied but not persisted. Win32="
                       << error << L"\n";
        }
    }
}

static uint32_t KernelErrorToApi(
    DWORD error)
{
    if (error == ERROR_FILE_NOT_FOUND ||
        error == ERROR_PATH_NOT_FOUND ||
        error == ERROR_INVALID_HANDLE ||
        error == ERROR_SERVICE_NOT_ACTIVE)
    {
        return
            SERPIUM_SFP_API_E_KERNEL_OFFLINE;
    }

    return
        SERPIUM_SFP_API_E_KERNEL_REJECTED;
}

// Called while g_MutationLock is held. Once ApplyPolicy succeeds, keep the
// accepted state even if persistence/cutover fails, and report partial success.
static uint32_t CommitPolicy(
    const PolicyState& candidate,
    uint32_t flags,
    uint64_t appHash,
    DWORD* error)
{
    if (!ApplyPolicy(candidate, error))
        return KernelErrorToApi(*error);

    DWORD persistenceError = ERROR_SUCCESS;
    bool persisted;
    {
        std::lock_guard<std::mutex> guard(g_StateLock);
        g_State = candidate;
        persisted = SaveStateLocked(&persistenceError);
    }

    DWORD cutoverError = ERROR_SUCCESS;
    bool cutoverComplete = true;
    if ((flags & SERPIUM_SFP_API_FLAG_HARD_CUTOVER) != 0)
    {
        // A failed disk write must not skip the requested cutover attempt.
        if (appHash != 0)
        {
            SERPIUM_SFP_ABORT_STALE_RESPONSE response = {};
            cutoverComplete = AbortHash(appHash, candidate.Generation, &response, &cutoverError);
        }
        else
        {
            cutoverComplete = AbortAllActiveApps(candidate.Generation, &cutoverError);
        }
    }

    *error = !persisted ? persistenceError : cutoverError;
    if (!persisted && !cutoverComplete)
        return SERPIUM_SFP_API_E_PERSIST_AND_CUTOVER;
    if (!persisted)
        return SERPIUM_SFP_API_E_POLICY_NOT_PERSISTED;
    if (!cutoverComplete)
        return SERPIUM_SFP_API_E_CUTOVER_INCOMPLETE;
    return SERPIUM_SFP_API_OK;
}

static bool ExtractUtf16Path(
    const std::vector<BYTE>& payload,
    size_t prefixBytes,
    uint32_t pathChars,
    std::wstring* path)
{
    size_t expected =
        prefixBytes +
        static_cast<size_t>(
            pathChars) *
            sizeof(wchar_t);

    if (pathChars == 0 ||
        pathChars > 32768 ||
        expected != payload.size())
    {
        return false;
    }

    path->assign(
        reinterpret_cast<
            const wchar_t*>(
                payload.data() +
                prefixBytes),
        pathChars);

    return true;
}

static std::vector<BYTE> BuildPolicyPayload(
    const PolicyState& state)
{
    size_t bytes =
        sizeof(
            SERPIUM_SFP_API_POLICY_HEADER);

    for (const auto& pair :
         state.Entries)
    {
        bytes +=
            sizeof(
                SERPIUM_SFP_API_POLICY_ENTRY) +
            pair.second.Path.size() *
                sizeof(wchar_t);
    }

    std::vector<BYTE> payload(
        bytes,
        0);

    auto* header =
        reinterpret_cast<
            SERPIUM_SFP_API_POLICY_HEADER*>(
                payload.data());

    header->Generation =
        state.Generation;
    header->DefaultRoute =
        state.DefaultRoute;
    header->EntryCount =
        static_cast<uint32_t>(
            state.Entries.size());

    size_t offset =
        sizeof(*header);

    for (const auto& pair :
         state.Entries)
    {
        const PolicyEntry& item =
            pair.second;

        auto* entry =
            reinterpret_cast<
                SERPIUM_SFP_API_POLICY_ENTRY*>(
                    payload.data() +
                    offset);

        entry->AppIdHash =
            item.Hash;
        entry->Route =
            item.Route;
        entry->PathChars =
            static_cast<uint32_t>(
                item.Path.size());

        offset += sizeof(*entry);

        if (!item.Path.empty())
        {
            memcpy(
                payload.data() +
                    offset,
                item.Path.data(),
                item.Path.size() *
                    sizeof(wchar_t));

            offset +=
                item.Path.size() *
                sizeof(wchar_t);
        }
    }

    return payload;
}

static uint32_t HandleRequest(
    const SERPIUM_SFP_API_REQUEST_HEADER& request,
    const std::vector<BYTE>& payload,
    std::vector<BYTE>* responsePayload,
    DWORD* win32Error)
{
    *win32Error = ERROR_SUCCESS;
    responsePayload->clear();

    std::unique_lock<std::mutex> mutationGuard(g_MutationLock, std::defer_lock);
    if (request.Command == SERPIUM_SFP_API_CMD_SET_DEFAULT ||
        request.Command == SERPIUM_SFP_API_CMD_SET_APP_ROUTE ||
        request.Command == SERPIUM_SFP_API_CMD_REMOVE_APP ||
        request.Command == SERPIUM_SFP_API_CMD_RESET_POLICY ||
        request.Command == SERPIUM_SFP_API_CMD_ABORT_APP)
    {
        mutationGuard.lock();
    }

    if (request.Command ==
        SERPIUM_SFP_API_CMD_PING)
    {
        static const char pong[] =
            "PONG";

        responsePayload->assign(
            pong,
            pong + sizeof(pong) - 1);

        return SERPIUM_SFP_API_OK;
    }

    if (request.Command ==
        SERPIUM_SFP_API_CMD_GET_STATUS)
    {
        SERPIUM_SFP_STATUS kernel = {};
        DWORD error = ERROR_SUCCESS;

        if (!QueryKernelStatus(
                &kernel,
                &error))
        {
            *win32Error = error;
            return
                KernelErrorToApi(error);
        }

        SERPIUM_SFP_API_STATUS api = {};
        api.ApiVersion =
            SERPIUM_SFP_API_VERSION;
        api.KernelProtocolVersion =
            kernel.ProtocolVersion;
        api.PolicyGeneration =
            kernel.PolicyGeneration;
        api.DefaultRoute =
            kernel.DefaultRoute;
        api.PolicyCount =
            kernel.PolicyCount;
        api.ActiveFlowCount =
            kernel.ActiveFlowCount;
        api.BridgeArmed =
            kernel.BridgeArmed;
        api.BridgeProcessId =
            kernel.BridgeProcessId;
        api.TotalRedirected =
            kernel.TotalRedirected;
        api.TotalRedirectFailOpen =
            kernel.TotalRedirectFailOpen;

        responsePayload->resize(
            sizeof(api));

        memcpy(
            responsePayload->data(),
            &api,
            sizeof(api));

        return SERPIUM_SFP_API_OK;
    }

    if (request.Command ==
        SERPIUM_SFP_API_CMD_GET_POLICY)
    {
        std::lock_guard<std::mutex> guard(
            g_StateLock);

        *responsePayload =
            BuildPolicyPayload(
                g_State);

        return SERPIUM_SFP_API_OK;
    }

    if (request.Command ==
        SERPIUM_SFP_API_CMD_GET_FLOWS)
    {
        std::vector<
            SERPIUM_SFP_FLOW_RECORD> flows;

        bool truncated = false;
        DWORD error = ERROR_SUCCESS;

        if (!QueryFlows(
                &flows,
                &truncated,
                &error))
        {
            *win32Error = error;
            return
                KernelErrorToApi(error);
        }

        size_t bytes =
            sizeof(
                SERPIUM_SFP_API_FLOWS_HEADER) +
            flows.size() *
                sizeof(
                    SERPIUM_SFP_FLOW_RECORD);

        responsePayload->resize(
            bytes,
            0);

        auto* header =
            reinterpret_cast<
                SERPIUM_SFP_API_FLOWS_HEADER*>(
                    responsePayload->data());

        header->Count =
            static_cast<uint32_t>(
                flows.size());
        header->Truncated =
            truncated ? 1u : 0u;

        if (!flows.empty())
        {
            memcpy(
                responsePayload->data() +
                    sizeof(*header),
                flows.data(),
                flows.size() *
                    sizeof(
                        SERPIUM_SFP_FLOW_RECORD));
        }

        return SERPIUM_SFP_API_OK;
    }

    if (request.Command ==
        SERPIUM_SFP_API_CMD_SET_DEFAULT)
    {
        if (payload.size() !=
            sizeof(
                SERPIUM_SFP_API_SET_DEFAULT_REQUEST))
        {
            return
                SERPIUM_SFP_API_E_INVALID;
        }

        const auto* input =
            reinterpret_cast<
                const SERPIUM_SFP_API_SET_DEFAULT_REQUEST*>(
                    payload.data());

        if (!IsValidRoute(
                input->Route))
        {
            return
                SERPIUM_SFP_API_E_INVALID;
        }

        PolicyState candidate;

        {
            std::lock_guard<std::mutex> guard(
                g_StateLock);

            candidate = g_State;
        }

        SERPIUM_SFP_STATUS kernel = {};
        DWORD error = ERROR_SUCCESS;

        if (!QueryKernelStatus(
                &kernel,
                &error))
        {
            *win32Error = error;
            return
                KernelErrorToApi(error);
        }

        candidate.Generation =
            std::max<uint64_t>(
                candidate.Generation,
                kernel.PolicyGeneration) + 1;

        candidate.DefaultRoute =
            input->Route;

        return CommitPolicy(candidate, request.Flags, 0, win32Error);
    }

    if (request.Command ==
        SERPIUM_SFP_API_CMD_SET_APP_ROUTE)
    {
        if (payload.size() <
            sizeof(
                SERPIUM_SFP_API_APP_ROUTE_REQUEST))
        {
            return
                SERPIUM_SFP_API_E_INVALID;
        }

        const auto* input =
            reinterpret_cast<
                const SERPIUM_SFP_API_APP_ROUTE_REQUEST*>(
                    payload.data());

        if (!IsValidRoute(
                input->Route))
        {
            return
                SERPIUM_SFP_API_E_INVALID;
        }

        std::wstring path;

        if (!ExtractUtf16Path(
                payload,
                sizeof(*input),
                input->PathChars,
                &path))
        {
            return
                SERPIUM_SFP_API_E_INVALID;
        }

        DWORD error = ERROR_SUCCESS;

        uint64_t hash =
            HashAppPath(
                path,
                &error);

        if (hash == 0)
        {
            *win32Error = error;
            return
                SERPIUM_SFP_API_E_INVALID;
        }

        PolicyState candidate;

        {
            std::lock_guard<std::mutex> guard(
                g_StateLock);

            candidate = g_State;
        }

        SERPIUM_SFP_STATUS kernel = {};

        if (!QueryKernelStatus(
                &kernel,
                &error))
        {
            *win32Error = error;
            return
                KernelErrorToApi(error);
        }

        candidate.Generation =
            std::max<uint64_t>(
                candidate.Generation,
                kernel.PolicyGeneration) + 1;

        PolicyEntry entry;
        entry.Hash = hash;
        entry.Route = input->Route;
        entry.Path = path;

        candidate.Entries[hash] =
            std::move(entry);

        if (candidate.Entries.size() >
            SERPIUM_SFP_MAX_POLICY_ENTRIES)
        {
            return
                SERPIUM_SFP_API_E_TOO_LARGE;
        }

        return CommitPolicy(candidate, request.Flags, hash, win32Error);
    }

    if (request.Command ==
            SERPIUM_SFP_API_CMD_REMOVE_APP ||
        request.Command ==
            SERPIUM_SFP_API_CMD_ABORT_APP)
    {
        if (payload.size() <
            sizeof(
                SERPIUM_SFP_API_APP_PATH_REQUEST))
        {
            return
                SERPIUM_SFP_API_E_INVALID;
        }

        const auto* input =
            reinterpret_cast<
                const SERPIUM_SFP_API_APP_PATH_REQUEST*>(
                    payload.data());

        std::wstring path;

        if (!ExtractUtf16Path(
                payload,
                sizeof(*input),
                input->PathChars,
                &path))
        {
            return
                SERPIUM_SFP_API_E_INVALID;
        }

        DWORD error = ERROR_SUCCESS;

        uint64_t hash =
            HashAppPath(
                path,
                &error);

        if (hash == 0)
        {
            *win32Error = error;
            return
                SERPIUM_SFP_API_E_INVALID;
        }

        if (request.Command ==
            SERPIUM_SFP_API_CMD_ABORT_APP)
        {
            SERPIUM_SFP_STATUS kernel = {};

            if (!QueryKernelStatus(
                    &kernel,
                    &error))
            {
                *win32Error = error;
                return
                    KernelErrorToApi(error);
            }

            SERPIUM_SFP_ABORT_STALE_RESPONSE abort = {};

            if (!AbortHash(
                    hash,
                    kernel.PolicyGeneration + 1,
                    &abort,
                    &error))
            {
                *win32Error = error;
                return
                    SERPIUM_SFP_API_E_ABORT_INCOMPLETE;
            }

            SERPIUM_SFP_API_ABORT_RESPONSE api = {};
            api.Matched = abort.Matched;
            api.Aborted = abort.Aborted;
            api.Failed = abort.Failed;

            responsePayload->resize(
                sizeof(api));

            memcpy(
                responsePayload->data(),
                &api,
                sizeof(api));

            return SERPIUM_SFP_API_OK;
        }

        PolicyState candidate;

        {
            std::lock_guard<std::mutex> guard(
                g_StateLock);

            candidate = g_State;
        }

        auto found =
            candidate.Entries.find(hash);

        if (found ==
            candidate.Entries.end())
        {
            return
                SERPIUM_SFP_API_E_NOT_FOUND;
        }

        SERPIUM_SFP_STATUS kernel = {};

        if (!QueryKernelStatus(
                &kernel,
                &error))
        {
            *win32Error = error;
            return
                KernelErrorToApi(error);
        }

        candidate.Generation =
            std::max<uint64_t>(
                candidate.Generation,
                kernel.PolicyGeneration) + 1;

        candidate.Entries.erase(
            found);

        return CommitPolicy(candidate, request.Flags, hash, win32Error);
    }

    if (request.Command ==
        SERPIUM_SFP_API_CMD_RESET_POLICY)
    {
        PolicyState candidate;
        candidate.DefaultRoute =
            SERPIUM_SFP_ROUTE_DIRECT;

        SERPIUM_SFP_STATUS kernel = {};
        DWORD error = ERROR_SUCCESS;

        if (!QueryKernelStatus(
                &kernel,
                &error))
        {
            *win32Error = error;
            return
                KernelErrorToApi(error);
        }

        {
            std::lock_guard<std::mutex> guard(
                g_StateLock);

            candidate.Generation =
                std::max<uint64_t>(
                    g_State.Generation,
                    kernel.PolicyGeneration) + 1;
        }

        return CommitPolicy(candidate, request.Flags, 0, win32Error);
    }

    return
        SERPIUM_SFP_API_E_INVALID;
}

static void ClientThread(HANDLE pipe)
{
    for (;;)
    {
        SERPIUM_SFP_API_REQUEST_HEADER request = {};

        if (!ReadExact(
                pipe,
                &request,
                sizeof(request)))
        {
            break;
        }

        SERPIUM_SFP_API_RESPONSE_HEADER response = {};
        response.Magic =
            SERPIUM_SFP_API_MAGIC;
        response.Version =
            SERPIUM_SFP_API_VERSION;
        response.Command =
            request.Command;
        response.RequestId =
            request.RequestId;

        if (request.Magic !=
                SERPIUM_SFP_API_MAGIC ||
            request.Version !=
                SERPIUM_SFP_API_VERSION ||
            request.PayloadBytes >
                SERPIUM_SFP_API_MAX_PAYLOAD)
        {
            response.Result =
                SERPIUM_SFP_API_E_PROTOCOL;

            WriteExact(
                pipe,
                &response,
                sizeof(response));

            break;
        }

        std::vector<BYTE> payload(
            request.PayloadBytes);

        if (!payload.empty() &&
            !ReadExact(
                pipe,
                payload.data(),
                static_cast<DWORD>(
                    payload.size())))
        {
            break;
        }

        std::vector<BYTE> responsePayload;
        DWORD win32Error = ERROR_SUCCESS;

        response.Result =
            HandleRequest(
                request,
                payload,
                &responsePayload,
                &win32Error);

        response.Win32Error =
            win32Error;
        response.PayloadBytes =
            static_cast<uint32_t>(
                responsePayload.size());

        if (!WriteExact(
                pipe,
                &response,
                sizeof(response)))
        {
            break;
        }

        if (!responsePayload.empty() &&
            !WriteExact(
                pipe,
                responsePayload.data(),
                static_cast<DWORD>(
                    responsePayload.size())))
        {
            break;
        }
    }

    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
}

static SECURITY_ATTRIBUTES* BuildPipeSecurity(
    SECURITY_ATTRIBUTES* attributes,
    PSECURITY_DESCRIPTOR* descriptor)
{
    *descriptor = nullptr;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P"
            L"(A;;GA;;;SY)"
            L"(A;;GA;;;BA)"
            L"(A;;GRGW;;;IU)",
            SDDL_REVISION_1,
            descriptor,
            nullptr))
    {
        return nullptr;
    }

    attributes->nLength =
        sizeof(*attributes);
    attributes->lpSecurityDescriptor =
        *descriptor;
    attributes->bInheritHandle =
        FALSE;

    return attributes;
}

static void WakePipe()
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

    if (pipe !=
        INVALID_HANDLE_VALUE)
    {
        CloseHandle(pipe);
    }
}

static int RunServer()
{
    LoadState();
    SynchronizeSavedStateToKernel();

    SECURITY_ATTRIBUTES attributes = {};
    PSECURITY_DESCRIPTOR descriptor = nullptr;

    if (BuildPipeSecurity(
            &attributes,
            &descriptor) == nullptr)
    {
        return 10;
    }

    for (;;)
    {
        if (WaitForSingleObject(
                g_StopEvent,
                0) == WAIT_OBJECT_0)
        {
            break;
        }

        HANDLE pipe =
            CreateNamedPipeW(
                SERPIUM_SFP_API_PIPE_NAME,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE |
                PIPE_READMODE_BYTE |
                PIPE_WAIT |
                PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                1024 * 1024,
                1024 * 1024,
                0,
                &attributes);

        if (pipe ==
            INVALID_HANDLE_VALUE)
        {
            LocalFree(
                descriptor);

            return 11;
        }

        BOOL connected =
            ConnectNamedPipe(
                pipe,
                nullptr)
            ? TRUE
            : GetLastError() ==
                ERROR_PIPE_CONNECTED;

        if (WaitForSingleObject(
                g_StopEvent,
                0) == WAIT_OBJECT_0)
        {
            if (connected)
                DisconnectNamedPipe(pipe);

            CloseHandle(pipe);
            break;
        }

        if (!connected)
        {
            CloseHandle(pipe);
            continue;
        }

        std::thread(
            ClientThread,
            pipe).detach();
    }

    LocalFree(descriptor);
    return 0;
}

static void SetServiceState(
    DWORD state,
    DWORD win32ExitCode = NO_ERROR)
{
    if (g_ServiceStatusHandle ==
        nullptr)
    {
        return;
    }

    g_ServiceStatus.dwServiceType =
        SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState =
        state;
    g_ServiceStatus.dwWin32ExitCode =
        win32ExitCode;

    g_ServiceStatus.dwControlsAccepted =
        state == SERVICE_RUNNING
            ? SERVICE_ACCEPT_STOP |
              SERVICE_ACCEPT_SHUTDOWN
            : 0;

    SetServiceStatus(
        g_ServiceStatusHandle,
        &g_ServiceStatus);
}

static DWORD WINAPI ServiceControl(
    DWORD control,
    DWORD,
    void*,
    void*)
{
    if (control ==
            SERVICE_CONTROL_STOP ||
        control ==
            SERVICE_CONTROL_SHUTDOWN)
    {
        SetServiceState(
            SERVICE_STOP_PENDING);

        SetEvent(
            g_StopEvent);

        WakePipe();
    }

    return NO_ERROR;
}

static void WINAPI ServiceMain(
    DWORD,
    wchar_t**)
{
    g_ServiceStatusHandle =
        RegisterServiceCtrlHandlerExW(
            kServiceName,
            ServiceControl,
            nullptr);

    if (g_ServiceStatusHandle ==
        nullptr)
    {
        return;
    }

    SetServiceState(
        SERVICE_START_PENDING);

    g_StopEvent =
        CreateEventW(
            nullptr,
            TRUE,
            FALSE,
            nullptr);

    if (g_StopEvent == nullptr)
    {
        SetServiceState(
            SERVICE_STOPPED,
            GetLastError());

        return;
    }

    SetServiceState(
        SERVICE_RUNNING);

    int result =
        RunServer();

    CloseHandle(
        g_StopEvent);

    g_StopEvent = nullptr;

    SetServiceState(
        SERVICE_STOPPED,
        result == 0
            ? NO_ERROR
            : ERROR_GEN_FAILURE);
}

static BOOL WINAPI ConsoleHandler(
    DWORD control)
{
    if (control == CTRL_C_EVENT ||
        control == CTRL_BREAK_EVENT ||
        control == CTRL_CLOSE_EVENT ||
        control == CTRL_SHUTDOWN_EVENT)
    {
        SetEvent(
            g_StopEvent);

        WakePipe();

        return TRUE;
    }

    return FALSE;
}

static int RunConsole()
{
    g_StopEvent =
        CreateEventW(
            nullptr,
            TRUE,
            FALSE,
            nullptr);

    if (g_StopEvent == nullptr)
        return 20;

    SetConsoleCtrlHandler(
        ConsoleHandler,
        TRUE);

    std::wcout
        << L"Serpium SFP API v1\n"
        << L"Pipe: "
        << SERPIUM_SFP_API_PIPE_NAME
        << L"\nKernel ABI: 0x"
        << std::hex
        << SERPIUM_SFP_PROTOCOL_VERSION
        << std::dec
        << L"\nCtrl+C to stop.\n";

    int result =
        RunServer();

    CloseHandle(
        g_StopEvent);

    g_StopEvent = nullptr;

    return result;
}

int wmain(
    int argc,
    wchar_t** argv)
{
    if (argc >= 2 &&
        _wcsicmp(
            argv[1],
            L"service") == 0)
    {
        SERVICE_TABLE_ENTRYW table[] =
        {
            {
                const_cast<LPWSTR>(
                    kServiceName),
                ServiceMain
            },
            { nullptr, nullptr }
        };

        if (!StartServiceCtrlDispatcherW(
                table))
        {
            return
                static_cast<int>(
                    GetLastError());
        }

        return 0;
    }

    return RunConsole();
}
