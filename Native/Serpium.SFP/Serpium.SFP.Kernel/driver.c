#include <initguid.h>
#include "driver.h"

#define SERPIUM_SFP_POOL_TAG 'pfSS'

DEFINE_GUID(
    SERPIUM_SFP_PROVIDER_KEY,
    0x78a3b3ac, 0x3dfb, 0x47a3, 0xa5, 0x13, 0x44, 0x81, 0x8a, 0x1f, 0x44, 0x01);

DEFINE_GUID(
    SERPIUM_SFP_SUBLAYER_KEY,
    0xeb89a96a, 0x7148, 0x4f55, 0xa8, 0x7d, 0x84, 0x93, 0x3f, 0x42, 0xe5, 0x32);

DEFINE_GUID(
    SERPIUM_SFP_AUTH_V4_CALLOUT_KEY,
    0x4a5f85d0, 0x65fd, 0x4dbc, 0xb7, 0x0c, 0xb1, 0x38, 0x5e, 0x17, 0x2a, 0x91);

DEFINE_GUID(
    SERPIUM_SFP_AUTH_V6_CALLOUT_KEY,
    0x21802dd4, 0x86a7, 0x4682, 0x91, 0x8d, 0x6d, 0xb2, 0x43, 0xc4, 0xc3, 0x49);

DEFINE_GUID(
    SERPIUM_SFP_FLOW_V4_CALLOUT_KEY,
    0x90ee4f75, 0x4575, 0x4f9f, 0x9c, 0x77, 0x9d, 0x0d, 0x69, 0x45, 0x53, 0xc3);

DEFINE_GUID(
    SERPIUM_SFP_FLOW_V6_CALLOUT_KEY,
    0x5788e59e, 0xd762, 0x4dda, 0x86, 0xf5, 0x40, 0x51, 0x31, 0x24, 0x87, 0xa5);


DEFINE_GUID(
    SERPIUM_SFP_REDIRECT_V4_CALLOUT_KEY,
    0xd7c5f930, 0x1373, 0x4a20, 0xae, 0x21, 0x66, 0x54, 0xca, 0x38, 0xdf, 0x11);

DEFINE_GUID(
    SERPIUM_SFP_REDIRECT_V6_CALLOUT_KEY,
    0x758cdd51, 0xdcaa, 0x4915, 0xa4, 0x80, 0xc9, 0x67, 0xef, 0xe2, 0xe6, 0x62);

typedef struct _SERPIUM_SFP_FLOW_CONTEXT
{
    LIST_ENTRY Link;
    BOOLEAN Listed;
    UCHAR Reserved0[7];

    SERPIUM_SFP_EVENT Event;
} SERPIUM_SFP_FLOW_CONTEXT, *PSERPIUM_SFP_FLOW_CONTEXT;

typedef struct _SERPIUM_SFP_RUNTIME
{
    WDFDEVICE Device;
    WDFQUEUE PendingReadQueue;

    WDFSPINLOCK EventLock;
    WDFSPINLOCK PolicyLock;
    WDFSPINLOCK FlowLock;
    WDFSPINLOCK BridgeLock;

    SERPIUM_SFP_EVENT Events[SERPIUM_SFP_EVENT_QUEUE_CAPACITY];
    ULONG EventHead;
    ULONG EventCount;

    UINT64 NextSequence;
    UINT64 TotalEvents;
    UINT64 DroppedEvents;
    UINT64 Started100ns;

    SERPIUM_SFP_POLICY_ENTRY Policy[SERPIUM_SFP_MAX_POLICY_ENTRIES];
    ULONG PolicyCount;
    ULONG DefaultRoute;
    UINT64 PolicyGeneration;

    LIST_ENTRY ActiveFlows;
    ULONG ActiveFlowCount;

    HANDLE EngineHandle;

    UINT32 AuthCalloutIdV4;
    UINT32 AuthCalloutIdV6;
    UINT32 FlowCalloutIdV4;
    UINT32 FlowCalloutIdV6;
    UINT32 RedirectCalloutIdV4;
    UINT32 RedirectCalloutIdV6;

    HANDLE RedirectHandle;

    BOOLEAN BridgeArmed;
    UCHAR ReservedBridge0[7];
    UINT64 BridgeProcessId;
    ULONG BridgeListenPortV4;
    ULONG BridgeListenPortV6;
    ULONG BridgeBypassProcessCount;
    UINT64 BridgeBypassProcessIds[SERPIUM_SFP_MAX_BYPASS_PROCESSES];
    UINT64 TotalRedirected;
    UINT64 TotalRedirectFailOpen;

    BOOLEAN Started;
} SERPIUM_SFP_RUNTIME;

static SERPIUM_SFP_RUNTIME g_Runtime;

static
UINT64
SerpiumSfpNow100ns(
    VOID
    )
{
    return KeQueryInterruptTime();
}

static
VOID
SerpiumSfpResetRuntime(
    VOID
    )
{
    RtlZeroMemory(&g_Runtime, sizeof(g_Runtime));
    g_Runtime.Started100ns = SerpiumSfpNow100ns();
    g_Runtime.NextSequence = 1;

    g_Runtime.DefaultRoute = SERPIUM_SFP_ROUTE_DIRECT;
    g_Runtime.PolicyGeneration = 0;

    InitializeListHead(&g_Runtime.ActiveFlows);
}

static
UINT64
SerpiumSfpHashAppId(
    _In_opt_ const FWP_BYTE_BLOB* AppId
    )
{
    UINT64 hash = 14695981039346656037ull;
    ULONG index;

    if (AppId == NULL || AppId->data == NULL || AppId->size == 0)
    {
        return 0;
    }

    for (index = 0; index < AppId->size; index++)
    {
        hash ^= AppId->data[index];
        hash *= 1099511628211ull;
    }

    return hash;
}

static
BOOLEAN
SerpiumSfpRouteIsValid(
    _In_ ULONG Route
    )
{
    return
        Route == SERPIUM_SFP_ROUTE_DIRECT ||
        Route == SERPIUM_SFP_ROUTE_VPN;
}

static
VOID
SerpiumSfpResolvePolicy(
    _In_ UINT64 AppIdHash,
    _Out_ PULONG Route,
    _Out_ PUINT64 Generation,
    _Out_ PBOOLEAN PolicyHit
    )
{
    ULONG index;
    ULONG route;
    UINT64 generation;
    BOOLEAN hit = FALSE;

    WdfSpinLockAcquire(g_Runtime.PolicyLock);

    route = g_Runtime.DefaultRoute;
    generation = g_Runtime.PolicyGeneration;

    for (index = 0; index < g_Runtime.PolicyCount; index++)
    {
        if (g_Runtime.Policy[index].AppIdHash == AppIdHash)
        {
            route = g_Runtime.Policy[index].Route;
            hit = TRUE;
            break;
        }
    }

    WdfSpinLockRelease(g_Runtime.PolicyLock);

    *Route = route;
    *Generation = generation;
    *PolicyHit = hit;
}

static
VOID
SerpiumSfpApplyPolicyToEvent(
    _In_opt_ const FWP_BYTE_BLOB* AppId,
    _Inout_ PSERPIUM_SFP_EVENT Event
    )
{
    BOOLEAN hit = FALSE;

    Event->AppIdHash =
        SerpiumSfpHashAppId(AppId);

    SerpiumSfpResolvePolicy(
        Event->AppIdHash,
        &Event->Route,
        &Event->PolicyGeneration,
        &hit);

    if (hit)
    {
        Event->Flags |=
            SERPIUM_SFP_EVENT_FLAG_POLICY_HIT;
    }
}

static
VOID
SerpiumSfpFlowListInsert(
    _Inout_ PSERPIUM_SFP_FLOW_CONTEXT Context
    )
{
    WdfSpinLockAcquire(g_Runtime.FlowLock);

    InsertTailList(
        &g_Runtime.ActiveFlows,
        &Context->Link);

    Context->Listed = TRUE;
    g_Runtime.ActiveFlowCount++;

    WdfSpinLockRelease(g_Runtime.FlowLock);
}

static
VOID
SerpiumSfpFlowListRemove(
    _Inout_ PSERPIUM_SFP_FLOW_CONTEXT Context
    )
{
    WdfSpinLockAcquire(g_Runtime.FlowLock);

    if (Context->Listed)
    {
        RemoveEntryList(&Context->Link);
        InitializeListHead(&Context->Link);
        Context->Listed = FALSE;

        if (g_Runtime.ActiveFlowCount > 0)
        {
            g_Runtime.ActiveFlowCount--;
        }
    }

    WdfSpinLockRelease(g_Runtime.FlowLock);
}

typedef struct _SERPIUM_SFP_BRIDGE_SNAPSHOT
{
    BOOLEAN Ready;
    ULONG ListenPort;
    UINT64 BridgeProcessId;
} SERPIUM_SFP_BRIDGE_SNAPSHOT, *PSERPIUM_SFP_BRIDGE_SNAPSHOT;

static
BOOLEAN
SerpiumSfpProcessIsBridgeBypassLocked(
    _In_ UINT64 ProcessId
    )
{
    ULONG index;

    if (ProcessId == g_Runtime.BridgeProcessId)
    {
        return TRUE;
    }

    for (index = 0;
         index < g_Runtime.BridgeBypassProcessCount;
         index++)
    {
        if (g_Runtime.BridgeBypassProcessIds[index] == ProcessId)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static
VOID
SerpiumSfpGetBridgeSnapshot(
    _In_ UINT64 ProcessId,
    _In_ USHORT AddressFamily,
    _Out_ PSERPIUM_SFP_BRIDGE_SNAPSHOT Snapshot
    )
{
    ULONG port = 0;

    RtlZeroMemory(Snapshot, sizeof(*Snapshot));

    WdfSpinLockAcquire(g_Runtime.BridgeLock);

    if (g_Runtime.BridgeArmed &&
        !SerpiumSfpProcessIsBridgeBypassLocked(ProcessId))
    {
        port =
            AddressFamily == AF_INET
                ? g_Runtime.BridgeListenPortV4
                : g_Runtime.BridgeListenPortV6;

        if (port > 0 && port <= MAXUSHORT &&
            g_Runtime.BridgeProcessId > 0 &&
            g_Runtime.BridgeProcessId <= MAXULONG)
        {
            Snapshot->Ready = TRUE;
            Snapshot->ListenPort = port;
            Snapshot->BridgeProcessId =
                g_Runtime.BridgeProcessId;
        }
    }

    WdfSpinLockRelease(g_Runtime.BridgeLock);
}

static
BOOLEAN
SerpiumSfpIsLoopbackSockaddr(
    _In_ const SOCKADDR_STORAGE* Address
    )
{
    if (Address == NULL)
    {
        return FALSE;
    }

    if (Address->ss_family == AF_INET)
    {
        const SOCKADDR_IN* address4 =
            (const SOCKADDR_IN*)Address;

        return
            RtlUlongByteSwap(address4->sin_addr.S_un.S_addr) ==
            0x7f000001u;
    }

    if (Address->ss_family == AF_INET6)
    {
        const SOCKADDR_IN6* address6 =
            (const SOCKADDR_IN6*)Address;
        static const UCHAR loopback[16] =
            { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

        return
            RtlCompareMemory(
                &address6->sin6_addr,
                loopback,
                sizeof(loopback)) == sizeof(loopback);
    }

    return FALSE;
}

static
VOID
SerpiumSfpFillRedirectContext(
    _In_ const FWPS_CONNECT_REQUEST0* ConnectRequest,
    _In_ UINT64 AppIdHash,
    _In_ UINT64 PolicyGeneration,
    _Out_ PSERPIUM_SFP_REDIRECT_CONTEXT Context
    )
{
    RtlZeroMemory(Context, sizeof(*Context));

    Context->Size = sizeof(*Context);
    Context->ProtocolVersion =
        SERPIUM_SFP_PROTOCOL_VERSION;
    Context->Magic =
        SERPIUM_SFP_REDIRECT_CONTEXT_MAGIC;
    Context->AppIdHash = AppIdHash;
    Context->PolicyGeneration =
        PolicyGeneration;
    Context->Route = SERPIUM_SFP_ROUTE_VPN;
    Context->Protocol = IPPROTO_TCP;

    if (ConnectRequest->remoteAddressAndPort.ss_family == AF_INET)
    {
        const SOCKADDR_IN* remote =
            (const SOCKADDR_IN*)&ConnectRequest->remoteAddressAndPort;

        Context->AddressFamily = AF_INET;
        Context->RemotePort =
            RtlUshortByteSwap(remote->sin_port);

        RtlCopyMemory(
            Context->RemoteAddress,
            &remote->sin_addr,
            4);
    }
    else if (ConnectRequest->remoteAddressAndPort.ss_family == AF_INET6)
    {
        const SOCKADDR_IN6* remote =
            (const SOCKADDR_IN6*)&ConnectRequest->remoteAddressAndPort;

        Context->AddressFamily = AF_INET6;
        Context->RemotePort =
            RtlUshortByteSwap(remote->sin6_port);

        RtlCopyMemory(
            Context->RemoteAddress,
            &remote->sin6_addr,
            16);
    }
}

static
VOID
SerpiumSfpRecordRedirectResult(
    _In_ BOOLEAN Redirected,
    _In_ BOOLEAN FailOpen
    )
{
    WdfSpinLockAcquire(g_Runtime.BridgeLock);

    if (Redirected)
    {
        g_Runtime.TotalRedirected++;
    }

    if (FailOpen)
    {
        g_Runtime.TotalRedirectFailOpen++;
    }

    WdfSpinLockRelease(g_Runtime.BridgeLock);
}

static
VOID
SerpiumSfpCopyAppId(
    _In_opt_ const FWP_BYTE_BLOB* AppId,
    _Inout_ PSERPIUM_SFP_EVENT Event
    )
{
    ULONG bytes;

    if (AppId == NULL || AppId->data == NULL || AppId->size == 0)
    {
        return;
    }

    bytes = AppId->size;

    if (bytes > ((SERPIUM_SFP_APP_ID_MAX_CHARS - 1u) * sizeof(WCHAR)))
    {
        bytes = (SERPIUM_SFP_APP_ID_MAX_CHARS - 1u) * sizeof(WCHAR);
    }

    RtlCopyMemory(Event->AppId, AppId->data, bytes);
    Event->AppId[bytes / sizeof(WCHAR)] = L'\0';
    Event->AppIdByteLength = bytes;
    Event->Flags |= SERPIUM_SFP_EVENT_FLAG_APP_ID;
}

static
VOID
SerpiumSfpCopyAddressV4(
    _In_ UINT32 Address,
    _Out_writes_bytes_(16) UCHAR Destination[16]
    )
{
    RtlZeroMemory(Destination, 16);
    RtlCopyMemory(Destination, &Address, sizeof(Address));
}

static
VOID
SerpiumSfpCopyAddressV6(
    _In_opt_ const FWP_BYTE_ARRAY16* Address,
    _Out_writes_bytes_(16) UCHAR Destination[16]
    )
{
    RtlZeroMemory(Destination, 16);

    if (Address != NULL)
    {
        RtlCopyMemory(Destination, Address->byteArray16, 16);
    }
}

static
VOID
SerpiumSfpFillProcessId(
    _In_ const FWPS_INCOMING_METADATA_VALUES0* Metadata,
    _Inout_ PSERPIUM_SFP_EVENT Event
    )
{
    if ((Metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0)
    {
        Event->ProcessId = Metadata->processId;
        Event->Flags |= SERPIUM_SFP_EVENT_FLAG_PROCESS_ID;
    }
}

static
VOID
SerpiumSfpFillAuthEventV4(
    _In_ const FWPS_INCOMING_VALUES0* Values,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* Metadata,
    _Inout_ PSERPIUM_SFP_EVENT Event
    )
{
    RtlZeroMemory(Event, sizeof(*Event));

    Event->Size = sizeof(*Event);
    Event->ProtocolVersion = SERPIUM_SFP_PROTOCOL_VERSION;
    Event->Type = SERPIUM_SFP_EVENT_CONNECT_ATTEMPT;
    Event->AddressFamily = AF_INET;

    Event->Protocol =
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;

    Event->LocalPort =
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;

    Event->RemotePort =
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;

    SerpiumSfpCopyAddressV4(
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32,
        Event->LocalAddress);

    SerpiumSfpCopyAddressV4(
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32,
        Event->RemoteAddress);

    SerpiumSfpCopyAppId(
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID].value.byteBlob,
        Event);

    SerpiumSfpApplyPolicyToEvent(
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID].value.byteBlob,
        Event);

    SerpiumSfpFillProcessId(Metadata, Event);
}

static
VOID
SerpiumSfpFillAuthEventV6(
    _In_ const FWPS_INCOMING_VALUES0* Values,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* Metadata,
    _Inout_ PSERPIUM_SFP_EVENT Event
    )
{
    RtlZeroMemory(Event, sizeof(*Event));

    Event->Size = sizeof(*Event);
    Event->ProtocolVersion = SERPIUM_SFP_PROTOCOL_VERSION;
    Event->Type = SERPIUM_SFP_EVENT_CONNECT_ATTEMPT;
    Event->AddressFamily = AF_INET6;
    Event->Flags |= SERPIUM_SFP_EVENT_FLAG_IPV6;

    Event->Protocol =
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL].value.uint8;

    Event->LocalPort =
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT].value.uint16;

    Event->RemotePort =
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16;

    SerpiumSfpCopyAddressV6(
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS].value.byteArray16,
        Event->LocalAddress);

    SerpiumSfpCopyAddressV6(
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16,
        Event->RemoteAddress);

    SerpiumSfpCopyAppId(
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID].value.byteBlob,
        Event);

    SerpiumSfpApplyPolicyToEvent(
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID].value.byteBlob,
        Event);

    SerpiumSfpFillProcessId(Metadata, Event);
}

static
VOID
SerpiumSfpFillFlowEventV4(
    _In_ const FWPS_INCOMING_VALUES0* Values,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* Metadata,
    _In_ UINT64 FlowId,
    _Inout_ PSERPIUM_SFP_EVENT Event
    )
{
    RtlZeroMemory(Event, sizeof(*Event));

    Event->Size = sizeof(*Event);
    Event->ProtocolVersion = SERPIUM_SFP_PROTOCOL_VERSION;
    Event->Type = SERPIUM_SFP_EVENT_FLOW_OPEN;
    Event->FlowId = FlowId;
    Event->AddressFamily = AF_INET;

    Event->Protocol =
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL].value.uint8;

    Event->LocalPort =
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT].value.uint16;

    Event->RemotePort =
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT].value.uint16;

    SerpiumSfpCopyAddressV4(
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS].value.uint32,
        Event->LocalAddress);

    SerpiumSfpCopyAddressV4(
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS].value.uint32,
        Event->RemoteAddress);

    SerpiumSfpCopyAppId(
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_APP_ID].value.byteBlob,
        Event);

    SerpiumSfpApplyPolicyToEvent(
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_APP_ID].value.byteBlob,
        Event);

    SerpiumSfpFillProcessId(Metadata, Event);
}

static
VOID
SerpiumSfpFillFlowEventV6(
    _In_ const FWPS_INCOMING_VALUES0* Values,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* Metadata,
    _In_ UINT64 FlowId,
    _Inout_ PSERPIUM_SFP_EVENT Event
    )
{
    RtlZeroMemory(Event, sizeof(*Event));

    Event->Size = sizeof(*Event);
    Event->ProtocolVersion = SERPIUM_SFP_PROTOCOL_VERSION;
    Event->Type = SERPIUM_SFP_EVENT_FLOW_OPEN;
    Event->FlowId = FlowId;
    Event->AddressFamily = AF_INET6;
    Event->Flags |= SERPIUM_SFP_EVENT_FLAG_IPV6;

    Event->Protocol =
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL].value.uint8;

    Event->LocalPort =
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT].value.uint16;

    Event->RemotePort =
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT].value.uint16;

    SerpiumSfpCopyAddressV6(
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS].value.byteArray16,
        Event->LocalAddress);

    SerpiumSfpCopyAddressV6(
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS].value.byteArray16,
        Event->RemoteAddress);

    SerpiumSfpCopyAppId(
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_ALE_APP_ID].value.byteBlob,
        Event);

    SerpiumSfpApplyPolicyToEvent(
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_ALE_APP_ID].value.byteBlob,
        Event);

    SerpiumSfpFillProcessId(Metadata, Event);
}

static
BOOLEAN
SerpiumSfpPopEvent(
    _Out_ PSERPIUM_SFP_EVENT Event
    )
{
    BOOLEAN result = FALSE;

    WdfSpinLockAcquire(g_Runtime.EventLock);

    if (g_Runtime.EventCount > 0)
    {
        *Event = g_Runtime.Events[g_Runtime.EventHead];

        g_Runtime.EventHead =
            (g_Runtime.EventHead + 1u) % SERPIUM_SFP_EVENT_QUEUE_CAPACITY;

        g_Runtime.EventCount--;
        result = TRUE;
    }

    WdfSpinLockRelease(g_Runtime.EventLock);
    return result;
}

static
VOID
SerpiumSfpTrySatisfyReads(
    VOID
    )
{
    WDFREQUEST request;
    NTSTATUS status;

    for (;;)
    {
        SERPIUM_SFP_EVENT event;
        PSERPIUM_SFP_EVENT output = NULL;
        size_t outputSize = 0;

        status = WdfIoQueueRetrieveNextRequest(
            g_Runtime.PendingReadQueue,
            &request);

        if (!NT_SUCCESS(status))
        {
            return;
        }

        if (!SerpiumSfpPopEvent(&event))
        {
            status = WdfRequestForwardToIoQueue(
                request,
                g_Runtime.PendingReadQueue);

            if (!NT_SUCCESS(status))
            {
                WdfRequestComplete(request, status);
            }

            return;
        }

        status = WdfRequestRetrieveOutputBuffer(
            request,
            sizeof(SERPIUM_SFP_EVENT),
            (PVOID*)&output,
            &outputSize);

        if (!NT_SUCCESS(status))
        {
            WdfRequestComplete(request, status);
            continue;
        }

        *output = event;

        WdfRequestCompleteWithInformation(
            request,
            STATUS_SUCCESS,
            sizeof(SERPIUM_SFP_EVENT));
    }
}

static
VOID
SerpiumSfpPushEvent(
    _In_ const SERPIUM_SFP_EVENT* Source
    )
{
    SERPIUM_SFP_EVENT event = *Source;
    ULONG tail;

    WdfSpinLockAcquire(g_Runtime.EventLock);

    event.Sequence = g_Runtime.NextSequence++;
    event.Timestamp100ns = SerpiumSfpNow100ns();

    if (g_Runtime.EventCount == SERPIUM_SFP_EVENT_QUEUE_CAPACITY)
    {
        g_Runtime.EventHead =
            (g_Runtime.EventHead + 1u) % SERPIUM_SFP_EVENT_QUEUE_CAPACITY;

        g_Runtime.EventCount--;
        g_Runtime.DroppedEvents++;
    }

    tail =
        (g_Runtime.EventHead + g_Runtime.EventCount) %
        SERPIUM_SFP_EVENT_QUEUE_CAPACITY;

    g_Runtime.Events[tail] = event;
    g_Runtime.EventCount++;
    g_Runtime.TotalEvents++;

    WdfSpinLockRelease(g_Runtime.EventLock);

    SerpiumSfpTrySatisfyReads();
}

static
VOID
SerpiumSfpPermit(
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    if ((ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0)
    {
        ClassifyOut->actionType = FWP_ACTION_CONTINUE;
    }
}

_Use_decl_annotations_
VOID
NTAPI
SerpiumSfpAuthClassifyV4(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    VOID* LayerData,
    const FWPS_FILTER0* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    SERPIUM_SFP_EVENT event;

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    SerpiumSfpFillAuthEventV4(
        InFixedValues,
        InMetaValues,
        &event);

    SerpiumSfpPushEvent(&event);
    SerpiumSfpPermit(ClassifyOut);
}

_Use_decl_annotations_
VOID
NTAPI
SerpiumSfpAuthClassifyV6(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    VOID* LayerData,
    const FWPS_FILTER0* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    SERPIUM_SFP_EVENT event;

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    SerpiumSfpFillAuthEventV6(
        InFixedValues,
        InMetaValues,
        &event);

    SerpiumSfpPushEvent(&event);
    SerpiumSfpPermit(ClassifyOut);
}

static
VOID
SerpiumSfpAttachFlowContext(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _In_ BOOLEAN IsV6,
    _In_ UINT32 CalloutId
    )
{
    UINT64 flowId;
    PSERPIUM_SFP_FLOW_CONTEXT context;
    NTSTATUS status;

    if ((InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) == 0)
    {
        return;
    }

    flowId = InMetaValues->flowHandle;

    context = (PSERPIUM_SFP_FLOW_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(*context),
        SERPIUM_SFP_POOL_TAG);

    if (context == NULL)
    {
        return;
    }

    InitializeListHead(&context->Link);
    context->Listed = FALSE;

    if (IsV6)
    {
        SerpiumSfpFillFlowEventV6(
            InFixedValues,
            InMetaValues,
            flowId,
            &context->Event);
    }
    else
    {
        SerpiumSfpFillFlowEventV4(
            InFixedValues,
            InMetaValues,
            flowId,
            &context->Event);
    }

    SerpiumSfpFlowListInsert(context);

    status = FwpsFlowAssociateContext0(
        flowId,
        InFixedValues->layerId,
        CalloutId,
        (UINT64)(ULONG_PTR)context);

    if (!NT_SUCCESS(status))
    {
        SerpiumSfpFlowListRemove(context);
        ExFreePoolWithTag(context, SERPIUM_SFP_POOL_TAG);
        return;
    }

    {
        SERPIUM_SFP_EVENT openEvent = context->Event;
        SerpiumSfpPushEvent(&openEvent);
    }
}

_Use_decl_annotations_
VOID
NTAPI
SerpiumSfpFlowClassifyV4(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    VOID* LayerData,
    const FWPS_FILTER0* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(Filter);

    if (FlowContext == 0)
    {
        SerpiumSfpAttachFlowContext(
            InFixedValues,
            InMetaValues,
            FALSE,
            g_Runtime.FlowCalloutIdV4);
    }

    SerpiumSfpPermit(ClassifyOut);
}

_Use_decl_annotations_
VOID
NTAPI
SerpiumSfpFlowClassifyV6(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    VOID* LayerData,
    const FWPS_FILTER0* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(Filter);

    if (FlowContext == 0)
    {
        SerpiumSfpAttachFlowContext(
            InFixedValues,
            InMetaValues,
            TRUE,
            g_Runtime.FlowCalloutIdV6);
    }

    SerpiumSfpPermit(ClassifyOut);
}

_Use_decl_annotations_
VOID
NTAPI
SerpiumSfpFlowDelete(
    UINT16 LayerId,
    UINT32 CalloutId,
    UINT64 FlowContext
    )
{
    PSERPIUM_SFP_FLOW_CONTEXT context;
    SERPIUM_SFP_EVENT closeEvent;

    UNREFERENCED_PARAMETER(LayerId);
    UNREFERENCED_PARAMETER(CalloutId);

    if (FlowContext == 0)
    {
        return;
    }

    context = (PSERPIUM_SFP_FLOW_CONTEXT)(ULONG_PTR)FlowContext;

    closeEvent = context->Event;
    closeEvent.Type = SERPIUM_SFP_EVENT_FLOW_CLOSE;

    SerpiumSfpFlowListRemove(context);
    SerpiumSfpPushEvent(&closeEvent);

    ExFreePoolWithTag(
        context,
        SERPIUM_SFP_POOL_TAG);
}

static
VOID
NTAPI
SerpiumSfpRedirectClassify(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _In_opt_ const VOID* ClassifyContext,
    _In_ const FWPS_FILTER1* Filter,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    ULONG appIdIndex;
    const FWP_BYTE_BLOB* appId;
    UINT64 appIdHash;
    ULONG route;
    UINT64 generation;
    BOOLEAN policyHit;
    UINT64 processId;
    SERPIUM_SFP_BRIDGE_SNAPSHOT snapshot;
    FWPS_CONNECTION_REDIRECT_STATE redirectState;
    UINT64 classifyHandle = 0;
    PVOID writableLayerData = NULL;
    FWPS_CONNECT_REQUEST0* connectRequest;
    PSERPIUM_SFP_REDIRECT_CONTEXT redirectContext = NULL;
    NTSTATUS status;

    if (InFixedValues == NULL ||
        InMetaValues == NULL ||
        Filter == NULL ||
        ClassifyOut == NULL)
    {
        return;
    }

    if ((ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
    {
        return;
    }

    ClassifyOut->actionType = FWP_ACTION_PERMIT;

    if (InFixedValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4)
    {
        if (InFixedValues->incomingValue[
                FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL
                ].value.uint8 != IPPROTO_TCP)
        {
            return;
        }

        appIdIndex =
            FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ALE_APP_ID;
    }
    else if (InFixedValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V6)
    {
        if (InFixedValues->incomingValue[
                FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_PROTOCOL
                ].value.uint8 != IPPROTO_TCP)
        {
            return;
        }

        appIdIndex =
            FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_ALE_APP_ID;
    }
    else
    {
        return;
    }

    appId =
        InFixedValues->incomingValue[appIdIndex].value.type ==
            FWP_BYTE_BLOB_TYPE
            ? InFixedValues->incomingValue[appIdIndex].value.byteBlob
            : NULL;

    appIdHash = SerpiumSfpHashAppId(appId);

    SerpiumSfpResolvePolicy(
        appIdHash,
        &route,
        &generation,
        &policyHit);

    UNREFERENCED_PARAMETER(policyHit);

    if (route != SERPIUM_SFP_ROUTE_VPN)
    {
        return;
    }

    if ((InMetaValues->currentMetadataValues &
         FWPS_METADATA_FIELD_PROCESS_ID) == 0)
    {
        SerpiumSfpRecordRedirectResult(FALSE, TRUE);
        return;
    }

    processId = InMetaValues->processId;

    SerpiumSfpGetBridgeSnapshot(
        processId,
        InFixedValues->layerId ==
            FWPS_LAYER_ALE_CONNECT_REDIRECT_V4
            ? AF_INET
            : AF_INET6,
        &snapshot);

    if (!snapshot.Ready)
    {
        SerpiumSfpRecordRedirectResult(FALSE, TRUE);
        return;
    }

    redirectState =
        InMetaValues->redirectRecords != NULL
            ? FwpsQueryConnectionRedirectState0(
                InMetaValues->redirectRecords,
                g_Runtime.RedirectHandle,
                NULL)
            : FWPS_CONNECTION_NOT_REDIRECTED;

    if (redirectState != FWPS_CONNECTION_NOT_REDIRECTED)
    {
        return;
    }

    status =
        FwpsAcquireClassifyHandle0(
            (VOID*)ClassifyContext,
            0,
            &classifyHandle);

    if (!NT_SUCCESS(status))
    {
        SerpiumSfpRecordRedirectResult(FALSE, TRUE);
        return;
    }

    status =
        FwpsAcquireWritableLayerDataPointer0(
            classifyHandle,
            Filter->filterId,
            0,
            &writableLayerData,
            ClassifyOut);

    if (!NT_SUCCESS(status) ||
        writableLayerData == NULL)
    {
        FwpsReleaseClassifyHandle0(classifyHandle);
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        SerpiumSfpRecordRedirectResult(FALSE, TRUE);
        return;
    }

    connectRequest =
        (FWPS_CONNECT_REQUEST0*)writableLayerData;

    if (SerpiumSfpIsLoopbackSockaddr(
            &connectRequest->remoteAddressAndPort))
    {
        FwpsApplyModifiedLayerData0(
            classifyHandle,
            writableLayerData,
            0);

        FwpsReleaseClassifyHandle0(classifyHandle);
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    redirectContext =
        (PSERPIUM_SFP_REDIRECT_CONTEXT)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(*redirectContext),
            SERPIUM_SFP_POOL_TAG);

    if (redirectContext == NULL)
    {
        FwpsApplyModifiedLayerData0(
            classifyHandle,
            writableLayerData,
            0);

        FwpsReleaseClassifyHandle0(classifyHandle);
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        SerpiumSfpRecordRedirectResult(FALSE, TRUE);
        return;
    }

    SerpiumSfpFillRedirectContext(
        connectRequest,
        appIdHash,
        generation,
        redirectContext);

    if (redirectContext->RemotePort == 0 ||
        (redirectContext->AddressFamily != AF_INET &&
         redirectContext->AddressFamily != AF_INET6))
    {
        ExFreePoolWithTag(
            redirectContext,
            SERPIUM_SFP_POOL_TAG);

        FwpsApplyModifiedLayerData0(
            classifyHandle,
            writableLayerData,
            0);

        FwpsReleaseClassifyHandle0(classifyHandle);
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        SerpiumSfpRecordRedirectResult(FALSE, TRUE);
        return;
    }

    if (redirectContext->AddressFamily == AF_INET)
    {
        SOCKADDR_IN* remote =
            (SOCKADDR_IN*)&connectRequest->remoteAddressAndPort;

        RtlZeroMemory(remote, sizeof(*remote));
        remote->sin_family = AF_INET;
        remote->sin_port =
            RtlUshortByteSwap((USHORT)snapshot.ListenPort);
        remote->sin_addr.S_un.S_addr =
            RtlUlongByteSwap(0x7f000001u);
    }
    else
    {
        SOCKADDR_IN6* remote =
            (SOCKADDR_IN6*)&connectRequest->remoteAddressAndPort;

        RtlZeroMemory(remote, sizeof(*remote));
        remote->sin6_family = AF_INET6;
        remote->sin6_port =
            RtlUshortByteSwap((USHORT)snapshot.ListenPort);
        remote->sin6_addr.u.Byte[15] = 1;
    }

    connectRequest->localRedirectTargetPID =
        (DWORD)snapshot.BridgeProcessId;
    connectRequest->localRedirectHandle =
        g_Runtime.RedirectHandle;
    connectRequest->localRedirectContext =
        redirectContext;
    connectRequest->localRedirectContextSize =
        sizeof(*redirectContext);

    FwpsApplyModifiedLayerData0(
        classifyHandle,
        writableLayerData,
        0);

    FwpsReleaseClassifyHandle0(classifyHandle);

    ClassifyOut->actionType = FWP_ACTION_PERMIT;
    SerpiumSfpRecordRedirectResult(TRUE, FALSE);

    //
    // WFP owns redirectContext after the modified request is applied.
    //
}

VOID
NTAPI
SerpiumSfpRedirectClassifyV4(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    VOID* LayerData,
    const VOID* ClassifyContext,
    const FWPS_FILTER1* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(FlowContext);

    SerpiumSfpRedirectClassify(
        InFixedValues,
        InMetaValues,
        ClassifyContext,
        Filter,
        ClassifyOut);
}

VOID
NTAPI
SerpiumSfpRedirectClassifyV6(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    VOID* LayerData,
    const VOID* ClassifyContext,
    const FWPS_FILTER1* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(FlowContext);

    SerpiumSfpRedirectClassify(
        InFixedValues,
        InMetaValues,
        ClassifyContext,
        Filter,
        ClassifyOut);
}

static
NTSTATUS
NTAPI
SerpiumSfpRedirectNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID* FilterKey,
    _Inout_ FWPS_FILTER1* Filter
    )
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
NTAPI
SerpiumSfpNotify(
    FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    const GUID* FilterKey,
    FWPS_FILTER0* Filter
    )
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);

    return STATUS_SUCCESS;
}

static
NTSTATUS
SerpiumSfpRegisterRuntimeCallout(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ const GUID* CalloutKey,
    _In_ FWPS_CALLOUT_CLASSIFY_FN0 ClassifyFunction,
    _In_opt_ FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0 FlowDeleteFunction,
    _Out_ UINT32* CalloutId
    )
{
    FWPS_CALLOUT0 callout;

    RtlZeroMemory(&callout, sizeof(callout));

    callout.calloutKey = *CalloutKey;
    callout.classifyFn = ClassifyFunction;
    callout.notifyFn = SerpiumSfpNotify;
    callout.flowDeleteFn = FlowDeleteFunction;

    return FwpsCalloutRegister0(
        DeviceObject,
        &callout,
        CalloutId);
}

static
NTSTATUS
SerpiumSfpRegisterRedirectRuntimeCallout(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ const GUID* CalloutKey,
    _In_ FWPS_CALLOUT_CLASSIFY_FN1 ClassifyFunction,
    _Out_ UINT32* CalloutId
    )
{
    FWPS_CALLOUT1 callout;

    RtlZeroMemory(&callout, sizeof(callout));

    callout.calloutKey = *CalloutKey;
    callout.classifyFn = ClassifyFunction;
    callout.notifyFn = SerpiumSfpRedirectNotify;
    callout.flowDeleteFn = NULL;

    return FwpsCalloutRegister1(
        DeviceObject,
        &callout,
        CalloutId);
}

static
NTSTATUS
SerpiumSfpAddManagementCallout(
    _In_ const GUID* CalloutKey,
    _In_ const GUID* LayerKey,
    _In_ PWSTR Name
    )
{
    FWPM_CALLOUT0 callout;

    RtlZeroMemory(&callout, sizeof(callout));

    callout.calloutKey = *CalloutKey;
    callout.displayData.name = Name;
    callout.displayData.description =
        L"Serpium SFP clean-room realtime telemetry callout";
    callout.applicableLayer = *LayerKey;
    callout.providerKey = (GUID*)&SERPIUM_SFP_PROVIDER_KEY;

    return FwpmCalloutAdd0(
        g_Runtime.EngineHandle,
        &callout,
        NULL,
        NULL);
}

static
NTSTATUS
SerpiumSfpAddInspectionFilter(
    _In_ const GUID* CalloutKey,
    _In_ const GUID* LayerKey,
    _In_ PWSTR Name
    )
{
    FWPM_FILTER0 filter;

    RtlZeroMemory(&filter, sizeof(filter));

    filter.displayData.name = Name;
    filter.displayData.description =
        L"SFP Core v1 policy observation; redirect comes in Bridge phase";
    filter.layerKey = *LayerKey;
    filter.subLayerKey = SERPIUM_SFP_SUBLAYER_KEY;
    filter.providerKey = (GUID*)&SERPIUM_SFP_PROVIDER_KEY;
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey = *CalloutKey;
    filter.weight.type = FWP_EMPTY;

    return FwpmFilterAdd0(
        g_Runtime.EngineHandle,
        &filter,
        NULL,
        NULL);
}

static
NTSTATUS
SerpiumSfpAddRedirectFilter(
    _In_ const GUID* CalloutKey,
    _In_ const GUID* LayerKey,
    _In_ PWSTR Name
    )
{
    FWPM_FILTER0 filter;
    FWPM_FILTER_CONDITION0 condition;

    RtlZeroMemory(&filter, sizeof(filter));
    RtlZeroMemory(&condition, sizeof(condition));

    condition.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_UINT8;
    condition.conditionValue.uint8 = IPPROTO_TCP;

    filter.displayData.name = Name;
    filter.displayData.description =
        L"SFP Bridge TCP redirect; unarmed state fails open";
    filter.layerKey = *LayerKey;
    filter.subLayerKey = SERPIUM_SFP_SUBLAYER_KEY;
    filter.providerKey = (GUID*)&SERPIUM_SFP_PROVIDER_KEY;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = *CalloutKey;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = 1;
    filter.filterCondition = &condition;

    return FwpmFilterAdd0(
        g_Runtime.EngineHandle,
        &filter,
        NULL,
        NULL);
}

_Use_decl_annotations_
NTSTATUS
SerpiumSfpStart(
    PDEVICE_OBJECT DeviceObject
    )
{
    NTSTATUS status;
    BOOLEAN transactionStarted = FALSE;
    FWPM_SESSION0 session;
    FWPM_PROVIDER0 provider;
    FWPM_SUBLAYER0 subLayer;

    if (g_Runtime.Started)
    {
        return STATUS_SUCCESS;
    }

    status = FwpsRedirectHandleCreate0(
        &SERPIUM_SFP_PROVIDER_KEY,
        0,
        &g_Runtime.RedirectHandle);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumSfpRegisterRedirectRuntimeCallout(
        DeviceObject,
        &SERPIUM_SFP_REDIRECT_V4_CALLOUT_KEY,
        SerpiumSfpRedirectClassifyV4,
        &g_Runtime.RedirectCalloutIdV4);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumSfpRegisterRedirectRuntimeCallout(
        DeviceObject,
        &SERPIUM_SFP_REDIRECT_V6_CALLOUT_KEY,
        SerpiumSfpRedirectClassifyV6,
        &g_Runtime.RedirectCalloutIdV6);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumSfpRegisterRuntimeCallout(
        DeviceObject,
        &SERPIUM_SFP_AUTH_V4_CALLOUT_KEY,
        SerpiumSfpAuthClassifyV4,
        NULL,
        &g_Runtime.AuthCalloutIdV4);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumSfpRegisterRuntimeCallout(
        DeviceObject,
        &SERPIUM_SFP_AUTH_V6_CALLOUT_KEY,
        SerpiumSfpAuthClassifyV6,
        NULL,
        &g_Runtime.AuthCalloutIdV6);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumSfpRegisterRuntimeCallout(
        DeviceObject,
        &SERPIUM_SFP_FLOW_V4_CALLOUT_KEY,
        SerpiumSfpFlowClassifyV4,
        SerpiumSfpFlowDelete,
        &g_Runtime.FlowCalloutIdV4);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumSfpRegisterRuntimeCallout(
        DeviceObject,
        &SERPIUM_SFP_FLOW_V6_CALLOUT_KEY,
        SerpiumSfpFlowClassifyV6,
        SerpiumSfpFlowDelete,
        &g_Runtime.FlowCalloutIdV6);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    RtlZeroMemory(&session, sizeof(session));
    session.displayData.name =
        L"Serpium SFP Core v1";
    session.displayData.description =
        L"Dynamic Serpium Flow Platform core session";
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.txnWaitTimeoutInMSec = 5000;

    status = FwpmEngineOpen0(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        &session,
        &g_Runtime.EngineHandle);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = FwpmTransactionBegin0(
        g_Runtime.EngineHandle,
        0);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    transactionStarted = TRUE;

    RtlZeroMemory(&provider, sizeof(provider));
    provider.providerKey = SERPIUM_SFP_PROVIDER_KEY;
    provider.displayData.name =
        L"Serpium SFP Provider";
    provider.displayData.description =
        L"Serpium Flow Platform event-driven core";

    status = FwpmProviderAdd0(
        g_Runtime.EngineHandle,
        &provider,
        NULL);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    RtlZeroMemory(&subLayer, sizeof(subLayer));
    subLayer.subLayerKey = SERPIUM_SFP_SUBLAYER_KEY;
    subLayer.displayData.name =
        L"Serpium SFP Realtime";
    subLayer.displayData.description =
        L"Realtime application flow policy and telemetry";
    subLayer.providerKey = (GUID*)&SERPIUM_SFP_PROVIDER_KEY;
    subLayer.weight = 0x0100;

    status = FwpmSubLayerAdd0(
        g_Runtime.EngineHandle,
        &subLayer,
        NULL);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

#define ADD_CALLOUT_AND_FILTER(calloutKey, layerKey, nameText) \
    status = SerpiumSfpAddManagementCallout(&(calloutKey), &(layerKey), (nameText)); \
    if (!NT_SUCCESS(status)) goto Exit; \
    status = SerpiumSfpAddInspectionFilter(&(calloutKey), &(layerKey), (nameText)); \
    if (!NT_SUCCESS(status)) goto Exit;

    ADD_CALLOUT_AND_FILTER(
        SERPIUM_SFP_AUTH_V4_CALLOUT_KEY,
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        L"Serpium SFP AUTH_CONNECT V4");

    ADD_CALLOUT_AND_FILTER(
        SERPIUM_SFP_AUTH_V6_CALLOUT_KEY,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        L"Serpium SFP AUTH_CONNECT V6");

    ADD_CALLOUT_AND_FILTER(
        SERPIUM_SFP_FLOW_V4_CALLOUT_KEY,
        FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
        L"Serpium SFP FLOW_ESTABLISHED V4");

    ADD_CALLOUT_AND_FILTER(
        SERPIUM_SFP_FLOW_V6_CALLOUT_KEY,
        FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
        L"Serpium SFP FLOW_ESTABLISHED V6");

    status = SerpiumSfpAddManagementCallout(
        &SERPIUM_SFP_REDIRECT_V4_CALLOUT_KEY,
        &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
        L"Serpium SFP CONNECT_REDIRECT V4");

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumSfpAddManagementCallout(
        &SERPIUM_SFP_REDIRECT_V6_CALLOUT_KEY,
        &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
        L"Serpium SFP CONNECT_REDIRECT V6");

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumSfpAddRedirectFilter(
        &SERPIUM_SFP_REDIRECT_V4_CALLOUT_KEY,
        &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
        L"Serpium SFP TCP Redirect V4");

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumSfpAddRedirectFilter(
        &SERPIUM_SFP_REDIRECT_V6_CALLOUT_KEY,
        &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
        L"Serpium SFP TCP Redirect V6");

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

#undef ADD_CALLOUT_AND_FILTER

    status = FwpmTransactionCommit0(
        g_Runtime.EngineHandle);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    transactionStarted = FALSE;
    g_Runtime.Started = TRUE;

    return STATUS_SUCCESS;

Exit:

    if (transactionStarted &&
        g_Runtime.EngineHandle != NULL)
    {
        FwpmTransactionAbort0(g_Runtime.EngineHandle);
    }

    SerpiumSfpStop();

    return status;
}

_Use_decl_annotations_
VOID
SerpiumSfpStop(
    VOID
    )
{
    g_Runtime.Started = FALSE;

    if (g_Runtime.EngineHandle != NULL)
    {
        FwpmEngineClose0(g_Runtime.EngineHandle);
        g_Runtime.EngineHandle = NULL;
    }

    WdfSpinLockAcquire(g_Runtime.BridgeLock);
    g_Runtime.BridgeArmed = FALSE;
    g_Runtime.BridgeProcessId = 0;
    g_Runtime.BridgeListenPortV4 = 0;
    g_Runtime.BridgeListenPortV6 = 0;
    g_Runtime.BridgeBypassProcessCount = 0;
    RtlZeroMemory(
        g_Runtime.BridgeBypassProcessIds,
        sizeof(g_Runtime.BridgeBypassProcessIds));
    WdfSpinLockRelease(g_Runtime.BridgeLock);

    if (g_Runtime.RedirectCalloutIdV6 != 0)
    {
        FwpsCalloutUnregisterById0(
            g_Runtime.RedirectCalloutIdV6);
        g_Runtime.RedirectCalloutIdV6 = 0;
    }

    if (g_Runtime.RedirectCalloutIdV4 != 0)
    {
        FwpsCalloutUnregisterById0(
            g_Runtime.RedirectCalloutIdV4);
        g_Runtime.RedirectCalloutIdV4 = 0;
    }

    if (g_Runtime.RedirectHandle != NULL)
    {
        FwpsRedirectHandleDestroy0(
            g_Runtime.RedirectHandle);
        g_Runtime.RedirectHandle = NULL;
    }

    if (g_Runtime.FlowCalloutIdV6 != 0)
    {
        FwpsCalloutUnregisterById0(g_Runtime.FlowCalloutIdV6);
        g_Runtime.FlowCalloutIdV6 = 0;
    }

    if (g_Runtime.FlowCalloutIdV4 != 0)
    {
        FwpsCalloutUnregisterById0(g_Runtime.FlowCalloutIdV4);
        g_Runtime.FlowCalloutIdV4 = 0;
    }

    if (g_Runtime.AuthCalloutIdV6 != 0)
    {
        FwpsCalloutUnregisterById0(g_Runtime.AuthCalloutIdV6);
        g_Runtime.AuthCalloutIdV6 = 0;
    }

    if (g_Runtime.AuthCalloutIdV4 != 0)
    {
        FwpsCalloutUnregisterById0(g_Runtime.AuthCalloutIdV4);
        g_Runtime.AuthCalloutIdV4 = 0;
    }
}

_Use_decl_annotations_
VOID
SerpiumSfpEvtIoRead(
    WDFQUEUE Queue,
    WDFREQUEST Request,
    size_t Length
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Queue);

    if (Length < sizeof(SERPIUM_SFP_EVENT))
    {
        WdfRequestComplete(
            Request,
            STATUS_BUFFER_TOO_SMALL);

        return;
    }

    status = WdfRequestForwardToIoQueue(
        Request,
        g_Runtime.PendingReadQueue);

    if (!NT_SUCCESS(status))
    {
        WdfRequestComplete(
            Request,
            status);

        return;
    }

    SerpiumSfpTrySatisfyReads();
}

static
NTSTATUS
SerpiumSfpReplacePolicy(
    _In_reads_bytes_(InputSize) const SERPIUM_SFP_POLICY_REPLACE_REQUEST* Request,
    _In_ size_t InputSize
    )
{
    size_t required;
    ULONG outer;
    ULONG inner;
    SERPIUM_SFP_EVENT event;

    if (Request == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (InputSize < FIELD_OFFSET(SERPIUM_SFP_POLICY_REPLACE_REQUEST, Entries))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (Request->ProtocolVersion != SERPIUM_SFP_PROTOCOL_VERSION)
    {
        return STATUS_REVISION_MISMATCH;
    }

    if (Request->EntryCount > SERPIUM_SFP_MAX_POLICY_ENTRIES ||
        !SerpiumSfpRouteIsValid(Request->DefaultRoute))
    {
        return STATUS_INVALID_PARAMETER;
    }

    required =
        FIELD_OFFSET(SERPIUM_SFP_POLICY_REPLACE_REQUEST, Entries) +
        ((size_t)Request->EntryCount * sizeof(SERPIUM_SFP_POLICY_ENTRY));

    if (InputSize < required ||
        Request->Size < required)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    for (outer = 0; outer < Request->EntryCount; outer++)
    {
        if (Request->Entries[outer].AppIdHash == 0 ||
            !SerpiumSfpRouteIsValid(Request->Entries[outer].Route))
        {
            return STATUS_INVALID_PARAMETER;
        }

        for (inner = outer + 1; inner < Request->EntryCount; inner++)
        {
            if (Request->Entries[outer].AppIdHash ==
                Request->Entries[inner].AppIdHash)
            {
                return STATUS_DUPLICATE_NAME;
            }
        }
    }

    WdfSpinLockAcquire(g_Runtime.PolicyLock);

    if (Request->Generation <= g_Runtime.PolicyGeneration)
    {
        WdfSpinLockRelease(g_Runtime.PolicyLock);
        return STATUS_REVISION_MISMATCH;
    }

    if (Request->EntryCount > 0)
    {
        RtlCopyMemory(
            g_Runtime.Policy,
            Request->Entries,
            Request->EntryCount * sizeof(SERPIUM_SFP_POLICY_ENTRY));
    }

    if (Request->EntryCount < SERPIUM_SFP_MAX_POLICY_ENTRIES)
    {
        RtlZeroMemory(
            &g_Runtime.Policy[Request->EntryCount],
            (SERPIUM_SFP_MAX_POLICY_ENTRIES - Request->EntryCount) *
                sizeof(SERPIUM_SFP_POLICY_ENTRY));
    }

    g_Runtime.PolicyCount = Request->EntryCount;
    g_Runtime.DefaultRoute = Request->DefaultRoute;
    g_Runtime.PolicyGeneration = Request->Generation;

    WdfSpinLockRelease(g_Runtime.PolicyLock);

    RtlZeroMemory(&event, sizeof(event));
    event.Size = sizeof(event);
    event.ProtocolVersion = SERPIUM_SFP_PROTOCOL_VERSION;
    event.Type = SERPIUM_SFP_EVENT_POLICY_REPLACED;
    event.PolicyGeneration = Request->Generation;
    event.Route = Request->DefaultRoute;

    SerpiumSfpPushEvent(&event);

    return STATUS_SUCCESS;
}

static
NTSTATUS
SerpiumSfpQueryFlows(
    _Out_writes_bytes_(OutputSize) SERPIUM_SFP_FLOW_QUERY_RESPONSE* Response,
    _In_ size_t OutputSize,
    _Out_ size_t* BytesWritten
    )
{
    ULONG capacity;
    ULONG returned = 0;
    ULONG total = 0;
    PLIST_ENTRY link;

    if (Response == NULL || BytesWritten == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (OutputSize < FIELD_OFFSET(SERPIUM_SFP_FLOW_QUERY_RESPONSE, Flows))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    capacity =
        (ULONG)((OutputSize -
            FIELD_OFFSET(SERPIUM_SFP_FLOW_QUERY_RESPONSE, Flows)) /
            sizeof(SERPIUM_SFP_FLOW_RECORD));

    RtlZeroMemory(Response, OutputSize);

    Response->Size =
        (ULONG)FIELD_OFFSET(SERPIUM_SFP_FLOW_QUERY_RESPONSE, Flows);
    Response->ProtocolVersion =
        SERPIUM_SFP_PROTOCOL_VERSION;

    WdfSpinLockAcquire(g_Runtime.FlowLock);

    total = g_Runtime.ActiveFlowCount;

    for (link = g_Runtime.ActiveFlows.Flink;
         link != &g_Runtime.ActiveFlows;
         link = link->Flink)
    {
        PSERPIUM_SFP_FLOW_CONTEXT context =
            CONTAINING_RECORD(
                link,
                SERPIUM_SFP_FLOW_CONTEXT,
                Link);

        if (returned < capacity)
        {
            PSERPIUM_SFP_FLOW_RECORD flow =
                &Response->Flows[returned];

            flow->FlowId = context->Event.FlowId;
            flow->ProcessId = context->Event.ProcessId;
            flow->AppIdHash = context->Event.AppIdHash;
            flow->PolicyGeneration =
                context->Event.PolicyGeneration;
            flow->Route = context->Event.Route;
            flow->Flags = context->Event.Flags;
            flow->AddressFamily =
                context->Event.AddressFamily;
            flow->Protocol = context->Event.Protocol;
            flow->LocalPort = context->Event.LocalPort;
            flow->RemotePort = context->Event.RemotePort;

            returned++;
        }
    }

    WdfSpinLockRelease(g_Runtime.FlowLock);

    Response->TotalFlowCount = total;
    Response->ReturnedFlowCount = returned;
    Response->Truncated =
        returned < total ? 1u : 0u;

    *BytesWritten =
        FIELD_OFFSET(SERPIUM_SFP_FLOW_QUERY_RESPONSE, Flows) +
        ((size_t)returned * sizeof(SERPIUM_SFP_FLOW_RECORD));

    Response->Size = (ULONG)*BytesWritten;

    return STATUS_SUCCESS;
}

static
NTSTATUS
SerpiumSfpAbortStaleFlows(
    _In_ const SERPIUM_SFP_ABORT_STALE_REQUEST* Request,
    _Out_ PSERPIUM_SFP_ABORT_STALE_RESPONSE Response
    )
{
    PUINT64 flowIds = NULL;
    ULONG count = 0;
    ULONG index;
    PLIST_ENTRY link;

    if (Request == NULL || Response == NULL ||
        Request->Size < sizeof(*Request) ||
        Request->ProtocolVersion != SERPIUM_SFP_PROTOCOL_VERSION ||
        Request->AppIdHash == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    flowIds = (PUINT64)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        SERPIUM_SFP_MAX_ABORT_SNAPSHOT * sizeof(UINT64),
        SERPIUM_SFP_POOL_TAG);

    if (flowIds == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfSpinLockAcquire(g_Runtime.FlowLock);

    for (link = g_Runtime.ActiveFlows.Flink;
         link != &g_Runtime.ActiveFlows &&
         count < SERPIUM_SFP_MAX_ABORT_SNAPSHOT;
         link = link->Flink)
    {
        PSERPIUM_SFP_FLOW_CONTEXT context =
            CONTAINING_RECORD(
                link,
                SERPIUM_SFP_FLOW_CONTEXT,
                Link);

        if (context->Event.AppIdHash == Request->AppIdHash &&
            context->Event.PolicyGeneration < Request->KeepGeneration)
        {
            flowIds[count++] = context->Event.FlowId;
        }
    }

    WdfSpinLockRelease(g_Runtime.FlowLock);

    RtlZeroMemory(Response, sizeof(*Response));
    Response->Size = sizeof(*Response);
    Response->ProtocolVersion =
        SERPIUM_SFP_PROTOCOL_VERSION;
    Response->Matched = count;

    for (index = 0; index < count; index++)
    {
        NTSTATUS abortStatus =
            FwpsFlowAbort0(flowIds[index]);

        if (NT_SUCCESS(abortStatus))
        {
            Response->Aborted++;
        }
        else
        {
            Response->Failed++;
        }
    }

    ExFreePoolWithTag(
        flowIds,
        SERPIUM_SFP_POOL_TAG);

    return STATUS_SUCCESS;
}

static
NTSTATUS
SerpiumSfpConfigureBridge(
    _In_ const SERPIUM_SFP_BRIDGE_CONFIG_REQUEST* Request,
    _Out_ PSERPIUM_SFP_BRIDGE_CONFIG_RESPONSE Response
    )
{
    ULONG index;
    SERPIUM_SFP_EVENT event;

    if (Request == NULL ||
        Response == NULL ||
        Request->Size < sizeof(*Request) ||
        Request->ProtocolVersion != SERPIUM_SFP_PROTOCOL_VERSION ||
        Request->BridgeProcessId == 0 ||
        Request->BridgeProcessId > MAXULONG ||
        Request->BypassProcessCount >
            SERPIUM_SFP_MAX_BYPASS_PROCESSES ||
        (Request->ListenPortV4 == 0 &&
         Request->ListenPortV6 == 0) ||
        Request->ListenPortV4 > MAXUSHORT ||
        Request->ListenPortV6 > MAXUSHORT)
    {
        return STATUS_INVALID_PARAMETER;
    }

    for (index = 0;
         index < Request->BypassProcessCount;
         index++)
    {
        if (Request->BypassProcessIds[index] == 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
    }

    WdfSpinLockAcquire(g_Runtime.BridgeLock);

    g_Runtime.BridgeProcessId =
        Request->BridgeProcessId;
    g_Runtime.BridgeListenPortV4 =
        Request->ListenPortV4;
    g_Runtime.BridgeListenPortV6 =
        Request->ListenPortV6;
    g_Runtime.BridgeBypassProcessCount =
        Request->BypassProcessCount;

    RtlZeroMemory(
        g_Runtime.BridgeBypassProcessIds,
        sizeof(g_Runtime.BridgeBypassProcessIds));

    if (Request->BypassProcessCount > 0)
    {
        RtlCopyMemory(
            g_Runtime.BridgeBypassProcessIds,
            Request->BypassProcessIds,
            Request->BypassProcessCount * sizeof(UINT64));
    }

    g_Runtime.BridgeArmed = TRUE;

    RtlZeroMemory(Response, sizeof(*Response));
    Response->Size = sizeof(*Response);
    Response->ProtocolVersion =
        SERPIUM_SFP_PROTOCOL_VERSION;
    Response->Armed = 1;
    Response->ListenPortV4 =
        g_Runtime.BridgeListenPortV4;
    Response->ListenPortV6 =
        g_Runtime.BridgeListenPortV6;
    Response->BypassProcessCount =
        g_Runtime.BridgeBypassProcessCount;
    Response->BridgeProcessId =
        g_Runtime.BridgeProcessId;
    Response->TotalRedirected =
        g_Runtime.TotalRedirected;
    Response->TotalFailOpen =
        g_Runtime.TotalRedirectFailOpen;

    WdfSpinLockRelease(g_Runtime.BridgeLock);

    RtlZeroMemory(&event, sizeof(event));
    event.Size = sizeof(event);
    event.ProtocolVersion =
        SERPIUM_SFP_PROTOCOL_VERSION;
    event.Type =
        SERPIUM_SFP_EVENT_BRIDGE_CONFIGURED;

    SerpiumSfpPushEvent(&event);

    return STATUS_SUCCESS;
}

static
NTSTATUS
SerpiumSfpDisarmBridge(
    _Out_ PSERPIUM_SFP_BRIDGE_CONFIG_RESPONSE Response
    )
{
    SERPIUM_SFP_EVENT event;

    if (Response == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    WdfSpinLockAcquire(g_Runtime.BridgeLock);

    g_Runtime.BridgeArmed = FALSE;
    g_Runtime.BridgeProcessId = 0;
    g_Runtime.BridgeListenPortV4 = 0;
    g_Runtime.BridgeListenPortV6 = 0;
    g_Runtime.BridgeBypassProcessCount = 0;

    RtlZeroMemory(
        g_Runtime.BridgeBypassProcessIds,
        sizeof(g_Runtime.BridgeBypassProcessIds));

    RtlZeroMemory(Response, sizeof(*Response));
    Response->Size = sizeof(*Response);
    Response->ProtocolVersion =
        SERPIUM_SFP_PROTOCOL_VERSION;
    Response->TotalRedirected =
        g_Runtime.TotalRedirected;
    Response->TotalFailOpen =
        g_Runtime.TotalRedirectFailOpen;

    WdfSpinLockRelease(g_Runtime.BridgeLock);

    RtlZeroMemory(&event, sizeof(event));
    event.Size = sizeof(event);
    event.ProtocolVersion =
        SERPIUM_SFP_PROTOCOL_VERSION;
    event.Type =
        SERPIUM_SFP_EVENT_BRIDGE_DISARMED;

    SerpiumSfpPushEvent(&event);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
SerpiumSfpEvtIoDeviceControl(
    WDFQUEUE Queue,
    WDFREQUEST Request,
    size_t OutputBufferLength,
    size_t InputBufferLength,
    ULONG IoControlCode
    )
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t information = 0;

    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    if (IoControlCode == IOCTL_SERPIUM_SFP_GET_STATUS)
    {
        PSERPIUM_SFP_STATUS output = NULL;
        size_t outputSize = 0;

        status = WdfRequestRetrieveOutputBuffer(
            Request,
            sizeof(*output),
            (PVOID*)&output,
            &outputSize);

        if (NT_SUCCESS(status))
        {
            RtlZeroMemory(output, sizeof(*output));

            output->Size = sizeof(*output);
            output->ProtocolVersion =
                SERPIUM_SFP_PROTOCOL_VERSION;

            output->KernelVersionMajor =
                SERPIUM_SFP_KERNEL_VERSION_MAJOR;
            output->KernelVersionMinor =
                SERPIUM_SFP_KERNEL_VERSION_MINOR;
            output->KernelVersionPatch =
                SERPIUM_SFP_KERNEL_VERSION_PATCH;

            output->Uptime100ns =
                SerpiumSfpNow100ns() -
                g_Runtime.Started100ns;

            output->NextSequence =
                g_Runtime.NextSequence;

            output->TotalEvents =
                g_Runtime.TotalEvents;

            output->DroppedEvents =
                g_Runtime.DroppedEvents;

            WdfSpinLockAcquire(g_Runtime.EventLock);
            output->QueueCount =
                g_Runtime.EventCount;
            WdfSpinLockRelease(g_Runtime.EventLock);

            output->QueueCapacity =
                SERPIUM_SFP_EVENT_QUEUE_CAPACITY;

            WdfSpinLockAcquire(g_Runtime.PolicyLock);
            output->PolicyGeneration =
                g_Runtime.PolicyGeneration;
            output->PolicyCount =
                g_Runtime.PolicyCount;
            output->DefaultRoute =
                g_Runtime.DefaultRoute;
            WdfSpinLockRelease(g_Runtime.PolicyLock);

            WdfSpinLockAcquire(g_Runtime.FlowLock);
            output->ActiveFlowCount =
                g_Runtime.ActiveFlowCount;
            WdfSpinLockRelease(g_Runtime.FlowLock);

            output->AuthCalloutIdV4 =
                g_Runtime.AuthCalloutIdV4;
            output->AuthCalloutIdV6 =
                g_Runtime.AuthCalloutIdV6;
            output->FlowCalloutIdV4 =
                g_Runtime.FlowCalloutIdV4;
            output->FlowCalloutIdV6 =
                g_Runtime.FlowCalloutIdV6;

            output->RedirectCalloutIdV4 =
                g_Runtime.RedirectCalloutIdV4;
            output->RedirectCalloutIdV6 =
                g_Runtime.RedirectCalloutIdV6;

            WdfSpinLockAcquire(g_Runtime.BridgeLock);
            output->BridgeArmed =
                g_Runtime.BridgeArmed ? 1u : 0u;
            output->BridgeListenPortV4 =
                g_Runtime.BridgeListenPortV4;
            output->BridgeListenPortV6 =
                g_Runtime.BridgeListenPortV6;
            output->BridgeBypassProcessCount =
                g_Runtime.BridgeBypassProcessCount;
            output->BridgeProcessId =
                g_Runtime.BridgeProcessId;
            output->TotalRedirected =
                g_Runtime.TotalRedirected;
            output->TotalRedirectFailOpen =
                g_Runtime.TotalRedirectFailOpen;
            WdfSpinLockRelease(g_Runtime.BridgeLock);

            information = sizeof(*output);
        }
    }
    else if (IoControlCode == IOCTL_SERPIUM_SFP_PING)
    {
        PSERPIUM_SFP_PING buffer = NULL;
        size_t bufferSize = 0;

        status = WdfRequestRetrieveInputBuffer(
            Request,
            sizeof(*buffer),
            (PVOID*)&buffer,
            &bufferSize);

        if (NT_SUCCESS(status))
        {
            if (buffer->Size != sizeof(*buffer) ||
                buffer->ProtocolVersion !=
                    SERPIUM_SFP_PROTOCOL_VERSION)
            {
                status = STATUS_REVISION_MISMATCH;
            }
            else
            {
                buffer->KernelTimestamp100ns =
                    SerpiumSfpNow100ns();

                information = sizeof(*buffer);
            }
        }
    }
    else if (IoControlCode == IOCTL_SERPIUM_SFP_REPLACE_POLICY)
    {
        PSERPIUM_SFP_POLICY_REPLACE_REQUEST input = NULL;
        size_t inputSize = 0;

        status = WdfRequestRetrieveInputBuffer(
            Request,
            FIELD_OFFSET(SERPIUM_SFP_POLICY_REPLACE_REQUEST, Entries),
            (PVOID*)&input,
            &inputSize);

        if (NT_SUCCESS(status))
        {
            status =
                SerpiumSfpReplacePolicy(
                    input,
                    inputSize);
        }
    }
    else if (IoControlCode == IOCTL_SERPIUM_SFP_QUERY_FLOWS)
    {
        PSERPIUM_SFP_FLOW_QUERY_RESPONSE output = NULL;
        size_t outputSize = 0;

        status = WdfRequestRetrieveOutputBuffer(
            Request,
            FIELD_OFFSET(SERPIUM_SFP_FLOW_QUERY_RESPONSE, Flows),
            (PVOID*)&output,
            &outputSize);

        if (NT_SUCCESS(status))
        {
            status =
                SerpiumSfpQueryFlows(
                    output,
                    outputSize,
                    &information);
        }
    }
    else if (IoControlCode == IOCTL_SERPIUM_SFP_ABORT_STALE)
    {
        PSERPIUM_SFP_ABORT_STALE_REQUEST input = NULL;
        PSERPIUM_SFP_ABORT_STALE_RESPONSE output = NULL;
        size_t inputSize = 0;
        size_t outputSize = 0;

        status = WdfRequestRetrieveInputBuffer(
            Request,
            sizeof(*input),
            (PVOID*)&input,
            &inputSize);

        if (NT_SUCCESS(status))
        {
            status = WdfRequestRetrieveOutputBuffer(
                Request,
                sizeof(*output),
                (PVOID*)&output,
                &outputSize);
        }

        if (NT_SUCCESS(status))
        {
            status =
                SerpiumSfpAbortStaleFlows(
                    input,
                    output);

            if (NT_SUCCESS(status))
            {
                information = sizeof(*output);
            }
        }
    }
    else if (IoControlCode == IOCTL_SERPIUM_SFP_CONFIGURE_BRIDGE)
    {
        PSERPIUM_SFP_BRIDGE_CONFIG_REQUEST input = NULL;
        PSERPIUM_SFP_BRIDGE_CONFIG_RESPONSE output = NULL;
        size_t inputSize = 0;
        size_t outputSize = 0;

        status = WdfRequestRetrieveInputBuffer(
            Request,
            sizeof(*input),
            (PVOID*)&input,
            &inputSize);

        if (NT_SUCCESS(status))
        {
            status = WdfRequestRetrieveOutputBuffer(
                Request,
                sizeof(*output),
                (PVOID*)&output,
                &outputSize);
        }

        if (NT_SUCCESS(status))
        {
            status =
                SerpiumSfpConfigureBridge(
                    input,
                    output);

            if (NT_SUCCESS(status))
            {
                information = sizeof(*output);
            }
        }
    }
    else if (IoControlCode == IOCTL_SERPIUM_SFP_DISARM_BRIDGE)
    {
        PSERPIUM_SFP_BRIDGE_CONFIG_RESPONSE output = NULL;
        size_t outputSize = 0;

        status = WdfRequestRetrieveOutputBuffer(
            Request,
            sizeof(*output),
            (PVOID*)&output,
            &outputSize);

        if (NT_SUCCESS(status))
        {
            status =
                SerpiumSfpDisarmBridge(
                    output);

            if (NT_SUCCESS(status))
            {
                information = sizeof(*output);
            }
        }
    }

    WdfRequestCompleteWithInformation(
        Request,
        status,
        information);
}

_Use_decl_annotations_
VOID
SerpiumSfpEvtDriverUnload(
    WDFDRIVER Driver
    )
{
    UNREFERENCED_PARAMETER(Driver);

    SerpiumSfpStop();
}

_Use_decl_annotations_
NTSTATUS
SerpiumSfpCreateControlDevice(
    WDFDRIVER Driver
    )
{
    NTSTATUS status;
    PWDFDEVICE_INIT deviceInit;
    WDFDEVICE device;
    WDF_IO_QUEUE_CONFIG defaultQueueConfig;
    WDF_IO_QUEUE_CONFIG pendingQueueConfig;
    WDF_OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLinkName;
    UNICODE_STRING securityDescriptor;

    RtlInitUnicodeString(
        &securityDescriptor,
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    deviceInit = WdfControlDeviceInitAllocate(
        Driver,
        &securityDescriptor);

    if (deviceInit == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetDeviceType(
        deviceInit,
        FILE_DEVICE_UNKNOWN);

    WdfDeviceInitSetExclusive(
        deviceInit,
        FALSE);

    RtlInitUnicodeString(
        &deviceName,
        SERPIUM_SFP_NT_DEVICE_NAME);

    status = WdfDeviceInitAssignName(
        deviceInit,
        &deviceName);

    if (!NT_SUCCESS(status))
    {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);

    status = WdfDeviceCreate(
        &deviceInit,
        &attributes,
        &device);

    if (!NT_SUCCESS(status))
    {
        if (deviceInit != NULL)
        {
            WdfDeviceInitFree(deviceInit);
        }

        return status;
    }

    g_Runtime.Device = device;

    RtlInitUnicodeString(
        &symbolicLinkName,
        SERPIUM_SFP_DOS_DEVICE_NAME);

    status = WdfDeviceCreateSymbolicLink(
        device,
        &symbolicLinkName);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);

    status = WdfSpinLockCreate(
        &attributes,
        &g_Runtime.EventLock);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);

    status = WdfSpinLockCreate(
        &attributes,
        &g_Runtime.PolicyLock);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);

    status = WdfSpinLockCreate(
        &attributes,
        &g_Runtime.FlowLock);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);

    status = WdfSpinLockCreate(
        &attributes,
        &g_Runtime.BridgeLock);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &defaultQueueConfig,
        WdfIoQueueDispatchParallel);

    defaultQueueConfig.EvtIoRead =
        SerpiumSfpEvtIoRead;

    defaultQueueConfig.EvtIoDeviceControl =
        SerpiumSfpEvtIoDeviceControl;

    status = WdfIoQueueCreate(
        device,
        &defaultQueueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        WDF_NO_HANDLE);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT(
        &pendingQueueConfig,
        WdfIoQueueDispatchManual);

    status = WdfIoQueueCreate(
        device,
        &pendingQueueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        &g_Runtime.PendingReadQueue);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = SerpiumSfpStart(
        WdfDeviceWdmGetDeviceObject(device));

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    WdfControlFinishInitializing(device);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDFDRIVER driver;

    SerpiumSfpResetRuntime();

    WDF_DRIVER_CONFIG_INIT(
        &config,
        WDF_NO_EVENT_CALLBACK);

    config.DriverInitFlags |=
        WdfDriverInitNonPnpDriver;

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = NULL;

    config.EvtDriverUnload =
        SerpiumSfpEvtDriverUnload;

    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        &attributes,
        &config,
        &driver);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    return SerpiumSfpCreateControlDevice(driver);
}
