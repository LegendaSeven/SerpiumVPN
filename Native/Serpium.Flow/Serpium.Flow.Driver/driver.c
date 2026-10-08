#include <initguid.h>
#include "driver.h"

static LARGE_INTEGER g_SerpiumFlowStartTime;
static HANDLE g_SerpiumFlowEngineHandle;
static UINT32 g_SerpiumFlowCalloutIdV4;
static UINT32 g_SerpiumFlowCalloutIdV6;
static UINT32 g_SerpiumFlowRedirectCalloutIdV4;
static UINT32 g_SerpiumFlowRedirectCalloutIdV6;
static UINT32 g_SerpiumFlowDatagramCalloutIdV4;
static UINT32 g_SerpiumFlowDatagramCalloutIdV6;
static UINT32 g_SerpiumFlowQuicCalloutIdV4;
static UINT32 g_SerpiumFlowQuicCalloutIdV6;
static HANDLE g_SerpiumFlowRedirectHandle;
static HANDLE g_SerpiumFlowDatagramInjectionHandle;
static BOOLEAN g_SerpiumFlowWfpActive;

#define SERPIUM_FLOW_AF_INET   2u
#define SERPIUM_FLOW_AF_INET6  23u

typedef struct _SERPIUM_FLOW_OBSERVATION_STATE
{
    KSPIN_LOCK Lock;
    ULONG Head;
    ULONG Count;
    ULONGLONG TotalObserved;
    ULONGLONG DroppedObservations;
    SERPIUM_FLOW_OBSERVATION Events[SERPIUM_FLOW_OBSERVATION_QUEUE_CAPACITY];
} SERPIUM_FLOW_OBSERVATION_STATE;

static SERPIUM_FLOW_OBSERVATION_STATE g_SerpiumFlowObservations;

typedef struct _SERPIUM_FLOW_POLICY_STATE
{
    KSPIN_LOCK Lock;
    ULONG Generation;
    ULONG Count;
    ULONGLONG TotalMatches;
    ULONGLONG TotalMisses;
    SERPIUM_FLOW_RULE_ENTRY Rules[SERPIUM_FLOW_RULE_CAPACITY];
} SERPIUM_FLOW_POLICY_STATE;

typedef struct _SERPIUM_FLOW_TABLE_STATE
{
    KSPIN_LOCK Lock;
    ULONG NextIndex;
    ULONG Count;
    ULONGLONG NextFlowId;
    SERPIUM_FLOW_FLOW_ENTRY Entries[SERPIUM_FLOW_FLOW_CAPACITY];
} SERPIUM_FLOW_TABLE_STATE;

static SERPIUM_FLOW_POLICY_STATE g_SerpiumFlowPolicy;
static SERPIUM_FLOW_TABLE_STATE g_SerpiumFlowTable;

typedef struct _SERPIUM_FLOW_ROUTE_STATE
{
    KSPIN_LOCK Lock;
    BOOLEAN Armed;
    BOOLEAN InspectAllTcp;
    BOOLEAN UdpAppRouting;
    BOOLEAN QuicTcpFallback;
    BOOLEAN DomainQuicFallback;
    ULONG ConfigGeneration;
    ULONGLONG LeaseExpiresMilliseconds;
    ULONGLONG BridgeProcessId;
    ULONGLONG RevokedBridgeProcessId;
    ULONG ListenPortV4;
    ULONG ListenPortV6;
    ULONG BypassProcessCount;
    ULONGLONG BypassProcessIds[SERPIUM_FLOW_BYPASS_PID_CAPACITY];
    ULONGLONG TotalRedirected;
    ULONGLONG TotalRedirectFailures;
    ULONGLONG TotalFailOpen;
} SERPIUM_FLOW_ROUTE_STATE;

typedef struct _SERPIUM_FLOW_ROUTE_SNAPSHOT
{
    ULONGLONG BridgeProcessId;
    ULONG ListenPort;
    ULONG ConfigGeneration;
    BOOLEAN InspectAllTcp;
    BOOLEAN UdpAppRouting;
    BOOLEAN QuicTcpFallback;
    BOOLEAN DomainQuicFallback;
} SERPIUM_FLOW_ROUTE_SNAPSHOT;

static SERPIUM_FLOW_ROUTE_STATE g_SerpiumFlowRoute;

#define SERPIUM_FLOW_REDIRECT_POOL_TAG '4pfS'
#define SERPIUM_FLOW_IPPROTO_TCP 6u
#define SERPIUM_FLOW_IPPROTO_UDP 17u

static const GUID SERPIUM_FLOW_SUBLAYER_KEY =
    { 0x72d11755, 0xd81c, 0x45ac, { 0x87, 0x56, 0x26, 0x4d, 0x00, 0x7a, 0xec, 0x99 } };

static const GUID SERPIUM_FLOW_CALLOUT_V4_KEY =
    { 0xa888f069, 0xd145, 0x4677, { 0x92, 0x25, 0x59, 0xc1, 0x10, 0x94, 0x59, 0x07 } };

static const GUID SERPIUM_FLOW_CALLOUT_V6_KEY =
    { 0xbc8b4f0b, 0xeaff, 0x4e69, { 0x9d, 0x91, 0x0c, 0x54, 0x82, 0x90, 0x9f, 0x01 } };

static const GUID SERPIUM_FLOW_PROVIDER_KEY =
    { 0x92d7a805, 0xe1f4, 0x4718, { 0xaf, 0xa8, 0x51, 0x5b, 0x61, 0xa6, 0xcb, 0x3e } };

static const GUID SERPIUM_FLOW_REDIRECT_CALLOUT_V4_KEY =
    { 0xb86e9cb2, 0xfda4, 0x46c8, { 0xa1, 0x0a, 0x4e, 0x6f, 0xcb, 0xf2, 0x22, 0xb2 } };

static const GUID SERPIUM_FLOW_REDIRECT_CALLOUT_V6_KEY =
    { 0x0308df48, 0x39d1, 0x46e4, { 0x91, 0x7f, 0x50, 0xaa, 0xa4, 0xc1, 0xec, 0xf8 } };

static const GUID SERPIUM_FLOW_DATAGRAM_CALLOUT_V4_KEY =
    { 0x0db5f6a1, 0x0f35, 0x47f0, { 0xa5, 0x76, 0x4d, 0x39, 0x6f, 0x75, 0x84, 0x11 } };

static const GUID SERPIUM_FLOW_DATAGRAM_CALLOUT_V6_KEY =
    { 0x57fbf2ce, 0xb2aa, 0x44df, { 0x9e, 0x4a, 0x25, 0x57, 0xf6, 0x02, 0x5d, 0xc4 } };

static const GUID SERPIUM_FLOW_QUIC_CALLOUT_V4_KEY =
    { 0x9a123dc8, 0x87aa, 0x46cb, { 0x97, 0x61, 0x18, 0x0f, 0x2b, 0x61, 0xd4, 0x4d } };

static const GUID SERPIUM_FLOW_QUIC_CALLOUT_V6_KEY =
    { 0x1e93c8c5, 0x13f9, 0x41d3, { 0x8d, 0x0e, 0x52, 0x0d, 0xef, 0xe8, 0xaf, 0xa9 } };

static
ULONGLONG
SerpiumFlowQueryMilliseconds(
    VOID
    )
{
    LARGE_INTEGER now;

    KeQuerySystemTimePrecise(&now);

    if (now.QuadPart <= g_SerpiumFlowStartTime.QuadPart)
    {
        return 0;
    }

    return (ULONGLONG)(
        (now.QuadPart - g_SerpiumFlowStartTime.QuadPart) / 10000
        );
}

static
VOID
SerpiumFlowResetObservationQueue(
    VOID
    )
{
    RtlZeroMemory(
        &g_SerpiumFlowObservations,
        sizeof(g_SerpiumFlowObservations)
        );

    KeInitializeSpinLock(&g_SerpiumFlowObservations.Lock);
}

static
VOID
SerpiumFlowResetPolicyState(
    VOID
    )
{
    RtlZeroMemory(
        &g_SerpiumFlowPolicy,
        sizeof(g_SerpiumFlowPolicy)
        );
    RtlZeroMemory(
        &g_SerpiumFlowTable,
        sizeof(g_SerpiumFlowTable)
        );

    KeInitializeSpinLock(&g_SerpiumFlowPolicy.Lock);
    KeInitializeSpinLock(&g_SerpiumFlowTable.Lock);
    g_SerpiumFlowPolicy.Generation = 1;
}

static
VOID
SerpiumFlowResetRouteState(
    VOID
    )
{
    RtlZeroMemory(
        &g_SerpiumFlowRoute,
        sizeof(g_SerpiumFlowRoute)
        );

    KeInitializeSpinLock(&g_SerpiumFlowRoute.Lock);
    g_SerpiumFlowRoute.ConfigGeneration = 1;
}

static
VOID
SerpiumFlowQueueObservation(
    _Inout_ PSERPIUM_FLOW_OBSERVATION Observation
    )
{
    KIRQL oldIrql;
    ULONG index;

    KeAcquireSpinLock(
        &g_SerpiumFlowObservations.Lock,
        &oldIrql
        );

    g_SerpiumFlowObservations.TotalObserved++;
    Observation->Sequence = g_SerpiumFlowObservations.TotalObserved;

    index = g_SerpiumFlowObservations.Head;
    g_SerpiumFlowObservations.Events[index] = *Observation;
    g_SerpiumFlowObservations.Head =
        (index + 1) % SERPIUM_FLOW_OBSERVATION_QUEUE_CAPACITY;

    if (
        g_SerpiumFlowObservations.Count <
        SERPIUM_FLOW_OBSERVATION_QUEUE_CAPACITY
        )
    {
        g_SerpiumFlowObservations.Count++;
    }
    else
    {
        g_SerpiumFlowObservations.DroppedObservations++;
    }

    KeReleaseSpinLock(
        &g_SerpiumFlowObservations.Lock,
        oldIrql
        );
}

static
BOOLEAN
SerpiumFlowAppIdsEqual(
    _In_reads_bytes_(LeftByteLength) const unsigned short* Left,
    _In_ ULONG LeftByteLength,
    _In_reads_bytes_(RightByteLength) const unsigned short* Right,
    _In_ ULONG RightByteLength
    )
{
    if (
        LeftByteLength == 0 ||
        LeftByteLength != RightByteLength ||
        LeftByteLength > SERPIUM_FLOW_APP_ID_MAX_BYTES
        )
    {
        return FALSE;
    }

    return
        RtlCompareMemory(
            Left,
            Right,
            LeftByteLength
            ) == LeftByteLength;
}

static
VOID
SerpiumFlowMatchPolicy(
    _Inout_ PSERPIUM_FLOW_OBSERVATION Observation
    )
{
    KIRQL oldIrql;
    ULONG index;

    KeAcquireSpinLock(
        &g_SerpiumFlowPolicy.Lock,
        &oldIrql
        );

    Observation->PolicyGeneration = g_SerpiumFlowPolicy.Generation;
    Observation->Route =
        g_SerpiumFlowPolicy.Count == 0
            ? SERPIUM_FLOW_ROUTE_VPN
            : SERPIUM_FLOW_ROUTE_DIRECT;
    Observation->RuleId = 0;

    for (index = 0; index < g_SerpiumFlowPolicy.Count; index++)
    {
        const SERPIUM_FLOW_RULE_ENTRY* rule =
            &g_SerpiumFlowPolicy.Rules[index];

        if (
            SerpiumFlowAppIdsEqual(
                rule->AppId,
                rule->AppIdByteLength,
                Observation->AppId,
                Observation->AppIdByteLength
                )
            )
        {
            Observation->Route = rule->Route;
            Observation->RuleId = rule->RuleId;
            Observation->Flags |=
                SERPIUM_FLOW_OBSERVATION_FLAG_POLICY_MATCH;
            g_SerpiumFlowPolicy.TotalMatches++;
            break;
        }
    }

    if (
        (Observation->Flags &
         SERPIUM_FLOW_OBSERVATION_FLAG_POLICY_MATCH) == 0
        )
    {
        g_SerpiumFlowPolicy.TotalMisses++;
    }

    KeReleaseSpinLock(
        &g_SerpiumFlowPolicy.Lock,
        oldIrql
        );
}

#define SERPIUM_FLOW_ROUTE_SNAPSHOT_READY       0u
#define SERPIUM_FLOW_ROUTE_SNAPSHOT_BYPASS      1u
#define SERPIUM_FLOW_ROUTE_SNAPSHOT_UNAVAILABLE 2u

static
VOID
SerpiumFlowResolveRouteForAppId(
    _In_reads_bytes_opt_(AppIdByteLength) const unsigned short* AppId,
    _In_ ULONG AppIdByteLength,
    _Out_ ULONG* Route,
    _Out_ ULONGLONG* RuleId,
    _Out_ ULONG* PolicyGeneration
    )
{
    KIRQL oldIrql;
    ULONG index;

    *Route = SERPIUM_FLOW_ROUTE_DIRECT;
    *RuleId = 0;
    *PolicyGeneration = 0;

    KeAcquireSpinLock(
        &g_SerpiumFlowPolicy.Lock,
        &oldIrql
        );

    *PolicyGeneration = g_SerpiumFlowPolicy.Generation;
    *Route =
        g_SerpiumFlowPolicy.Count == 0
            ? SERPIUM_FLOW_ROUTE_VPN
            : SERPIUM_FLOW_ROUTE_DIRECT;

    for (index = 0; index < g_SerpiumFlowPolicy.Count; index++)
    {
        const SERPIUM_FLOW_RULE_ENTRY* rule =
            &g_SerpiumFlowPolicy.Rules[index];

        if (
            SerpiumFlowAppIdsEqual(
                rule->AppId,
                rule->AppIdByteLength,
                AppId,
                AppIdByteLength
                )
            )
        {
            *Route = rule->Route;
            *RuleId = rule->RuleId;
            break;
        }
    }

    KeReleaseSpinLock(
        &g_SerpiumFlowPolicy.Lock,
        oldIrql
        );
}

static
ULONG
SerpiumFlowGetRouteSnapshot(
    _In_ ULONGLONG ProcessId,
    _In_ USHORT AddressFamily,
    _Out_ SERPIUM_FLOW_ROUTE_SNAPSHOT* Snapshot
    )
{
    KIRQL oldIrql;
    ULONGLONG now = SerpiumFlowQueryMilliseconds();
    ULONG index;
    ULONG result = SERPIUM_FLOW_ROUTE_SNAPSHOT_UNAVAILABLE;

    RtlZeroMemory(Snapshot, sizeof(*Snapshot));

    KeAcquireSpinLock(
        &g_SerpiumFlowRoute.Lock,
        &oldIrql
        );

    if (g_SerpiumFlowRoute.Armed)
    {
        Snapshot->BridgeProcessId =
            g_SerpiumFlowRoute.BridgeProcessId;
        Snapshot->ListenPort =
            AddressFamily == SERPIUM_FLOW_AF_INET
                ? g_SerpiumFlowRoute.ListenPortV4
                : g_SerpiumFlowRoute.ListenPortV6;
        Snapshot->ConfigGeneration =
            g_SerpiumFlowRoute.ConfigGeneration;
        Snapshot->InspectAllTcp = g_SerpiumFlowRoute.InspectAllTcp;
        Snapshot->UdpAppRouting = g_SerpiumFlowRoute.UdpAppRouting;
        Snapshot->QuicTcpFallback = g_SerpiumFlowRoute.QuicTcpFallback;
        Snapshot->DomainQuicFallback = g_SerpiumFlowRoute.DomainQuicFallback;
    }

    if (
        !g_SerpiumFlowRoute.Armed ||
        g_SerpiumFlowRoute.LeaseExpiresMilliseconds <= now
        )
    {
        result = SERPIUM_FLOW_ROUTE_SNAPSHOT_UNAVAILABLE;
    }
    else if (ProcessId == g_SerpiumFlowRoute.BridgeProcessId)
    {
        result = SERPIUM_FLOW_ROUTE_SNAPSHOT_BYPASS;
    }
    else
    {
        for (
            index = 0;
            index < g_SerpiumFlowRoute.BypassProcessCount;
            index++
            )
        {
            if (ProcessId == g_SerpiumFlowRoute.BypassProcessIds[index])
            {
                result = SERPIUM_FLOW_ROUTE_SNAPSHOT_BYPASS;
                break;
            }
        }

        if (index == g_SerpiumFlowRoute.BypassProcessCount)
        {
            result =
                Snapshot->ListenPort > 0 &&
                Snapshot->ListenPort <= 65535
                    ? SERPIUM_FLOW_ROUTE_SNAPSHOT_READY
                    : SERPIUM_FLOW_ROUTE_SNAPSHOT_UNAVAILABLE;
        }
    }

    KeReleaseSpinLock(
        &g_SerpiumFlowRoute.Lock,
        oldIrql
        );

    return result;
}

static
VOID
SerpiumFlowRecordRouteResult(
    _In_ BOOLEAN Redirected,
    _In_ BOOLEAN RedirectFailure,
    _In_ BOOLEAN FailOpen
    )
{
    KIRQL oldIrql;

    KeAcquireSpinLock(
        &g_SerpiumFlowRoute.Lock,
        &oldIrql
        );

    if (Redirected)
    {
        g_SerpiumFlowRoute.TotalRedirected++;
    }

    if (RedirectFailure)
    {
        g_SerpiumFlowRoute.TotalRedirectFailures++;
    }

    if (FailOpen)
    {
        g_SerpiumFlowRoute.TotalFailOpen++;
    }

    KeReleaseSpinLock(
        &g_SerpiumFlowRoute.Lock,
        oldIrql
        );
}

static
VOID
SerpiumFlowAdvanceRouteGenerationLocked(
    VOID
    )
{
    g_SerpiumFlowRoute.ConfigGeneration++;

    if (g_SerpiumFlowRoute.ConfigGeneration == 0)
    {
        g_SerpiumFlowRoute.ConfigGeneration = 1;
    }
}

static
VOID
SerpiumFlowFillRouteConfigResult(
    _Out_ PSERPIUM_FLOW_ROUTE_CONFIG_RESULT Result,
    _In_ BOOLEAN Changed
    )
{
    KIRQL oldIrql;
    ULONGLONG now = SerpiumFlowQueryMilliseconds();
    ULONGLONG remaining = 0;

    RtlZeroMemory(Result, sizeof(*Result));
    Result->Size = sizeof(*Result);
    Result->ProtocolVersion = SERPIUM_FLOW_PROTOCOL_VERSION;

    KeAcquireSpinLock(
        &g_SerpiumFlowRoute.Lock,
        &oldIrql
        );

    if (Changed)
    {
        Result->Flags |= SERPIUM_FLOW_ROUTE_CONFIG_FLAG_CHANGED;
    }

    if (
        g_SerpiumFlowRoute.Armed &&
        g_SerpiumFlowRoute.LeaseExpiresMilliseconds > now
        )
    {
        remaining =
            g_SerpiumFlowRoute.LeaseExpiresMilliseconds - now;
        Result->Flags |=
            SERPIUM_FLOW_ROUTE_CONFIG_FLAG_ARM |
            SERPIUM_FLOW_ROUTE_CONFIG_FLAG_LEASE_ACTIVE;

        if (g_SerpiumFlowRoute.InspectAllTcp)
        {
            Result->Flags |=
                SERPIUM_FLOW_ROUTE_CONFIG_FLAG_INSPECT_ALL_TCP;
        }

        if (g_SerpiumFlowRoute.UdpAppRouting)
        {
            Result->Flags |=
                SERPIUM_FLOW_ROUTE_CONFIG_FLAG_UDP_APP_ROUTING;
        }

        if (g_SerpiumFlowRoute.QuicTcpFallback)
        {
            Result->Flags |=
                SERPIUM_FLOW_ROUTE_CONFIG_FLAG_QUIC_TCP_FALLBACK;
        }

        if (g_SerpiumFlowRoute.DomainQuicFallback)
        {
            Result->Flags |=
                SERPIUM_FLOW_ROUTE_CONFIG_FLAG_DOMAIN_QUIC_FALLBACK;
        }
    }

    Result->ConfigGeneration = g_SerpiumFlowRoute.ConfigGeneration;
    Result->LeaseRemainingMilliseconds =
        remaining > MAXULONG ? MAXULONG : (ULONG)remaining;
    Result->ListenPortV4 = g_SerpiumFlowRoute.ListenPortV4;
    Result->ListenPortV6 = g_SerpiumFlowRoute.ListenPortV6;
    Result->BypassProcessCount =
        g_SerpiumFlowRoute.BypassProcessCount;
    Result->BridgeProcessId = g_SerpiumFlowRoute.BridgeProcessId;
    Result->TotalRedirected = g_SerpiumFlowRoute.TotalRedirected;
    Result->TotalRedirectFailures =
        g_SerpiumFlowRoute.TotalRedirectFailures;
    Result->TotalFailOpen = g_SerpiumFlowRoute.TotalFailOpen;

    KeReleaseSpinLock(
        &g_SerpiumFlowRoute.Lock,
        oldIrql
        );
}

static
NTSTATUS
SerpiumFlowConfigureRoute(
    _In_ const SERPIUM_FLOW_ROUTE_CONFIG_REQUEST* Request,
    _Out_ BOOLEAN* Changed
    )
{
    KIRQL oldIrql;
    ULONG index;
    ULONG compareIndex;
    ULONGLONG now = SerpiumFlowQueryMilliseconds();

    *Changed = FALSE;

    if (
        Request->Size != sizeof(*Request) ||
        Request->ProtocolVersion != SERPIUM_FLOW_PROTOCOL_VERSION ||
        (Request->Flags & SERPIUM_FLOW_ROUTE_CONFIG_FLAG_ARM) == 0 ||
        (Request->Flags &
         ~(SERPIUM_FLOW_ROUTE_CONFIG_FLAG_ARM |
           SERPIUM_FLOW_ROUTE_CONFIG_FLAG_INSPECT_ALL_TCP |
           SERPIUM_FLOW_ROUTE_CONFIG_FLAG_UDP_APP_ROUTING |
           SERPIUM_FLOW_ROUTE_CONFIG_FLAG_QUIC_TCP_FALLBACK |
           SERPIUM_FLOW_ROUTE_CONFIG_FLAG_DOMAIN_QUIC_FALLBACK)) != 0 ||
        Request->LeaseMilliseconds <
            SERPIUM_FLOW_ROUTE_LEASE_MIN_MILLISECONDS ||
        Request->LeaseMilliseconds >
            SERPIUM_FLOW_ROUTE_LEASE_MAX_MILLISECONDS ||
        Request->BridgeProcessId == 0 ||
        Request->BridgeProcessId > MAXULONG ||
        Request->ListenPortV4 == 0 ||
        Request->ListenPortV4 > 65535 ||
        Request->ListenPortV6 == 0 ||
        Request->ListenPortV6 > 65535 ||
        Request->BypassProcessCount == 0 ||
        Request->BypassProcessCount > SERPIUM_FLOW_BYPASS_PID_CAPACITY
        )
    {
        return STATUS_INVALID_PARAMETER;
    }

    for (index = 0; index < Request->BypassProcessCount; index++)
    {
        if (
            Request->BypassProcessIds[index] == 0 ||
            Request->BypassProcessIds[index] > MAXULONG ||
            Request->BypassProcessIds[index] ==
                Request->BridgeProcessId
            )
        {
            return STATUS_INVALID_PARAMETER;
        }

        for (compareIndex = 0; compareIndex < index; compareIndex++)
        {
            if (
                Request->BypassProcessIds[index] ==
                Request->BypassProcessIds[compareIndex]
                )
            {
                return STATUS_INVALID_PARAMETER;
            }
        }
    }

    KeAcquireSpinLock(
        &g_SerpiumFlowRoute.Lock,
        &oldIrql
        );

    if (
        g_SerpiumFlowRoute.RevokedBridgeProcessId ==
        Request->BridgeProcessId
        )
    {
        KeReleaseSpinLock(
            &g_SerpiumFlowRoute.Lock,
            oldIrql
            );
        return STATUS_ACCESS_DENIED;
    }

    if (
        g_SerpiumFlowRoute.Armed &&
        g_SerpiumFlowRoute.LeaseExpiresMilliseconds > now &&
        g_SerpiumFlowRoute.BridgeProcessId !=
            Request->BridgeProcessId
        )
    {
        KeReleaseSpinLock(
            &g_SerpiumFlowRoute.Lock,
            oldIrql
            );
        return STATUS_DEVICE_BUSY;
    }

    *Changed =
        !g_SerpiumFlowRoute.Armed ||
        g_SerpiumFlowRoute.BridgeProcessId !=
            Request->BridgeProcessId ||
        g_SerpiumFlowRoute.ListenPortV4 != Request->ListenPortV4 ||
        g_SerpiumFlowRoute.ListenPortV6 != Request->ListenPortV6 ||
        g_SerpiumFlowRoute.InspectAllTcp !=
            ((Request->Flags & SERPIUM_FLOW_ROUTE_CONFIG_FLAG_INSPECT_ALL_TCP) != 0) ||
        g_SerpiumFlowRoute.UdpAppRouting !=
            ((Request->Flags & SERPIUM_FLOW_ROUTE_CONFIG_FLAG_UDP_APP_ROUTING) != 0) ||
        g_SerpiumFlowRoute.QuicTcpFallback !=
            ((Request->Flags & SERPIUM_FLOW_ROUTE_CONFIG_FLAG_QUIC_TCP_FALLBACK) != 0) ||
        g_SerpiumFlowRoute.DomainQuicFallback !=
            ((Request->Flags & SERPIUM_FLOW_ROUTE_CONFIG_FLAG_DOMAIN_QUIC_FALLBACK) != 0) ||
        g_SerpiumFlowRoute.BypassProcessCount !=
            Request->BypassProcessCount ||
        RtlCompareMemory(
            g_SerpiumFlowRoute.BypassProcessIds,
            Request->BypassProcessIds,
            Request->BypassProcessCount * sizeof(ULONGLONG)
            ) != Request->BypassProcessCount * sizeof(ULONGLONG);

    if (*Changed)
    {
        SerpiumFlowAdvanceRouteGenerationLocked();
    }

    g_SerpiumFlowRoute.Armed = TRUE;
    g_SerpiumFlowRoute.InspectAllTcp =
        (Request->Flags & SERPIUM_FLOW_ROUTE_CONFIG_FLAG_INSPECT_ALL_TCP) != 0;
    g_SerpiumFlowRoute.UdpAppRouting =
        (Request->Flags & SERPIUM_FLOW_ROUTE_CONFIG_FLAG_UDP_APP_ROUTING) != 0;
    g_SerpiumFlowRoute.QuicTcpFallback =
        (Request->Flags & SERPIUM_FLOW_ROUTE_CONFIG_FLAG_QUIC_TCP_FALLBACK) != 0;
    g_SerpiumFlowRoute.DomainQuicFallback =
        (Request->Flags & SERPIUM_FLOW_ROUTE_CONFIG_FLAG_DOMAIN_QUIC_FALLBACK) != 0;
    g_SerpiumFlowRoute.BridgeProcessId = Request->BridgeProcessId;
    g_SerpiumFlowRoute.ListenPortV4 = Request->ListenPortV4;
    g_SerpiumFlowRoute.ListenPortV6 = Request->ListenPortV6;
    g_SerpiumFlowRoute.BypassProcessCount =
        Request->BypassProcessCount;
    RtlZeroMemory(
        g_SerpiumFlowRoute.BypassProcessIds,
        sizeof(g_SerpiumFlowRoute.BypassProcessIds)
        );
    RtlCopyMemory(
        g_SerpiumFlowRoute.BypassProcessIds,
        Request->BypassProcessIds,
        Request->BypassProcessCount * sizeof(ULONGLONG)
        );
    g_SerpiumFlowRoute.LeaseExpiresMilliseconds =
        now + Request->LeaseMilliseconds;

    KeReleaseSpinLock(
        &g_SerpiumFlowRoute.Lock,
        oldIrql
        );

    return STATUS_SUCCESS;
}

static
VOID
SerpiumFlowDisarmRoute(
    _Out_ BOOLEAN* Changed
    )
{
    KIRQL oldIrql;

    KeAcquireSpinLock(
        &g_SerpiumFlowRoute.Lock,
        &oldIrql
        );

    *Changed = g_SerpiumFlowRoute.Armed;

    if (*Changed)
    {
        g_SerpiumFlowRoute.RevokedBridgeProcessId =
            g_SerpiumFlowRoute.BridgeProcessId;
        SerpiumFlowAdvanceRouteGenerationLocked();
    }

    g_SerpiumFlowRoute.Armed = FALSE;
    g_SerpiumFlowRoute.InspectAllTcp = FALSE;
    g_SerpiumFlowRoute.UdpAppRouting = FALSE;
    g_SerpiumFlowRoute.QuicTcpFallback = FALSE;
    g_SerpiumFlowRoute.DomainQuicFallback = FALSE;
    g_SerpiumFlowRoute.LeaseExpiresMilliseconds = 0;
    g_SerpiumFlowRoute.BridgeProcessId = 0;
    g_SerpiumFlowRoute.ListenPortV4 = 0;
    g_SerpiumFlowRoute.ListenPortV6 = 0;
    g_SerpiumFlowRoute.BypassProcessCount = 0;
    RtlZeroMemory(
        g_SerpiumFlowRoute.BypassProcessIds,
        sizeof(g_SerpiumFlowRoute.BypassProcessIds)
        );

    KeReleaseSpinLock(
        &g_SerpiumFlowRoute.Lock,
        oldIrql
        );
}

static
BOOLEAN
SerpiumFlowEntriesMatch(
    _In_ const SERPIUM_FLOW_FLOW_ENTRY* Entry,
    _In_ const SERPIUM_FLOW_OBSERVATION* Observation
    )
{
    ULONG addressLength =
        Observation->AddressFamily == SERPIUM_FLOW_AF_INET6
            ? 16u
            : 4u;

    return
        Entry->ProcessId == Observation->ProcessId &&
        Entry->Layer == Observation->Layer &&
        Entry->Protocol == Observation->Protocol &&
        Entry->LocalPort == Observation->LocalPort &&
        Entry->RemotePort == Observation->RemotePort &&
        Entry->AddressFamily == Observation->AddressFamily &&
        RtlCompareMemory(
            Entry->RemoteAddress,
            Observation->RemoteAddress,
            addressLength
            ) == addressLength &&
        SerpiumFlowAppIdsEqual(
            Entry->AppId,
            Entry->AppIdByteLength,
            Observation->AppId,
            Observation->AppIdByteLength
            );
}

static
VOID
SerpiumFlowRecordObservedFlow(
    _In_ const SERPIUM_FLOW_OBSERVATION* Observation
    )
{
    KIRQL oldIrql;
    ULONG logicalIndex;
    ULONG physicalIndex;
    ULONG oldestIndex;
    PSERPIUM_FLOW_FLOW_ENTRY entry;

    KeAcquireSpinLock(
        &g_SerpiumFlowTable.Lock,
        &oldIrql
        );

    oldestIndex =
        g_SerpiumFlowTable.Count < SERPIUM_FLOW_FLOW_CAPACITY
            ? 0u
            : g_SerpiumFlowTable.NextIndex;

    for (
        logicalIndex = 0;
        logicalIndex < g_SerpiumFlowTable.Count;
        logicalIndex++
        )
    {
        physicalIndex =
            (oldestIndex + logicalIndex) %
            SERPIUM_FLOW_FLOW_CAPACITY;
        entry = &g_SerpiumFlowTable.Entries[physicalIndex];

        if (SerpiumFlowEntriesMatch(entry, Observation))
        {
            entry->LastSeenMilliseconds =
                Observation->TimestampMilliseconds;
            entry->ObservationCount++;
            KeReleaseSpinLock(
                &g_SerpiumFlowTable.Lock,
                oldIrql
                );
            return;
        }
    }

    physicalIndex = g_SerpiumFlowTable.NextIndex;
    entry = &g_SerpiumFlowTable.Entries[physicalIndex];
    RtlZeroMemory(entry, sizeof(*entry));

    g_SerpiumFlowTable.NextFlowId++;
    if (g_SerpiumFlowTable.NextFlowId == 0)
    {
        g_SerpiumFlowTable.NextFlowId++;
    }

    entry->Size = sizeof(*entry);
    entry->ProtocolVersion = SERPIUM_FLOW_PROTOCOL_VERSION;
    entry->FlowId = g_SerpiumFlowTable.NextFlowId;
    entry->FirstSeenMilliseconds = Observation->TimestampMilliseconds;
    entry->LastSeenMilliseconds = Observation->TimestampMilliseconds;
    entry->ObservationCount = 1;
    entry->ProcessId = Observation->ProcessId;
    entry->RuleId = Observation->RuleId;
    entry->PolicyGeneration = Observation->PolicyGeneration;
    entry->Layer = Observation->Layer;
    entry->AddressFamily = Observation->AddressFamily;
    entry->Protocol = Observation->Protocol;
    entry->Flags = Observation->Flags;
    entry->LocalPort = Observation->LocalPort;
    entry->RemotePort = Observation->RemotePort;
    entry->Route = Observation->Route;
    entry->AppIdByteLength = Observation->AppIdByteLength;

    RtlCopyMemory(
        entry->RemoteAddress,
        Observation->RemoteAddress,
        sizeof(entry->RemoteAddress)
        );

    if (Observation->AppIdByteLength > 0)
    {
        RtlCopyMemory(
            entry->AppId,
            Observation->AppId,
            Observation->AppIdByteLength
            );
    }

    g_SerpiumFlowTable.NextIndex =
        (physicalIndex + 1) % SERPIUM_FLOW_FLOW_CAPACITY;

    if (g_SerpiumFlowTable.Count < SERPIUM_FLOW_FLOW_CAPACITY)
    {
        g_SerpiumFlowTable.Count++;
    }

    KeReleaseSpinLock(
        &g_SerpiumFlowTable.Lock,
        oldIrql
        );
}

static
VOID
SerpiumFlowCaptureObservation(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _In_ USHORT AddressFamily
    )
{
    SERPIUM_FLOW_OBSERVATION observation;
    const FWP_BYTE_BLOB* appId;
    const FWP_VALUE0* appIdValue;
    ULONG appIdBytes;
    ULONG appIdIndex;
    UINT32 addressV4;
    const FWP_BYTE_ARRAY16* addressV6;

    if (InFixedValues == NULL || InMetaValues == NULL)
    {
        return;
    }

    RtlZeroMemory(&observation, sizeof(observation));

    observation.Size = sizeof(observation);
    observation.ProtocolVersion = SERPIUM_FLOW_PROTOCOL_VERSION;
    observation.TimestampMilliseconds = SerpiumFlowQueryMilliseconds();
    observation.AddressFamily = (unsigned short)AddressFamily;

    if (
        (InMetaValues->currentMetadataValues &
         FWPS_METADATA_FIELD_PROCESS_ID) != 0
        )
    {
        observation.ProcessId = InMetaValues->processId;
        observation.Flags |=
            SERPIUM_FLOW_OBSERVATION_FLAG_PROCESS_ID_PRESENT;
    }

    if (AddressFamily == SERPIUM_FLOW_AF_INET)
    {
        observation.Layer = SERPIUM_FLOW_LAYER_ALE_AUTH_CONNECT_V4;
        observation.Protocol =
            InFixedValues->incomingValue[
                FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL
                ].value.uint8;
        observation.LocalPort =
            InFixedValues->incomingValue[
                FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT
                ].value.uint16;
        observation.RemotePort =
            InFixedValues->incomingValue[
                FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT
                ].value.uint16;

        addressV4 =
            InFixedValues->incomingValue[
                FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS
                ].value.uint32;

        observation.RemoteAddress[0] = (UCHAR)(addressV4 >> 24);
        observation.RemoteAddress[1] = (UCHAR)(addressV4 >> 16);
        observation.RemoteAddress[2] = (UCHAR)(addressV4 >> 8);
        observation.RemoteAddress[3] = (UCHAR)addressV4;

        appIdIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID;
    }
    else
    {
        observation.Layer = SERPIUM_FLOW_LAYER_ALE_AUTH_CONNECT_V6;
        observation.Flags |= SERPIUM_FLOW_OBSERVATION_FLAG_IPV6;
        observation.Protocol =
            InFixedValues->incomingValue[
                FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL
                ].value.uint8;
        observation.LocalPort =
            InFixedValues->incomingValue[
                FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT
                ].value.uint16;
        observation.RemotePort =
            InFixedValues->incomingValue[
                FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT
                ].value.uint16;

        addressV6 =
            InFixedValues->incomingValue[
                FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS
                ].value.byteArray16;

        if (addressV6 != NULL)
        {
            RtlCopyMemory(
                observation.RemoteAddress,
                addressV6->byteArray16,
                sizeof(observation.RemoteAddress)
                );
        }

        appIdIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID;
    }

    appIdValue = &InFixedValues->incomingValue[appIdIndex].value;
    appId =
        appIdValue->type == FWP_BYTE_BLOB_TYPE
            ? appIdValue->byteBlob
            : NULL;

    if (appId != NULL && appId->data != NULL && appId->size > 0)
    {
        appIdBytes = appId->size;

        if (
            appIdBytes >
            ((SERPIUM_FLOW_APP_ID_MAX_CHARS - 1) * sizeof(unsigned short))
            )
        {
            appIdBytes =
                (SERPIUM_FLOW_APP_ID_MAX_CHARS - 1) *
                sizeof(unsigned short);
        }

        appIdBytes &= ~1u;

        if (appIdBytes > 0)
        {
            RtlCopyMemory(
                observation.AppId,
                appId->data,
                appIdBytes
                );

            observation.AppId[appIdBytes / sizeof(unsigned short)] = 0;
            observation.AppIdByteLength = appIdBytes;
            observation.Flags |=
                SERPIUM_FLOW_OBSERVATION_FLAG_APP_ID_PRESENT;
        }
    }

    SerpiumFlowMatchPolicy(&observation);

    if (observation.Route == SERPIUM_FLOW_ROUTE_VPN)
    {
        SERPIUM_FLOW_ROUTE_SNAPSHOT snapshot = {0};
        ULONG snapshotResult =
            (observation.Flags &
             SERPIUM_FLOW_OBSERVATION_FLAG_PROCESS_ID_PRESENT) != 0
                ? SerpiumFlowGetRouteSnapshot(
                    observation.ProcessId,
                    observation.AddressFamily,
                    &snapshot
                    )
                : SERPIUM_FLOW_ROUTE_SNAPSHOT_UNAVAILABLE;

        if (
            (InMetaValues->currentMetadataValues &
             FWPS_METADATA_FIELD_LOCAL_REDIRECT_TARGET_PID) != 0 &&
            InMetaValues->localRedirectTargetPID != 0 &&
            snapshot.BridgeProcessId != 0 &&
            InMetaValues->localRedirectTargetPID ==
                snapshot.BridgeProcessId
            )
        {
            observation.Flags |=
                SERPIUM_FLOW_OBSERVATION_FLAG_ROUTE_REDIRECTED;
        }
        else
        {
            observation.Route = SERPIUM_FLOW_ROUTE_DIRECT;

            if (snapshotResult != SERPIUM_FLOW_ROUTE_SNAPSHOT_BYPASS)
            {
                observation.Flags |=
                    SERPIUM_FLOW_OBSERVATION_FLAG_ROUTE_FAIL_OPEN;
            }
        }
    }

    SerpiumFlowRecordObservedFlow(&observation);
    SerpiumFlowQueueObservation(&observation);
}

_Use_decl_annotations_
VOID
NTAPI
SerpiumFlowClassifyV4(
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
    UNREFERENCED_PARAMETER(FlowContext);

    if (ClassifyOut != NULL)
    {
        ClassifyOut->actionType = FWP_ACTION_CONTINUE;
    }

    SerpiumFlowCaptureObservation(
        InFixedValues,
        InMetaValues,
        SERPIUM_FLOW_AF_INET
        );
}

_Use_decl_annotations_
VOID
NTAPI
SerpiumFlowClassifyV6(
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
    UNREFERENCED_PARAMETER(FlowContext);

    if (ClassifyOut != NULL)
    {
        ClassifyOut->actionType = FWP_ACTION_CONTINUE;
    }

    SerpiumFlowCaptureObservation(
        InFixedValues,
        InMetaValues,
        SERPIUM_FLOW_AF_INET6
        );
}

static
BOOLEAN
SerpiumFlowIsLoopbackDestination(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ USHORT AddressFamily
    )
{
    if (AddressFamily == SERPIUM_FLOW_AF_INET)
    {
        UINT32 address =
            InFixedValues->incomingValue[
                FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS
                ].value.uint32;

        return (address >> 24) == 127u;
    }
    else
    {
        const FWP_BYTE_ARRAY16* address =
            InFixedValues->incomingValue[
                FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_ADDRESS
                ].value.byteArray16;
        ULONG index;

        if (address == NULL)
        {
            return FALSE;
        }

        for (index = 0; index < 15; index++)
        {
            if (address->byteArray16[index] != 0)
            {
                return FALSE;
            }
        }

        return address->byteArray16[15] == 1;
    }
}

static
VOID
SerpiumFlowFillRedirectContext(
    _Out_ PSERPIUM_FLOW_REDIRECT_CONTEXT Context,
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ USHORT AddressFamily,
    _In_ UCHAR Protocol,
    _In_ ULONG PolicyGeneration,
    _In_ ULONGLONG RuleId,
    _In_ ULONG ResolvedRoute
    )
{
    RtlZeroMemory(Context, sizeof(*Context));
    Context->Size = sizeof(*Context);
    Context->ProtocolVersion = SERPIUM_FLOW_PROTOCOL_VERSION;
    Context->Magic = SERPIUM_FLOW_REDIRECT_CONTEXT_MAGIC;
    Context->PolicyGeneration = PolicyGeneration;
    Context->RuleId = RuleId;
    Context->ResolvedRoute = ResolvedRoute;
    Context->AddressFamily = AddressFamily;
    Context->Protocol = Protocol;

    if (AddressFamily == SERPIUM_FLOW_AF_INET)
    {
        UINT32 address =
            InFixedValues->incomingValue[
                FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS
                ].value.uint32;

        Context->RemotePort =
            InFixedValues->incomingValue[
                FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT
                ].value.uint16;
        Context->RemoteAddress[0] = (UCHAR)(address >> 24);
        Context->RemoteAddress[1] = (UCHAR)(address >> 16);
        Context->RemoteAddress[2] = (UCHAR)(address >> 8);
        Context->RemoteAddress[3] = (UCHAR)address;
    }
    else
    {
        const FWP_BYTE_ARRAY16* address =
            InFixedValues->incomingValue[
                FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_ADDRESS
                ].value.byteArray16;

        Context->RemotePort =
            InFixedValues->incomingValue[
                FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_PORT
                ].value.uint16;

        if (address != NULL)
        {
            RtlCopyMemory(
                Context->RemoteAddress,
                address->byteArray16,
                sizeof(Context->RemoteAddress)
                );
        }
    }
}

static
VOID
NTAPI
SerpiumFlowRedirectClassify(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _In_opt_ VOID* ClassifyContext,
    _In_ const FWPS_FILTER1* Filter,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut,
    _In_ USHORT AddressFamily
    )
{
    ULONG appIdIndex;
    ULONG protocolIndex;
    UCHAR protocol;
    const FWP_VALUE0* appIdValue;
    const FWP_BYTE_BLOB* appId;
    ULONG route;
    ULONGLONG ruleId;
    ULONG policyGeneration;
    ULONGLONG processId;
    ULONG snapshotResult;
    SERPIUM_FLOW_ROUTE_SNAPSHOT snapshot = {0};
    FWPS_CONNECTION_REDIRECT_STATE redirectState;
    UINT64 classifyHandle = 0;
    PVOID writableLayerData = NULL;
    FWPS_CONNECT_REQUEST0* connectRequest;
    PSERPIUM_FLOW_REDIRECT_CONTEXT redirectContext;
    NTSTATUS status;

    if (
        InFixedValues == NULL ||
        InMetaValues == NULL ||
        Filter == NULL ||
        ClassifyOut == NULL
        )
    {
        return;
    }

    if ((ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
    {
        return;
    }

    ClassifyOut->actionType = FWP_ACTION_PERMIT;

    appIdIndex =
        AddressFamily == SERPIUM_FLOW_AF_INET
            ? FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ALE_APP_ID
            : FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_ALE_APP_ID;
    protocolIndex =
        AddressFamily == SERPIUM_FLOW_AF_INET
            ? FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL
            : FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_PROTOCOL;

    protocol = InFixedValues->incomingValue[protocolIndex].value.uint8;

    if (
        (protocol != SERPIUM_FLOW_IPPROTO_TCP &&
         protocol != SERPIUM_FLOW_IPPROTO_UDP) ||
        SerpiumFlowIsLoopbackDestination(
            InFixedValues,
            AddressFamily
            )
        )
    {
        return;
    }

    appIdValue = &InFixedValues->incomingValue[appIdIndex].value;
    appId =
        appIdValue->type == FWP_BYTE_BLOB_TYPE
            ? appIdValue->byteBlob
            : NULL;

    SerpiumFlowResolveRouteForAppId(
        appId != NULL ? (const unsigned short*)appId->data : NULL,
        appId != NULL ? appId->size : 0,
        &route,
        &ruleId,
        &policyGeneration
        );

    if (
        (InMetaValues->currentMetadataValues &
         FWPS_METADATA_FIELD_PROCESS_ID) == 0
        )
    {
        if (route == SERPIUM_FLOW_ROUTE_VPN)
        {
            SerpiumFlowRecordRouteResult(FALSE, FALSE, TRUE);
        }
        return;
    }

    processId = InMetaValues->processId;
    snapshotResult = SerpiumFlowGetRouteSnapshot(
        processId,
        AddressFamily,
        &snapshot
        );

    if (snapshotResult == SERPIUM_FLOW_ROUTE_SNAPSHOT_BYPASS)
    {
        return;
    }

    if (snapshotResult != SERPIUM_FLOW_ROUTE_SNAPSHOT_READY)
    {
        if (route == SERPIUM_FLOW_ROUTE_VPN)
        {
            SerpiumFlowRecordRouteResult(FALSE, FALSE, TRUE);
        }
        return;
    }

    if (protocol == SERPIUM_FLOW_IPPROTO_TCP)
    {
        if (route != SERPIUM_FLOW_ROUTE_VPN && !snapshot.InspectAllTcp)
        {
            return;
        }
    }
    else
    {
        if (!snapshot.UdpAppRouting || route != SERPIUM_FLOW_ROUTE_VPN)
        {
            return;
        }
    }

    redirectState =
        InMetaValues->redirectRecords != NULL
            ? FwpsQueryConnectionRedirectState0(
                InMetaValues->redirectRecords,
                g_SerpiumFlowRedirectHandle,
                NULL
                )
            : FWPS_CONNECTION_NOT_REDIRECTED;

    if (redirectState != FWPS_CONNECTION_NOT_REDIRECTED)
    {
        if (
            redirectState == FWPS_CONNECTION_REDIRECTED_BY_OTHER
            )
        {
            SerpiumFlowRecordRouteResult(FALSE, FALSE, TRUE);
        }

        return;
    }

    status = FwpsAcquireClassifyHandle0(
        ClassifyContext,
        0,
        &classifyHandle
        );

    if (!NT_SUCCESS(status))
    {
        SerpiumFlowRecordRouteResult(FALSE, TRUE, TRUE);
        return;
    }

    status = FwpsAcquireWritableLayerDataPointer0(
        classifyHandle,
        Filter->filterId,
        0,
        &writableLayerData,
        ClassifyOut
        );

    if (!NT_SUCCESS(status) || writableLayerData == NULL)
    {
        FwpsReleaseClassifyHandle0(classifyHandle);
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        SerpiumFlowRecordRouteResult(FALSE, TRUE, TRUE);
        return;
    }

    connectRequest = (FWPS_CONNECT_REQUEST0*)writableLayerData;
    redirectContext = (PSERPIUM_FLOW_REDIRECT_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(*redirectContext),
        SERPIUM_FLOW_REDIRECT_POOL_TAG
        );

    if (redirectContext == NULL)
    {
        FwpsApplyModifiedLayerData0(
            classifyHandle,
            writableLayerData,
            0
            );
        FwpsReleaseClassifyHandle0(classifyHandle);
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        SerpiumFlowRecordRouteResult(FALSE, TRUE, TRUE);
        return;
    }

    SerpiumFlowFillRedirectContext(
        redirectContext,
        InFixedValues,
        AddressFamily,
        protocol,
        policyGeneration,
        ruleId,
        route
        );

    if (AddressFamily == SERPIUM_FLOW_AF_INET)
    {
        PSOCKADDR_IN remote =
            (PSOCKADDR_IN)&connectRequest->remoteAddressAndPort;

        remote->sin_family = AF_INET;
        remote->sin_port = RtlUshortByteSwap((USHORT)snapshot.ListenPort);
        remote->sin_addr.S_un.S_addr = RtlUlongByteSwap(0x7f000001u);
    }
    else
    {
        PSOCKADDR_IN6 remote =
            (PSOCKADDR_IN6)&connectRequest->remoteAddressAndPort;

        RtlZeroMemory(&remote->sin6_addr, sizeof(remote->sin6_addr));
        remote->sin6_family = AF_INET6;
        remote->sin6_port = RtlUshortByteSwap((USHORT)snapshot.ListenPort);
        remote->sin6_addr.u.Byte[15] = 1;
    }

    connectRequest->localRedirectTargetPID =
        (DWORD)snapshot.BridgeProcessId;
    connectRequest->localRedirectHandle = g_SerpiumFlowRedirectHandle;
    connectRequest->localRedirectContext = redirectContext;
    connectRequest->localRedirectContextSize = sizeof(*redirectContext);

    FwpsApplyModifiedLayerData0(
        classifyHandle,
        writableLayerData,
        0
        );
    FwpsReleaseClassifyHandle0(classifyHandle);

    ClassifyOut->actionType = FWP_ACTION_PERMIT;
    SerpiumFlowRecordRouteResult(TRUE, FALSE, FALSE);
}

VOID
NTAPI
SerpiumFlowRedirectClassifyV4(
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

    SerpiumFlowRedirectClassify(
        InFixedValues,
        InMetaValues,
        (VOID*)ClassifyContext,
        Filter,
        ClassifyOut,
        SERPIUM_FLOW_AF_INET
        );
}

VOID
NTAPI
SerpiumFlowRedirectClassifyV6(
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

    SerpiumFlowRedirectClassify(
        InFixedValues,
        InMetaValues,
        (VOID*)ClassifyContext,
        Filter,
        ClassifyOut,
        SERPIUM_FLOW_AF_INET6
        );
}


static
BOOLEAN
SerpiumFlowShouldBlockQuic(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _In_ USHORT AddressFamily
    )
{
    ULONG appIdIndex;
    ULONG protocolIndex;
    ULONG remotePortIndex;
    const FWP_VALUE0* appIdValue;
    const FWP_BYTE_BLOB* appId;
    ULONG route;
    ULONGLONG ruleId;
    ULONG policyGeneration;
    SERPIUM_FLOW_ROUTE_SNAPSHOT snapshot = {0};
    ULONG snapshotResult;

    if (InFixedValues == NULL || InMetaValues == NULL)
    {
        return FALSE;
    }

    protocolIndex =
        AddressFamily == SERPIUM_FLOW_AF_INET
            ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL
            : FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL;
    remotePortIndex =
        AddressFamily == SERPIUM_FLOW_AF_INET
            ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT
            : FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT;

    if (
        InFixedValues->incomingValue[protocolIndex].value.uint8 !=
            SERPIUM_FLOW_IPPROTO_UDP ||
        InFixedValues->incomingValue[remotePortIndex].value.uint16 != 443u
        )
    {
        return FALSE;
    }

    if (
        (InMetaValues->currentMetadataValues &
         FWPS_METADATA_FIELD_PROCESS_ID) == 0
        )
    {
        return FALSE;
    }

    snapshotResult = SerpiumFlowGetRouteSnapshot(
        InMetaValues->processId,
        AddressFamily,
        &snapshot
        );

    if (snapshotResult != SERPIUM_FLOW_ROUTE_SNAPSHOT_READY)
    {
        return FALSE;
    }

    if (snapshot.DomainQuicFallback)
    {
        return TRUE;
    }

    if (!snapshot.QuicTcpFallback)
    {
        return FALSE;
    }

    appIdIndex =
        AddressFamily == SERPIUM_FLOW_AF_INET
            ? FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID
            : FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID;
    appIdValue = &InFixedValues->incomingValue[appIdIndex].value;
    appId =
        appIdValue->type == FWP_BYTE_BLOB_TYPE
            ? appIdValue->byteBlob
            : NULL;

    SerpiumFlowResolveRouteForAppId(
        appId != NULL ? (const unsigned short*)appId->data : NULL,
        appId != NULL ? appId->size : 0,
        &route,
        &ruleId,
        &policyGeneration
        );

    UNREFERENCED_PARAMETER(ruleId);
    UNREFERENCED_PARAMETER(policyGeneration);

    return route == SERPIUM_FLOW_ROUTE_VPN;
}

static
VOID
NTAPI
SerpiumFlowQuicFallbackClassify(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_ const FWPS_FILTER0* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut,
    _In_ USHORT AddressFamily
    )
{
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    if (ClassifyOut == NULL ||
        (ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
    {
        return;
    }

    ClassifyOut->actionType = FWP_ACTION_PERMIT;

    if (SerpiumFlowShouldBlockQuic(
            InFixedValues,
            InMetaValues,
            AddressFamily))
    {
        //
        // Deliberately reject UDP/443 only while a healthy route lease is
        // active. Browsers then retry over TCP/TLS, which is handled by the
        // established WFP TCP + domain bridge path. If the bridge/backend
        // disappears, SerpiumFlowGetRouteSnapshot returns unavailable and
        // this callout immediately returns to DIRECT fail-open behavior.
        //
        ClassifyOut->actionType = FWP_ACTION_BLOCK;
        ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}

VOID
NTAPI
SerpiumFlowQuicFallbackClassifyV4(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    VOID* LayerData,
    const FWPS_FILTER0* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    SerpiumFlowQuicFallbackClassify(
        InFixedValues,
        InMetaValues,
        LayerData,
        Filter,
        FlowContext,
        ClassifyOut,
        SERPIUM_FLOW_AF_INET
        );
}

VOID
NTAPI
SerpiumFlowQuicFallbackClassifyV6(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    VOID* LayerData,
    const FWPS_FILTER0* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    SerpiumFlowQuicFallbackClassify(
        InFixedValues,
        InMetaValues,
        LayerData,
        Filter,
        FlowContext,
        ClassifyOut,
        SERPIUM_FLOW_AF_INET6
        );
}

static
VOID
NTAPI
SerpiumFlowDatagramClassify(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_ const FWPS_FILTER0* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    FWPS_PACKET_INJECTION_STATE injectionState;

    UNREFERENCED_PARAMETER(InFixedValues);
    UNREFERENCED_PARAMETER(InMetaValues);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    if (ClassifyOut != NULL)
    {
        ClassifyOut->actionType = FWP_ACTION_CONTINUE;
    }

    if (LayerData == NULL || g_SerpiumFlowDatagramInjectionHandle == NULL)
    {
        return;
    }

    //
    // U2 establishes a DATAGRAM_DATA interception/injection boundary without
    // altering payloads yet. The self-injection guard is deliberately in place
    // before packet reinjection is enabled in the follow-up transport step.
    //
    injectionState = FwpsQueryPacketInjectionState0(
        g_SerpiumFlowDatagramInjectionHandle,
        (NET_BUFFER_LIST*)LayerData,
        NULL
        );

    if (
        injectionState == FWPS_PACKET_INJECTED_BY_SELF ||
        injectionState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF
        )
    {
        return;
    }
}

VOID
NTAPI
SerpiumFlowDatagramClassifyV4(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    VOID* LayerData,
    const FWPS_FILTER0* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    SerpiumFlowDatagramClassify(
        InFixedValues,
        InMetaValues,
        LayerData,
        Filter,
        FlowContext,
        ClassifyOut
        );
}

VOID
NTAPI
SerpiumFlowDatagramClassifyV6(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    VOID* LayerData,
    const FWPS_FILTER0* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    SerpiumFlowDatagramClassify(
        InFixedValues,
        InMetaValues,
        LayerData,
        Filter,
        FlowContext,
        ClassifyOut
        );
}

_Use_decl_annotations_
NTSTATUS
NTAPI
SerpiumFlowNotify(
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
NTAPI
SerpiumFlowRedirectNotify(
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

static
NTSTATUS
SerpiumFlowRegisterRuntimeCallout(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ const GUID* CalloutKey,
    _In_ FWPS_CALLOUT_CLASSIFY_FN0 ClassifyFunction,
    _Out_ UINT32* CalloutId
    )
{
    FWPS_CALLOUT0 callout;

    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = *CalloutKey;
    callout.classifyFn = ClassifyFunction;
    callout.notifyFn = SerpiumFlowNotify;
    callout.flowDeleteFn = NULL;

    return FwpsCalloutRegister0(
        DeviceObject,
        &callout,
        CalloutId
        );
}

static
NTSTATUS
SerpiumFlowRegisterRedirectRuntimeCallout(
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
    callout.notifyFn = SerpiumFlowRedirectNotify;
    callout.flowDeleteFn = NULL;

    return FwpsCalloutRegister1(
        DeviceObject,
        &callout,
        CalloutId
        );
}

static
NTSTATUS
SerpiumFlowAddManagementCallout(
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
        L"Serpium Flow policy and guarded route callout";
    callout.applicableLayer = *LayerKey;

    return FwpmCalloutAdd0(
        g_SerpiumFlowEngineHandle,
        &callout,
        NULL,
        NULL
        );
}

static
NTSTATUS
SerpiumFlowAddInspectionFilter(
    _In_ const GUID* CalloutKey,
    _In_ const GUID* LayerKey,
    _In_ PWSTR Name
    )
{
    FWPM_FILTER0 filter;

    RtlZeroMemory(&filter, sizeof(filter));
    filter.displayData.name = Name;
    filter.displayData.description =
        L"Serpium Flow WFP-4A route telemetry; inspection always continues";
    filter.layerKey = *LayerKey;
    filter.subLayerKey = SERPIUM_FLOW_SUBLAYER_KEY;
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey = *CalloutKey;
    filter.weight.type = FWP_EMPTY;

    return FwpmFilterAdd0(
        g_SerpiumFlowEngineHandle,
        &filter,
        NULL,
        NULL
        );
}

static
NTSTATUS
SerpiumFlowAddRedirectFilter(
    _In_ const GUID* CalloutKey,
    _In_ const GUID* LayerKey,
    _In_ UCHAR Protocol,
    _In_ PWSTR Name,
    _In_ PWSTR Description
    )
{
    FWPM_FILTER0 filter;
    FWPM_FILTER_CONDITION0 condition;

    RtlZeroMemory(&filter, sizeof(filter));
    RtlZeroMemory(&condition, sizeof(condition));

    condition.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_UINT8;
    condition.conditionValue.uint8 = Protocol;

    filter.displayData.name = Name;
    filter.displayData.description = Description;
    filter.layerKey = *LayerKey;
    filter.subLayerKey = SERPIUM_FLOW_SUBLAYER_KEY;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = *CalloutKey;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = 1;
    filter.filterCondition = &condition;

    return FwpmFilterAdd0(
        g_SerpiumFlowEngineHandle,
        &filter,
        NULL,
        NULL
        );
}


static
NTSTATUS
SerpiumFlowAddQuicFallbackFilter(
    _In_ const GUID* CalloutKey,
    _In_ const GUID* LayerKey,
    _In_ PWSTR Name
    )
{
    FWPM_FILTER0 filter;
    FWPM_FILTER_CONDITION0 conditions[2];

    RtlZeroMemory(&filter, sizeof(filter));
    RtlZeroMemory(conditions, sizeof(conditions));

    conditions[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_UINT8;
    conditions[0].conditionValue.uint8 = SERPIUM_FLOW_IPPROTO_UDP;

    conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conditions[1].matchType = FWP_MATCH_EQUAL;
    conditions[1].conditionValue.type = FWP_UINT16;
    conditions[1].conditionValue.uint16 = 443u;

    filter.displayData.name = Name;
    filter.displayData.description =
        L"Lease-gated QUIC TCP fallback; UDP/443 is blocked only while WFP route state is healthy";
    filter.layerKey = *LayerKey;
    filter.subLayerKey = SERPIUM_FLOW_SUBLAYER_KEY;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = *CalloutKey;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = RTL_NUMBER_OF(conditions);
    filter.filterCondition = conditions;

    return FwpmFilterAdd0(
        g_SerpiumFlowEngineHandle,
        &filter,
        NULL,
        NULL
        );
}

_Use_decl_annotations_
NTSTATUS
SerpiumFlowWfpStart(
    PDEVICE_OBJECT DeviceObject
    )
{
    NTSTATUS status;
    BOOLEAN transactionStarted = FALSE;
    FWPM_SESSION0 session;
    FWPM_PROVIDER0 provider;
    FWPM_SUBLAYER0 subLayer;

    SerpiumFlowResetObservationQueue();

    status = SerpiumFlowRegisterRuntimeCallout(
        DeviceObject,
        &SERPIUM_FLOW_CALLOUT_V4_KEY,
        SerpiumFlowClassifyV4,
        &g_SerpiumFlowCalloutIdV4
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = FwpsRedirectHandleCreate0(
        &SERPIUM_FLOW_PROVIDER_KEY,
        0,
        &g_SerpiumFlowRedirectHandle
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowRegisterRedirectRuntimeCallout(
        DeviceObject,
        &SERPIUM_FLOW_REDIRECT_CALLOUT_V4_KEY,
        SerpiumFlowRedirectClassifyV4,
        &g_SerpiumFlowRedirectCalloutIdV4
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowRegisterRedirectRuntimeCallout(
        DeviceObject,
        &SERPIUM_FLOW_REDIRECT_CALLOUT_V6_KEY,
        SerpiumFlowRedirectClassifyV6,
        &g_SerpiumFlowRedirectCalloutIdV6
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowRegisterRuntimeCallout(
        DeviceObject,
        &SERPIUM_FLOW_CALLOUT_V6_KEY,
        SerpiumFlowClassifyV6,
        &g_SerpiumFlowCalloutIdV6
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = FwpsInjectionHandleCreate0(
        AF_UNSPEC,
        FWPS_INJECTION_TYPE_TRANSPORT,
        &g_SerpiumFlowDatagramInjectionHandle
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowRegisterRuntimeCallout(
        DeviceObject,
        &SERPIUM_FLOW_DATAGRAM_CALLOUT_V4_KEY,
        SerpiumFlowDatagramClassifyV4,
        &g_SerpiumFlowDatagramCalloutIdV4
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowRegisterRuntimeCallout(
        DeviceObject,
        &SERPIUM_FLOW_DATAGRAM_CALLOUT_V6_KEY,
        SerpiumFlowDatagramClassifyV6,
        &g_SerpiumFlowDatagramCalloutIdV6
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowRegisterRuntimeCallout(
        DeviceObject,
        &SERPIUM_FLOW_QUIC_CALLOUT_V4_KEY,
        SerpiumFlowQuicFallbackClassifyV4,
        &g_SerpiumFlowQuicCalloutIdV4
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowRegisterRuntimeCallout(
        DeviceObject,
        &SERPIUM_FLOW_QUIC_CALLOUT_V6_KEY,
        SerpiumFlowQuicFallbackClassifyV6,
        &g_SerpiumFlowQuicCalloutIdV6
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    RtlZeroMemory(&session, sizeof(session));
    session.displayData.name = L"Serpium Flow WFP-4A Route Session";
    session.displayData.description =
        L"Dynamic session; objects disappear when the driver unloads";
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.txnWaitTimeoutInMSec = 5000;

    status = FwpmEngineOpen0(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        &session,
        &g_SerpiumFlowEngineHandle
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = FwpmTransactionBegin0(
        g_SerpiumFlowEngineHandle,
        0
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    transactionStarted = TRUE;

    RtlZeroMemory(&provider, sizeof(provider));
    provider.providerKey = SERPIUM_FLOW_PROVIDER_KEY;
    provider.displayData.name = L"Serpium Flow WFP-4A Provider";
    provider.displayData.description =
        L"Dynamic provider for guarded TCP/UDP connect redirection";

    status = FwpmProviderAdd0(
        g_SerpiumFlowEngineHandle,
        &provider,
        NULL
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    RtlZeroMemory(&subLayer, sizeof(subLayer));
    subLayer.subLayerKey = SERPIUM_FLOW_SUBLAYER_KEY;
    subLayer.displayData.name = L"Serpium Flow WFP-4A Route Enforcement";
    subLayer.displayData.description =
        L"Policy observation plus guarded fail-open TCP/UDP connect redirect";
    subLayer.providerKey = (GUID*)&SERPIUM_FLOW_PROVIDER_KEY;
    subLayer.weight = 0x0100;

    status = FwpmSubLayerAdd0(
        g_SerpiumFlowEngineHandle,
        &subLayer,
        NULL
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowAddManagementCallout(
        &SERPIUM_FLOW_CALLOUT_V4_KEY,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        L"Serpium Flow Observe ALE Connect V4"
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowAddManagementCallout(
        &SERPIUM_FLOW_CALLOUT_V6_KEY,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        L"Serpium Flow Observe ALE Connect V6"
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowAddInspectionFilter(
        &SERPIUM_FLOW_CALLOUT_V4_KEY,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        L"Serpium Flow Observe Filter V4"
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowAddManagementCallout(
        &SERPIUM_FLOW_REDIRECT_CALLOUT_V4_KEY,
        &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
        L"Serpium Flow Connect Redirect V4"
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowAddManagementCallout(
        &SERPIUM_FLOW_REDIRECT_CALLOUT_V6_KEY,
        &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
        L"Serpium Flow Connect Redirect V6"
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowAddRedirectFilter(
        &SERPIUM_FLOW_REDIRECT_CALLOUT_V4_KEY,
        &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
        SERPIUM_FLOW_IPPROTO_TCP,
        L"Serpium Flow TCP Redirect Filter V4",
        L"WFP-4A guarded TCP redirect; disarmed or expired state permits DIRECT"
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowAddRedirectFilter(
        &SERPIUM_FLOW_REDIRECT_CALLOUT_V6_KEY,
        &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
        SERPIUM_FLOW_IPPROTO_TCP,
        L"Serpium Flow TCP Redirect Filter V6",
        L"WFP-4A guarded TCP redirect; disarmed or expired state permits DIRECT"
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowAddRedirectFilter(
        &SERPIUM_FLOW_REDIRECT_CALLOUT_V4_KEY,
        &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
        SERPIUM_FLOW_IPPROTO_UDP,
        L"Serpium Flow UDP Redirect Filter V4",
        L"Patch A guarded UDP app redirect; missing state permits DIRECT"
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowAddRedirectFilter(
        &SERPIUM_FLOW_REDIRECT_CALLOUT_V6_KEY,
        &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
        SERPIUM_FLOW_IPPROTO_UDP,
        L"Serpium Flow UDP Redirect Filter V6",
        L"Patch A guarded UDP app redirect; missing state permits DIRECT"
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowAddManagementCallout(
        &SERPIUM_FLOW_DATAGRAM_CALLOUT_V4_KEY,
        &FWPM_LAYER_DATAGRAM_DATA_V4,
        L"Serpium Flow Datagram Core V4"
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowAddManagementCallout(
        &SERPIUM_FLOW_DATAGRAM_CALLOUT_V6_KEY,
        &FWPM_LAYER_DATAGRAM_DATA_V6,
        L"Serpium Flow Datagram Core V6"
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowAddInspectionFilter(
        &SERPIUM_FLOW_DATAGRAM_CALLOUT_V4_KEY,
        &FWPM_LAYER_DATAGRAM_DATA_V4,
        L"Serpium Flow Datagram Inspection V4"
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowAddInspectionFilter(
        &SERPIUM_FLOW_DATAGRAM_CALLOUT_V6_KEY,
        &FWPM_LAYER_DATAGRAM_DATA_V6,
        L"Serpium Flow Datagram Inspection V6"
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowAddManagementCallout(
        &SERPIUM_FLOW_QUIC_CALLOUT_V4_KEY,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        L"Serpium Flow QUIC TCP Fallback V4"
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowAddManagementCallout(
        &SERPIUM_FLOW_QUIC_CALLOUT_V6_KEY,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        L"Serpium Flow QUIC TCP Fallback V6"
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowAddQuicFallbackFilter(
        &SERPIUM_FLOW_QUIC_CALLOUT_V4_KEY,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        L"Serpium Flow QUIC TCP Fallback Filter V4"
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowAddQuicFallbackFilter(
        &SERPIUM_FLOW_QUIC_CALLOUT_V6_KEY,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        L"Serpium Flow QUIC TCP Fallback Filter V6"
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumFlowAddInspectionFilter(
        &SERPIUM_FLOW_CALLOUT_V6_KEY,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        L"Serpium Flow Observe Filter V6"
        );

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = FwpmTransactionCommit0(g_SerpiumFlowEngineHandle);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    transactionStarted = FALSE;
    g_SerpiumFlowWfpActive = TRUE;

Exit:
    if (!NT_SUCCESS(status))
    {
        if (transactionStarted && g_SerpiumFlowEngineHandle != NULL)
        {
            FwpmTransactionAbort0(g_SerpiumFlowEngineHandle);
        }

        SerpiumFlowWfpStop();
    }

    return status;
}

VOID
SerpiumFlowWfpStop(
    VOID
    )
{
    BOOLEAN changed;

    g_SerpiumFlowWfpActive = FALSE;
    SerpiumFlowDisarmRoute(&changed);

    if (g_SerpiumFlowEngineHandle != NULL)
    {
        FwpmEngineClose0(g_SerpiumFlowEngineHandle);
        g_SerpiumFlowEngineHandle = NULL;
    }

    if (g_SerpiumFlowCalloutIdV6 != 0)
    {
        FwpsCalloutUnregisterById0(g_SerpiumFlowCalloutIdV6);
        g_SerpiumFlowCalloutIdV6 = 0;
    }

    if (g_SerpiumFlowCalloutIdV4 != 0)
    {
        FwpsCalloutUnregisterById0(g_SerpiumFlowCalloutIdV4);
        g_SerpiumFlowCalloutIdV4 = 0;
    }

    if (g_SerpiumFlowQuicCalloutIdV6 != 0)
    {
        FwpsCalloutUnregisterById0(g_SerpiumFlowQuicCalloutIdV6);
        g_SerpiumFlowQuicCalloutIdV6 = 0;
    }

    if (g_SerpiumFlowQuicCalloutIdV4 != 0)
    {
        FwpsCalloutUnregisterById0(g_SerpiumFlowQuicCalloutIdV4);
        g_SerpiumFlowQuicCalloutIdV4 = 0;
    }

    if (g_SerpiumFlowDatagramCalloutIdV6 != 0)
    {
        FwpsCalloutUnregisterById0(g_SerpiumFlowDatagramCalloutIdV6);
        g_SerpiumFlowDatagramCalloutIdV6 = 0;
    }

    if (g_SerpiumFlowDatagramCalloutIdV4 != 0)
    {
        FwpsCalloutUnregisterById0(g_SerpiumFlowDatagramCalloutIdV4);
        g_SerpiumFlowDatagramCalloutIdV4 = 0;
    }

    if (g_SerpiumFlowDatagramInjectionHandle != NULL)
    {
        FwpsInjectionHandleDestroy0(g_SerpiumFlowDatagramInjectionHandle);
        g_SerpiumFlowDatagramInjectionHandle = NULL;
    }

    if (g_SerpiumFlowRedirectCalloutIdV6 != 0)
    {
        FwpsCalloutUnregisterById0(g_SerpiumFlowRedirectCalloutIdV6);
        g_SerpiumFlowRedirectCalloutIdV6 = 0;
    }

    if (g_SerpiumFlowRedirectCalloutIdV4 != 0)
    {
        FwpsCalloutUnregisterById0(g_SerpiumFlowRedirectCalloutIdV4);
        g_SerpiumFlowRedirectCalloutIdV4 = 0;
    }

    if (g_SerpiumFlowRedirectHandle != NULL)
    {
        FwpsRedirectHandleDestroy0(g_SerpiumFlowRedirectHandle);
        g_SerpiumFlowRedirectHandle = NULL;
    }
}

static
VOID
SerpiumFlowFillStatus(
    _Out_ PSERPIUM_FLOW_STATUS Status
    )
{
    KIRQL oldIrql;

    RtlZeroMemory(Status, sizeof(*Status));

    Status->Size = sizeof(*Status);
    Status->ProtocolVersion = SERPIUM_FLOW_PROTOCOL_VERSION;
    Status->DriverVersionMajor = SERPIUM_FLOW_DRIVER_VERSION_MAJOR;
    Status->DriverVersionMinor = SERPIUM_FLOW_DRIVER_VERSION_MINOR;
    Status->DriverVersionPatch = SERPIUM_FLOW_DRIVER_VERSION_PATCH;
    Status->Flags =
        SERPIUM_FLOW_STATUS_FLAG_DRIVER_READY |
        SERPIUM_FLOW_STATUS_FLAG_CONTROL_DEVICE |
        SERPIUM_FLOW_STATUS_FLAG_EVENT_QUEUE |
        SERPIUM_FLOW_STATUS_FLAG_FAIL_OPEN |
        SERPIUM_FLOW_STATUS_FLAG_POLICY_TRANSPORT |
        SERPIUM_FLOW_STATUS_FLAG_ROUTE_ENFORCEMENT_AVAILABLE |
        SERPIUM_FLOW_STATUS_FLAG_TCP_CONNECT_REDIRECT |
        SERPIUM_FLOW_STATUS_FLAG_UDP_CONNECT_REDIRECT |
        SERPIUM_FLOW_STATUS_FLAG_DATAGRAM_DATA_CORE |
        SERPIUM_FLOW_STATUS_FLAG_QUIC_TCP_FALLBACK |
        SERPIUM_FLOW_STATUS_FLAG_APP_RULE_TABLE |
        SERPIUM_FLOW_STATUS_FLAG_FLOW_TABLE |
        SERPIUM_FLOW_STATUS_FLAG_POLICY_BATCH_REPLACE;
    Status->UptimeMilliseconds = SerpiumFlowQueryMilliseconds();
    Status->QueueCapacity = SERPIUM_FLOW_OBSERVATION_QUEUE_CAPACITY;
    Status->RuleCapacity = SERPIUM_FLOW_RULE_CAPACITY;
    Status->FlowCapacity = SERPIUM_FLOW_FLOW_CAPACITY;

    if (g_SerpiumFlowWfpActive)
    {
        Status->Flags |=
            SERPIUM_FLOW_STATUS_FLAG_CALLOUTS_REGISTERED |
            SERPIUM_FLOW_STATUS_FLAG_FILTERS_ACTIVE;
        Status->CalloutIdV4 = g_SerpiumFlowCalloutIdV4;
        Status->CalloutIdV6 = g_SerpiumFlowCalloutIdV6;
        Status->RedirectCalloutIdV4 =
            g_SerpiumFlowRedirectCalloutIdV4;
        Status->RedirectCalloutIdV6 =
            g_SerpiumFlowRedirectCalloutIdV6;
    }
    else
    {
        Status->Flags |= SERPIUM_FLOW_STATUS_FLAG_WFP_DISABLED;
    }

    KeAcquireSpinLock(
        &g_SerpiumFlowPolicy.Lock,
        &oldIrql
        );

    Status->PolicyGeneration = g_SerpiumFlowPolicy.Generation;
    Status->RuleCount = g_SerpiumFlowPolicy.Count;
    Status->TotalPolicyMatches = g_SerpiumFlowPolicy.TotalMatches;
    Status->TotalPolicyMisses = g_SerpiumFlowPolicy.TotalMisses;

    KeReleaseSpinLock(
        &g_SerpiumFlowPolicy.Lock,
        oldIrql
        );

    KeAcquireSpinLock(
        &g_SerpiumFlowTable.Lock,
        &oldIrql
        );

    Status->FlowCount = g_SerpiumFlowTable.Count;

    KeReleaseSpinLock(
        &g_SerpiumFlowTable.Lock,
        oldIrql
        );

    KeAcquireSpinLock(
        &g_SerpiumFlowObservations.Lock,
        &oldIrql
        );

    Status->TotalObserved = g_SerpiumFlowObservations.TotalObserved;
    Status->DroppedObservations =
        g_SerpiumFlowObservations.DroppedObservations;
    Status->QueuedObservations = g_SerpiumFlowObservations.Count;

    KeReleaseSpinLock(
        &g_SerpiumFlowObservations.Lock,
        oldIrql
        );

    KeAcquireSpinLock(
        &g_SerpiumFlowRoute.Lock,
        &oldIrql
        );

    Status->RouteConfigGeneration =
        g_SerpiumFlowRoute.ConfigGeneration;
    Status->TotalRedirected = g_SerpiumFlowRoute.TotalRedirected;
    Status->TotalRedirectFailures =
        g_SerpiumFlowRoute.TotalRedirectFailures;
    Status->TotalRouteFailOpen = g_SerpiumFlowRoute.TotalFailOpen;

    if (
        g_SerpiumFlowRoute.Armed &&
        g_SerpiumFlowRoute.LeaseExpiresMilliseconds >
            Status->UptimeMilliseconds
        )
    {
        ULONGLONG remaining =
            g_SerpiumFlowRoute.LeaseExpiresMilliseconds -
            Status->UptimeMilliseconds;

        Status->Flags |=
            SERPIUM_FLOW_STATUS_FLAG_ROUTE_ENFORCEMENT_ARMED |
            SERPIUM_FLOW_STATUS_FLAG_ROUTE_LEASE_ACTIVE;
        Status->RouteLeaseRemainingMilliseconds =
            remaining > MAXULONG ? MAXULONG : (ULONG)remaining;
    }
    else
    {
        Status->Flags |=
            SERPIUM_FLOW_STATUS_FLAG_ROUTE_ENFORCEMENT_DISABLED;
    }

    KeReleaseSpinLock(
        &g_SerpiumFlowRoute.Lock,
        oldIrql
        );
}

static
ULONG
SerpiumFlowDrainObservations(
    _Out_ PSERPIUM_FLOW_OBSERVATION_BATCH Batch
    )
{
    KIRQL oldIrql;
    ULONG count;
    ULONG index;
    ULONG eventIndex;

    RtlZeroMemory(Batch, sizeof(*Batch));
    Batch->ProtocolVersion = SERPIUM_FLOW_PROTOCOL_VERSION;
    Batch->EventSize = sizeof(SERPIUM_FLOW_OBSERVATION);

    KeAcquireSpinLock(
        &g_SerpiumFlowObservations.Lock,
        &oldIrql
        );

    count = g_SerpiumFlowObservations.Count;

    if (count > SERPIUM_FLOW_OBSERVATION_BATCH_MAX)
    {
        count = SERPIUM_FLOW_OBSERVATION_BATCH_MAX;
    }

    index =
        (g_SerpiumFlowObservations.Head +
         SERPIUM_FLOW_OBSERVATION_QUEUE_CAPACITY -
         g_SerpiumFlowObservations.Count) %
        SERPIUM_FLOW_OBSERVATION_QUEUE_CAPACITY;

    for (eventIndex = 0; eventIndex < count; eventIndex++)
    {
        Batch->Events[eventIndex] =
            g_SerpiumFlowObservations.Events[index];
        index =
            (index + 1) % SERPIUM_FLOW_OBSERVATION_QUEUE_CAPACITY;
    }

    g_SerpiumFlowObservations.Count -= count;

    Batch->EventCount = count;
    Batch->TotalObserved = g_SerpiumFlowObservations.TotalObserved;
    Batch->DroppedObservations =
        g_SerpiumFlowObservations.DroppedObservations;
    Batch->RemainingObservations = g_SerpiumFlowObservations.Count;
    Batch->Size =
        FIELD_OFFSET(SERPIUM_FLOW_OBSERVATION_BATCH, Events) +
        (count * sizeof(SERPIUM_FLOW_OBSERVATION));

    KeReleaseSpinLock(
        &g_SerpiumFlowObservations.Lock,
        oldIrql
        );

    return Batch->Size;
}

static
VOID
SerpiumFlowAdvancePolicyGenerationLocked(
    VOID
    )
{
    g_SerpiumFlowPolicy.Generation++;

    if (g_SerpiumFlowPolicy.Generation == 0)
    {
        g_SerpiumFlowPolicy.Generation = 1;
    }
}

static
VOID
SerpiumFlowFillMutationResult(
    _Out_ PSERPIUM_FLOW_MUTATION_RESULT Result,
    _In_ BOOLEAN Changed
    )
{
    KIRQL oldIrql;

    RtlZeroMemory(Result, sizeof(*Result));
    Result->Size = sizeof(*Result);
    Result->ProtocolVersion = SERPIUM_FLOW_PROTOCOL_VERSION;

    if (Changed)
    {
        Result->Flags |= SERPIUM_FLOW_MUTATION_FLAG_CHANGED;
    }

    KeAcquireSpinLock(
        &g_SerpiumFlowPolicy.Lock,
        &oldIrql
        );

    Result->PolicyGeneration = g_SerpiumFlowPolicy.Generation;
    Result->RuleCount = g_SerpiumFlowPolicy.Count;

    KeReleaseSpinLock(
        &g_SerpiumFlowPolicy.Lock,
        oldIrql
        );

    KeAcquireSpinLock(
        &g_SerpiumFlowTable.Lock,
        &oldIrql
        );

    Result->FlowCount = g_SerpiumFlowTable.Count;

    KeReleaseSpinLock(
        &g_SerpiumFlowTable.Lock,
        oldIrql
        );
}

static
NTSTATUS
SerpiumFlowAddRule(
    _In_ const SERPIUM_FLOW_RULE_REQUEST* Request,
    _Out_ BOOLEAN* Changed
    )
{
    KIRQL oldIrql;
    ULONG index;
    LONG matchingIndex = -1;
    SERPIUM_FLOW_RULE_ENTRY entry;

    *Changed = FALSE;

    if (
        Request->Size != sizeof(*Request) ||
        Request->ProtocolVersion != SERPIUM_FLOW_PROTOCOL_VERSION
        )
    {
        return STATUS_REVISION_MISMATCH;
    }

    if (
        Request->RuleId == 0 ||
        (Request->Route != SERPIUM_FLOW_ROUTE_DIRECT &&
         Request->Route != SERPIUM_FLOW_ROUTE_VPN) ||
        Request->Flags != 0 ||
        Request->AppIdByteLength == 0 ||
        Request->AppIdByteLength > SERPIUM_FLOW_APP_ID_MAX_BYTES ||
        (Request->AppIdByteLength & 1u) != 0
        )
    {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&entry, sizeof(entry));
    entry.Size = sizeof(entry);
    entry.ProtocolVersion = SERPIUM_FLOW_PROTOCOL_VERSION;
    entry.RuleId = Request->RuleId;
    entry.Route = Request->Route;
    entry.AppIdByteLength = Request->AppIdByteLength;
    RtlCopyMemory(
        entry.AppId,
        Request->AppId,
        Request->AppIdByteLength
        );

    KeAcquireSpinLock(
        &g_SerpiumFlowPolicy.Lock,
        &oldIrql
        );

    for (index = 0; index < g_SerpiumFlowPolicy.Count; index++)
    {
        SERPIUM_FLOW_RULE_ENTRY* current =
            &g_SerpiumFlowPolicy.Rules[index];

        if (
            current->RuleId == Request->RuleId ||
            SerpiumFlowAppIdsEqual(
                current->AppId,
                current->AppIdByteLength,
                Request->AppId,
                Request->AppIdByteLength
                )
            )
        {
            matchingIndex = (LONG)index;
            break;
        }
    }

    if (matchingIndex >= 0)
    {
        SERPIUM_FLOW_RULE_ENTRY* current =
            &g_SerpiumFlowPolicy.Rules[matchingIndex];

        if (
            current->RuleId != entry.RuleId ||
            current->Route != entry.Route ||
            !SerpiumFlowAppIdsEqual(
                current->AppId,
                current->AppIdByteLength,
                entry.AppId,
                entry.AppIdByteLength
                )
            )
        {
            *current = entry;
            SerpiumFlowAdvancePolicyGenerationLocked();
            *Changed = TRUE;
        }
    }
    else if (g_SerpiumFlowPolicy.Count < SERPIUM_FLOW_RULE_CAPACITY)
    {
        g_SerpiumFlowPolicy.Rules[g_SerpiumFlowPolicy.Count] = entry;
        g_SerpiumFlowPolicy.Count++;
        SerpiumFlowAdvancePolicyGenerationLocked();
        *Changed = TRUE;
    }
    else
    {
        KeReleaseSpinLock(
            &g_SerpiumFlowPolicy.Lock,
            oldIrql
            );
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeReleaseSpinLock(
        &g_SerpiumFlowPolicy.Lock,
        oldIrql
        );

    return STATUS_SUCCESS;
}

static
NTSTATUS
SerpiumFlowRemoveRule(
    _In_ const SERPIUM_FLOW_REMOVE_RULE_REQUEST* Request,
    _Out_ BOOLEAN* Changed
    )
{
    KIRQL oldIrql;
    ULONG index;

    *Changed = FALSE;

    if (
        Request->Size != sizeof(*Request) ||
        Request->ProtocolVersion != SERPIUM_FLOW_PROTOCOL_VERSION
        )
    {
        return STATUS_REVISION_MISMATCH;
    }

    if (Request->RuleId == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(
        &g_SerpiumFlowPolicy.Lock,
        &oldIrql
        );

    for (index = 0; index < g_SerpiumFlowPolicy.Count; index++)
    {
        if (g_SerpiumFlowPolicy.Rules[index].RuleId == Request->RuleId)
        {
            ULONG remaining = g_SerpiumFlowPolicy.Count - index - 1;

            if (remaining > 0)
            {
                RtlMoveMemory(
                    &g_SerpiumFlowPolicy.Rules[index],
                    &g_SerpiumFlowPolicy.Rules[index + 1],
                    remaining * sizeof(SERPIUM_FLOW_RULE_ENTRY)
                    );
            }

            g_SerpiumFlowPolicy.Count--;
            RtlZeroMemory(
                &g_SerpiumFlowPolicy.Rules[g_SerpiumFlowPolicy.Count],
                sizeof(SERPIUM_FLOW_RULE_ENTRY)
                );
            SerpiumFlowAdvancePolicyGenerationLocked();
            *Changed = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(
        &g_SerpiumFlowPolicy.Lock,
        oldIrql
        );

    return STATUS_SUCCESS;
}

static
VOID
SerpiumFlowClearRules(
    _Out_ BOOLEAN* Changed
    )
{
    KIRQL oldIrql;

    *Changed = FALSE;

    KeAcquireSpinLock(
        &g_SerpiumFlowPolicy.Lock,
        &oldIrql
        );

    if (g_SerpiumFlowPolicy.Count > 0)
    {
        RtlZeroMemory(
            g_SerpiumFlowPolicy.Rules,
            sizeof(g_SerpiumFlowPolicy.Rules)
            );
        g_SerpiumFlowPolicy.Count = 0;
        SerpiumFlowAdvancePolicyGenerationLocked();
        *Changed = TRUE;
    }

    KeReleaseSpinLock(
        &g_SerpiumFlowPolicy.Lock,
        oldIrql
        );
}

static
NTSTATUS
SerpiumFlowReplaceRules(
    _In_ const SERPIUM_FLOW_REPLACE_RULES_REQUEST* Request,
    _Out_ BOOLEAN* Changed
    )
{
    KIRQL oldIrql;
    ULONG index;
    ULONG compareIndex;
    BOOLEAN differs = FALSE;

    *Changed = FALSE;

    if (
        Request == NULL ||
        Request->Size != sizeof(*Request) ||
        Request->ProtocolVersion != SERPIUM_FLOW_PROTOCOL_VERSION
        )
    {
        return STATUS_REVISION_MISMATCH;
    }

    if (
        Request->RuleCount > SERPIUM_FLOW_RULE_CAPACITY ||
        Request->Reserved != 0
        )
    {
        return STATUS_INVALID_PARAMETER;
    }

    for (index = 0; index < Request->RuleCount; index++)
    {
        const SERPIUM_FLOW_RULE_ENTRY* entry = &Request->Rules[index];

        if (
            entry->Size != sizeof(*entry) ||
            entry->ProtocolVersion != SERPIUM_FLOW_PROTOCOL_VERSION ||
            entry->RuleId == 0 ||
            (entry->Route != SERPIUM_FLOW_ROUTE_DIRECT &&
             entry->Route != SERPIUM_FLOW_ROUTE_VPN) ||
            entry->Flags != 0 ||
            entry->Reserved != 0 ||
            entry->AppIdByteLength == 0 ||
            entry->AppIdByteLength > SERPIUM_FLOW_APP_ID_MAX_BYTES ||
            (entry->AppIdByteLength & 1u) != 0
            )
        {
            return STATUS_INVALID_PARAMETER;
        }

        for (compareIndex = 0; compareIndex < index; compareIndex++)
        {
            const SERPIUM_FLOW_RULE_ENTRY* previous =
                &Request->Rules[compareIndex];

            if (
                previous->RuleId == entry->RuleId ||
                SerpiumFlowAppIdsEqual(
                    previous->AppId,
                    previous->AppIdByteLength,
                    entry->AppId,
                    entry->AppIdByteLength
                    )
                )
            {
                return STATUS_OBJECT_NAME_COLLISION;
            }
        }
    }

    KeAcquireSpinLock(
        &g_SerpiumFlowPolicy.Lock,
        &oldIrql
        );

    if (g_SerpiumFlowPolicy.Count != Request->RuleCount)
    {
        differs = TRUE;
    }
    else
    {
        for (index = 0; index < Request->RuleCount; index++)
        {
            const SERPIUM_FLOW_RULE_ENTRY* current =
                &g_SerpiumFlowPolicy.Rules[index];
            const SERPIUM_FLOW_RULE_ENTRY* replacement =
                &Request->Rules[index];

            if (
                current->RuleId != replacement->RuleId ||
                current->Route != replacement->Route ||
                current->Flags != replacement->Flags ||
                !SerpiumFlowAppIdsEqual(
                    current->AppId,
                    current->AppIdByteLength,
                    replacement->AppId,
                    replacement->AppIdByteLength
                    )
                )
            {
                differs = TRUE;
                break;
            }
        }
    }

    if (differs)
    {
        RtlZeroMemory(
            g_SerpiumFlowPolicy.Rules,
            sizeof(g_SerpiumFlowPolicy.Rules)
            );

        if (Request->RuleCount > 0)
        {
            RtlCopyMemory(
                g_SerpiumFlowPolicy.Rules,
                Request->Rules,
                Request->RuleCount * sizeof(SERPIUM_FLOW_RULE_ENTRY)
                );
        }

        g_SerpiumFlowPolicy.Count = Request->RuleCount;
        SerpiumFlowAdvancePolicyGenerationLocked();
        *Changed = TRUE;
    }

    KeReleaseSpinLock(
        &g_SerpiumFlowPolicy.Lock,
        oldIrql
        );

    return STATUS_SUCCESS;
}

static
ULONG
SerpiumFlowEnumerateRules(
    _In_ ULONG StartIndex,
    _Out_ PSERPIUM_FLOW_RULE_BATCH Batch
    )
{
    KIRQL oldIrql;
    ULONG available;
    ULONG count;

    RtlZeroMemory(Batch, sizeof(*Batch));
    Batch->ProtocolVersion = SERPIUM_FLOW_PROTOCOL_VERSION;
    Batch->EntrySize = sizeof(SERPIUM_FLOW_RULE_ENTRY);

    KeAcquireSpinLock(
        &g_SerpiumFlowPolicy.Lock,
        &oldIrql
        );

    Batch->PolicyGeneration = g_SerpiumFlowPolicy.Generation;
    Batch->TotalCount = g_SerpiumFlowPolicy.Count;

    if (StartIndex < g_SerpiumFlowPolicy.Count)
    {
        available = g_SerpiumFlowPolicy.Count - StartIndex;
        count =
            available > SERPIUM_FLOW_RULE_BATCH_MAX
                ? SERPIUM_FLOW_RULE_BATCH_MAX
                : available;

        RtlCopyMemory(
            Batch->Entries,
            &g_SerpiumFlowPolicy.Rules[StartIndex],
            count * sizeof(SERPIUM_FLOW_RULE_ENTRY)
            );
        Batch->EntryCount = count;
        Batch->NextIndex = StartIndex + count;
    }
    else
    {
        Batch->NextIndex = g_SerpiumFlowPolicy.Count;
    }

    Batch->Size =
        FIELD_OFFSET(SERPIUM_FLOW_RULE_BATCH, Entries) +
        (Batch->EntryCount * sizeof(SERPIUM_FLOW_RULE_ENTRY));

    KeReleaseSpinLock(
        &g_SerpiumFlowPolicy.Lock,
        oldIrql
        );

    return Batch->Size;
}

static
ULONG
SerpiumFlowEnumerateFlows(
    _In_ ULONG StartIndex,
    _Out_ PSERPIUM_FLOW_FLOW_BATCH Batch
    )
{
    KIRQL oldIrql;
    ULONG available;
    ULONG count;
    ULONG oldestIndex;
    ULONG index;

    RtlZeroMemory(Batch, sizeof(*Batch));
    Batch->ProtocolVersion = SERPIUM_FLOW_PROTOCOL_VERSION;
    Batch->EntrySize = sizeof(SERPIUM_FLOW_FLOW_ENTRY);

    KeAcquireSpinLock(
        &g_SerpiumFlowTable.Lock,
        &oldIrql
        );

    Batch->TotalCount = g_SerpiumFlowTable.Count;

    if (StartIndex < g_SerpiumFlowTable.Count)
    {
        available = g_SerpiumFlowTable.Count - StartIndex;
        count =
            available > SERPIUM_FLOW_FLOW_BATCH_MAX
                ? SERPIUM_FLOW_FLOW_BATCH_MAX
                : available;
        oldestIndex =
            g_SerpiumFlowTable.Count < SERPIUM_FLOW_FLOW_CAPACITY
                ? 0u
                : g_SerpiumFlowTable.NextIndex;

        for (index = 0; index < count; index++)
        {
            ULONG physicalIndex =
                (oldestIndex + StartIndex + index) %
                SERPIUM_FLOW_FLOW_CAPACITY;
            Batch->Entries[index] =
                g_SerpiumFlowTable.Entries[physicalIndex];
        }

        Batch->EntryCount = count;
        Batch->NextIndex = StartIndex + count;
    }
    else
    {
        Batch->NextIndex = g_SerpiumFlowTable.Count;
    }

    Batch->Size =
        FIELD_OFFSET(SERPIUM_FLOW_FLOW_BATCH, Entries) +
        (Batch->EntryCount * sizeof(SERPIUM_FLOW_FLOW_ENTRY));

    KeReleaseSpinLock(
        &g_SerpiumFlowTable.Lock,
        oldIrql
        );

    return Batch->Size;
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

    KeQuerySystemTimePrecise(&g_SerpiumFlowStartTime);
    SerpiumFlowResetObservationQueue();
    SerpiumFlowResetPolicyState();
    SerpiumFlowResetRouteState();

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);

    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = SerpiumFlowEvtDriverUnload;

    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        &attributes,
        &config,
        &driver
        );

    if (!NT_SUCCESS(status))
    {
        KdPrintEx((
            DPFLTR_IHVNETWORK_ID,
            DPFLTR_ERROR_LEVEL,
            "SerpiumFlow: WdfDriverCreate failed: 0x%08X\n",
            status
            ));

        return status;
    }

    status = SerpiumFlowCreateControlDevice(driver);

    if (!NT_SUCCESS(status))
    {
        KdPrintEx((
            DPFLTR_IHVNETWORK_ID,
            DPFLTR_ERROR_LEVEL,
            "SerpiumFlow: control/WFP initialization failed: 0x%08X\n",
            status
            ));

        return status;
    }

    KdPrintEx((
        DPFLTR_IHVNETWORK_ID,
        DPFLTR_INFO_LEVEL,
        "SerpiumFlow: WFP-4A guarded TCP route core active; enforcement is lease-gated.\n"
        ));

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
SerpiumFlowEvtDriverUnload(
    WDFDRIVER Driver
    )
{
    UNREFERENCED_PARAMETER(Driver);

    SerpiumFlowWfpStop();

    KdPrintEx((
        DPFLTR_IHVNETWORK_ID,
        DPFLTR_INFO_LEVEL,
        "SerpiumFlow: WFP-4A objects removed; route disarmed; driver unloaded.\n"
        ));
}

_Use_decl_annotations_
NTSTATUS
SerpiumFlowCreateControlDevice(
    WDFDRIVER Driver
    )
{
    NTSTATUS status;
    PWDFDEVICE_INIT deviceInit;
    WDFDEVICE device;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLinkName;
    UNICODE_STRING securityDescriptor;

    // Only LocalSystem and built-in Administrators can open the control device.
    RtlInitUnicodeString(
        &securityDescriptor,
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"
        );

    deviceInit = WdfControlDeviceInitAllocate(
        Driver,
        &securityDescriptor
        );

    if (deviceInit == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetDeviceType(deviceInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetExclusive(deviceInit, FALSE);

    RtlInitUnicodeString(
        &deviceName,
        SERPIUM_FLOW_NT_DEVICE_NAME
        );

    status = WdfDeviceInitAssignName(
        deviceInit,
        &deviceName
        );

    if (!NT_SUCCESS(status))
    {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT(&deviceAttributes);

    status = WdfDeviceCreate(
        &deviceInit,
        &deviceAttributes,
        &device
        );

    if (!NT_SUCCESS(status))
    {
        if (deviceInit != NULL)
        {
            WdfDeviceInitFree(deviceInit);
        }

        return status;
    }

    RtlInitUnicodeString(
        &symbolicLinkName,
        SERPIUM_FLOW_DOS_DEVICE_NAME
        );

    status = WdfDeviceCreateSymbolicLink(
        device,
        &symbolicLinkName
        );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &queueConfig,
        WdfIoQueueDispatchSequential
        );

    queueConfig.EvtIoDeviceControl = SerpiumFlowEvtIoDeviceControl;

    status = WdfIoQueueCreate(
        device,
        &queueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        WDF_NO_HANDLE
        );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = SerpiumFlowWfpStart(
        WdfDeviceWdmGetDeviceObject(device)
        );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    WdfControlFinishInitializing(device);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
SerpiumFlowEvtIoDeviceControl(
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

    switch (IoControlCode)
    {
        case IOCTL_SERPIUM_FLOW_GET_STATUS:
        {
            PSERPIUM_FLOW_STATUS output = NULL;
            size_t outputSize = 0;

            status = WdfRequestRetrieveOutputBuffer(
                Request,
                sizeof(SERPIUM_FLOW_STATUS),
                (PVOID*)&output,
                &outputSize
                );

            if (NT_SUCCESS(status))
            {
                SerpiumFlowFillStatus(output);
                information = sizeof(*output);
            }

            break;
        }

        case IOCTL_SERPIUM_FLOW_PING:
        {
            PSERPIUM_FLOW_PING ping = NULL;
            size_t bufferSize = 0;

            status = WdfRequestRetrieveInputBuffer(
                Request,
                sizeof(SERPIUM_FLOW_PING),
                (PVOID*)&ping,
                &bufferSize
                );

            if (!NT_SUCCESS(status))
            {
                break;
            }

            if (
                ping->Size != sizeof(SERPIUM_FLOW_PING) ||
                ping->ProtocolVersion != SERPIUM_FLOW_PROTOCOL_VERSION
                )
            {
                status = STATUS_REVISION_MISMATCH;
                break;
            }

            ping->DriverTimestamp = SerpiumFlowQueryMilliseconds();
            information = sizeof(*ping);
            status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_SERPIUM_FLOW_DRAIN_OBSERVATIONS:
        {
            PSERPIUM_FLOW_OBSERVATION_BATCH batch = NULL;
            size_t outputSize = 0;

            status = WdfRequestRetrieveOutputBuffer(
                Request,
                sizeof(SERPIUM_FLOW_OBSERVATION_BATCH),
                (PVOID*)&batch,
                &outputSize
                );

            if (NT_SUCCESS(status))
            {
                information = SerpiumFlowDrainObservations(batch);
            }

            break;
        }

        case IOCTL_SERPIUM_FLOW_ADD_RULE:
        {
            PSERPIUM_FLOW_RULE_REQUEST input = NULL;
            PSERPIUM_FLOW_MUTATION_RESULT output = NULL;
            SERPIUM_FLOW_RULE_REQUEST request;
            size_t bufferSize = 0;
            BOOLEAN changed = FALSE;

            status = WdfRequestRetrieveInputBuffer(
                Request,
                sizeof(SERPIUM_FLOW_RULE_REQUEST),
                (PVOID*)&input,
                &bufferSize
                );

            if (!NT_SUCCESS(status))
            {
                break;
            }

            request = *input;

            status = WdfRequestRetrieveOutputBuffer(
                Request,
                sizeof(SERPIUM_FLOW_MUTATION_RESULT),
                (PVOID*)&output,
                &bufferSize
                );

            if (!NT_SUCCESS(status))
            {
                break;
            }

            status = SerpiumFlowAddRule(&request, &changed);

            if (NT_SUCCESS(status))
            {
                SerpiumFlowFillMutationResult(output, changed);
                information = sizeof(*output);
            }

            break;
        }

        case IOCTL_SERPIUM_FLOW_REMOVE_RULE:
        {
            PSERPIUM_FLOW_REMOVE_RULE_REQUEST input = NULL;
            PSERPIUM_FLOW_MUTATION_RESULT output = NULL;
            SERPIUM_FLOW_REMOVE_RULE_REQUEST request;
            size_t bufferSize = 0;
            BOOLEAN changed = FALSE;

            status = WdfRequestRetrieveInputBuffer(
                Request,
                sizeof(SERPIUM_FLOW_REMOVE_RULE_REQUEST),
                (PVOID*)&input,
                &bufferSize
                );

            if (!NT_SUCCESS(status))
            {
                break;
            }

            request = *input;

            status = WdfRequestRetrieveOutputBuffer(
                Request,
                sizeof(SERPIUM_FLOW_MUTATION_RESULT),
                (PVOID*)&output,
                &bufferSize
                );

            if (!NT_SUCCESS(status))
            {
                break;
            }

            status = SerpiumFlowRemoveRule(&request, &changed);

            if (NT_SUCCESS(status))
            {
                SerpiumFlowFillMutationResult(output, changed);
                information = sizeof(*output);
            }

            break;
        }

        case IOCTL_SERPIUM_FLOW_CLEAR_RULES:
        {
            PSERPIUM_FLOW_MUTATION_RESULT output = NULL;
            size_t outputSize = 0;
            BOOLEAN changed = FALSE;

            status = WdfRequestRetrieveOutputBuffer(
                Request,
                sizeof(SERPIUM_FLOW_MUTATION_RESULT),
                (PVOID*)&output,
                &outputSize
                );

            if (NT_SUCCESS(status))
            {
                SerpiumFlowClearRules(&changed);
                SerpiumFlowFillMutationResult(output, changed);
                information = sizeof(*output);
            }

            break;
        }

        case IOCTL_SERPIUM_FLOW_REPLACE_RULES:
        {
            PSERPIUM_FLOW_REPLACE_RULES_REQUEST input = NULL;
            PSERPIUM_FLOW_MUTATION_RESULT output = NULL;
            size_t bufferSize = 0;
            BOOLEAN changed = FALSE;

            status = WdfRequestRetrieveInputBuffer(
                Request,
                sizeof(SERPIUM_FLOW_REPLACE_RULES_REQUEST),
                (PVOID*)&input,
                &bufferSize
                );

            if (!NT_SUCCESS(status))
            {
                break;
            }

            status = WdfRequestRetrieveOutputBuffer(
                Request,
                sizeof(SERPIUM_FLOW_MUTATION_RESULT),
                (PVOID*)&output,
                &bufferSize
                );

            if (!NT_SUCCESS(status))
            {
                break;
            }

            status = SerpiumFlowReplaceRules(input, &changed);

            if (NT_SUCCESS(status))
            {
                SerpiumFlowFillMutationResult(output, changed);
                information = sizeof(*output);
            }

            break;
        }

        case IOCTL_SERPIUM_FLOW_ENUM_RULES:
        {
            PSERPIUM_FLOW_ENUM_REQUEST input = NULL;
            PSERPIUM_FLOW_RULE_BATCH output = NULL;
            SERPIUM_FLOW_ENUM_REQUEST request;
            size_t bufferSize = 0;

            status = WdfRequestRetrieveInputBuffer(
                Request,
                sizeof(SERPIUM_FLOW_ENUM_REQUEST),
                (PVOID*)&input,
                &bufferSize
                );

            if (!NT_SUCCESS(status))
            {
                break;
            }

            request = *input;

            if (
                request.Size != sizeof(request) ||
                request.ProtocolVersion != SERPIUM_FLOW_PROTOCOL_VERSION
                )
            {
                status = STATUS_REVISION_MISMATCH;
                break;
            }

            status = WdfRequestRetrieveOutputBuffer(
                Request,
                sizeof(SERPIUM_FLOW_RULE_BATCH),
                (PVOID*)&output,
                &bufferSize
                );

            if (NT_SUCCESS(status))
            {
                information =
                    SerpiumFlowEnumerateRules(
                        request.StartIndex,
                        output
                        );
            }

            break;
        }

        case IOCTL_SERPIUM_FLOW_ENUM_FLOWS:
        {
            PSERPIUM_FLOW_ENUM_REQUEST input = NULL;
            PSERPIUM_FLOW_FLOW_BATCH output = NULL;
            SERPIUM_FLOW_ENUM_REQUEST request;
            size_t bufferSize = 0;

            status = WdfRequestRetrieveInputBuffer(
                Request,
                sizeof(SERPIUM_FLOW_ENUM_REQUEST),
                (PVOID*)&input,
                &bufferSize
                );

            if (!NT_SUCCESS(status))
            {
                break;
            }

            request = *input;

            if (
                request.Size != sizeof(request) ||
                request.ProtocolVersion != SERPIUM_FLOW_PROTOCOL_VERSION
                )
            {
                status = STATUS_REVISION_MISMATCH;
                break;
            }

            status = WdfRequestRetrieveOutputBuffer(
                Request,
                sizeof(SERPIUM_FLOW_FLOW_BATCH),
                (PVOID*)&output,
                &bufferSize
                );

            if (NT_SUCCESS(status))
            {
                information =
                    SerpiumFlowEnumerateFlows(
                        request.StartIndex,
                        output
                        );
            }

            break;
        }

        case IOCTL_SERPIUM_FLOW_CONFIGURE_ROUTE:
        {
            PSERPIUM_FLOW_ROUTE_CONFIG_REQUEST input = NULL;
            PSERPIUM_FLOW_ROUTE_CONFIG_RESULT output = NULL;
            SERPIUM_FLOW_ROUTE_CONFIG_REQUEST request;
            size_t bufferSize = 0;
            BOOLEAN changed = FALSE;

            status = WdfRequestRetrieveInputBuffer(
                Request,
                sizeof(SERPIUM_FLOW_ROUTE_CONFIG_REQUEST),
                (PVOID*)&input,
                &bufferSize
                );

            if (!NT_SUCCESS(status))
            {
                break;
            }

            request = *input;

            status = WdfRequestRetrieveOutputBuffer(
                Request,
                sizeof(SERPIUM_FLOW_ROUTE_CONFIG_RESULT),
                (PVOID*)&output,
                &bufferSize
                );

            if (!NT_SUCCESS(status))
            {
                break;
            }

            status = SerpiumFlowConfigureRoute(&request, &changed);

            if (NT_SUCCESS(status))
            {
                SerpiumFlowFillRouteConfigResult(output, changed);
                information = sizeof(*output);
            }

            break;
        }

        case IOCTL_SERPIUM_FLOW_DISARM_ROUTE:
        {
            PSERPIUM_FLOW_ROUTE_CONFIG_RESULT output = NULL;
            size_t outputSize = 0;
            BOOLEAN changed = FALSE;

            status = WdfRequestRetrieveOutputBuffer(
                Request,
                sizeof(SERPIUM_FLOW_ROUTE_CONFIG_RESULT),
                (PVOID*)&output,
                &outputSize
                );

            if (NT_SUCCESS(status))
            {
                SerpiumFlowDisarmRoute(&changed);
                SerpiumFlowFillRouteConfigResult(output, changed);
                information = sizeof(*output);
            }

            break;
        }

        default:
        {
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }

    WdfRequestCompleteWithInformation(
        Request,
        status,
        information
        );
}
