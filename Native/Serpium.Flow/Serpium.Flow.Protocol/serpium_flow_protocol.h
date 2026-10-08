#pragma once

//
// Serpium Flow shared user/kernel protocol.
//
// WFP-4A adds guarded TCP/UDP connect redirection to a local transparent bridge.
// Patch A keeps domain-aware TCP selection using HTTP Host / TLS ClientHello
// SNI and adds application-scoped UDP forwarding through SOCKS5 UDP
// ASSOCIATE. QUIC hostname/domain matching is intentionally deferred.
// Enforcement is disarmed by default and protected by a short renewable lease.
// Any missing/invalid state fails open to DIRECT. Packet injection, blocking,
// kill-switch behavior, and old-flow termination are out of scope.
//


#define SERPIUM_FLOW_PROTOCOL_VERSION       0x00040000u
#define SERPIUM_FLOW_DRIVER_VERSION_MAJOR   4u
#define SERPIUM_FLOW_DRIVER_VERSION_MINOR   0u
#define SERPIUM_FLOW_DRIVER_VERSION_PATCH   0u

#define SERPIUM_FLOW_NT_DEVICE_NAME         L"\\Device\\SerpiumFlow"
#define SERPIUM_FLOW_DOS_DEVICE_NAME        L"\\DosDevices\\SerpiumFlow"
#define SERPIUM_FLOW_WIN32_DEVICE_NAME      L"\\\\.\\SerpiumFlow"

#define SERPIUM_FLOW_DEVICE_TYPE            0x8000u

#ifndef CTL_CODE
#include <winioctl.h>
#endif

#define IOCTL_SERPIUM_FLOW_GET_STATUS \
    CTL_CODE(SERPIUM_FLOW_DEVICE_TYPE, 0x800u, METHOD_BUFFERED, FILE_READ_DATA)

#define IOCTL_SERPIUM_FLOW_PING \
    CTL_CODE(SERPIUM_FLOW_DEVICE_TYPE, 0x801u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_SERPIUM_FLOW_DRAIN_OBSERVATIONS \
    CTL_CODE(SERPIUM_FLOW_DEVICE_TYPE, 0x802u, METHOD_BUFFERED, FILE_READ_DATA)

#define IOCTL_SERPIUM_FLOW_ADD_RULE \
    CTL_CODE(SERPIUM_FLOW_DEVICE_TYPE, 0x803u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_SERPIUM_FLOW_REMOVE_RULE \
    CTL_CODE(SERPIUM_FLOW_DEVICE_TYPE, 0x804u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_SERPIUM_FLOW_CLEAR_RULES \
    CTL_CODE(SERPIUM_FLOW_DEVICE_TYPE, 0x805u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_SERPIUM_FLOW_ENUM_RULES \
    CTL_CODE(SERPIUM_FLOW_DEVICE_TYPE, 0x806u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_SERPIUM_FLOW_ENUM_FLOWS \
    CTL_CODE(SERPIUM_FLOW_DEVICE_TYPE, 0x807u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_SERPIUM_FLOW_CONFIGURE_ROUTE \
    CTL_CODE(SERPIUM_FLOW_DEVICE_TYPE, 0x808u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_SERPIUM_FLOW_DISARM_ROUTE \
    CTL_CODE(SERPIUM_FLOW_DEVICE_TYPE, 0x809u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_SERPIUM_FLOW_REPLACE_RULES \
    CTL_CODE(SERPIUM_FLOW_DEVICE_TYPE, 0x80Au, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define SERPIUM_FLOW_STATUS_FLAG_DRIVER_READY               0x00000001u
#define SERPIUM_FLOW_STATUS_FLAG_CONTROL_DEVICE             0x00000002u
#define SERPIUM_FLOW_STATUS_FLAG_WFP_DISABLED               0x00000004u
#define SERPIUM_FLOW_STATUS_FLAG_CALLOUTS_REGISTERED        0x00000008u
#define SERPIUM_FLOW_STATUS_FLAG_FILTERS_ACTIVE             0x00000010u
#define SERPIUM_FLOW_STATUS_FLAG_OBSERVE_ONLY               0x00000020u
#define SERPIUM_FLOW_STATUS_FLAG_EVENT_QUEUE                0x00000040u
#define SERPIUM_FLOW_STATUS_FLAG_FAIL_OPEN                  0x00000080u
#define SERPIUM_FLOW_STATUS_FLAG_POLICY_TRANSPORT           0x00000100u
#define SERPIUM_FLOW_STATUS_FLAG_ROUTE_ENFORCEMENT_DISABLED 0x00000200u
#define SERPIUM_FLOW_STATUS_FLAG_APP_RULE_TABLE             0x00000400u
#define SERPIUM_FLOW_STATUS_FLAG_FLOW_TABLE                 0x00000800u
#define SERPIUM_FLOW_STATUS_FLAG_ROUTE_ENFORCEMENT_AVAILABLE 0x00001000u
#define SERPIUM_FLOW_STATUS_FLAG_ROUTE_ENFORCEMENT_ARMED     0x00002000u
#define SERPIUM_FLOW_STATUS_FLAG_TCP_CONNECT_REDIRECT        0x00004000u
#define SERPIUM_FLOW_STATUS_FLAG_ROUTE_LEASE_ACTIVE          0x00008000u
#define SERPIUM_FLOW_STATUS_FLAG_POLICY_BATCH_REPLACE        0x00010000u
#define SERPIUM_FLOW_STATUS_FLAG_UDP_CONNECT_REDIRECT        0x00020000u
#define SERPIUM_FLOW_STATUS_FLAG_DATAGRAM_DATA_CORE          0x00040000u
#define SERPIUM_FLOW_STATUS_FLAG_QUIC_TCP_FALLBACK           0x00080000u

#define SERPIUM_FLOW_OBSERVATION_FLAG_APP_ID_PRESENT      0x01u
#define SERPIUM_FLOW_OBSERVATION_FLAG_PROCESS_ID_PRESENT  0x02u
#define SERPIUM_FLOW_OBSERVATION_FLAG_IPV6                0x04u
#define SERPIUM_FLOW_OBSERVATION_FLAG_POLICY_MATCH        0x08u
#define SERPIUM_FLOW_OBSERVATION_FLAG_ROUTE_REDIRECTED    0x10u
#define SERPIUM_FLOW_OBSERVATION_FLAG_ROUTE_FAIL_OPEN     0x20u

#define SERPIUM_FLOW_MUTATION_FLAG_CHANGED                0x00000001u

#define SERPIUM_FLOW_ROUTE_CONFIG_FLAG_ARM                0x00000001u
#define SERPIUM_FLOW_ROUTE_CONFIG_FLAG_CHANGED            0x00000002u
#define SERPIUM_FLOW_ROUTE_CONFIG_FLAG_LEASE_ACTIVE       0x00000004u
#define SERPIUM_FLOW_ROUTE_CONFIG_FLAG_INSPECT_ALL_TCP     0x00000008u
#define SERPIUM_FLOW_ROUTE_CONFIG_FLAG_UDP_APP_ROUTING     0x00000010u
#define SERPIUM_FLOW_ROUTE_CONFIG_FLAG_QUIC_TCP_FALLBACK   0x00000020u
#define SERPIUM_FLOW_ROUTE_CONFIG_FLAG_DOMAIN_QUIC_FALLBACK 0x00000040u

#define SERPIUM_FLOW_LAYER_ALE_AUTH_CONNECT_V4   4u
#define SERPIUM_FLOW_LAYER_ALE_AUTH_CONNECT_V6   6u

#define SERPIUM_FLOW_ROUTE_UNSPECIFIED            0u
#define SERPIUM_FLOW_ROUTE_DIRECT                 1u
#define SERPIUM_FLOW_ROUTE_VPN                    2u

#define SERPIUM_FLOW_APP_ID_MAX_CHARS             260u
#define SERPIUM_FLOW_APP_ID_MAX_BYTES             ((SERPIUM_FLOW_APP_ID_MAX_CHARS - 1u) * 2u)
#define SERPIUM_FLOW_OBSERVATION_BATCH_MAX        32u
#define SERPIUM_FLOW_OBSERVATION_QUEUE_CAPACITY   256u
#define SERPIUM_FLOW_RULE_CAPACITY                128u
#define SERPIUM_FLOW_RULE_BATCH_MAX               32u
#define SERPIUM_FLOW_FLOW_CAPACITY                256u
#define SERPIUM_FLOW_FLOW_BATCH_MAX               32u
#define SERPIUM_FLOW_BYPASS_PID_CAPACITY           8u
#define SERPIUM_FLOW_ROUTE_LEASE_MIN_MILLISECONDS 3000u
#define SERPIUM_FLOW_ROUTE_LEASE_MAX_MILLISECONDS 30000u
#define SERPIUM_FLOW_REDIRECT_CONTEXT_MAGIC        0x34504653u

typedef struct _SERPIUM_FLOW_STATUS
{
    unsigned long Size;
    unsigned long ProtocolVersion;
    unsigned long DriverVersionMajor;
    unsigned long DriverVersionMinor;
    unsigned long DriverVersionPatch;
    unsigned long Flags;
    unsigned long Reserved;
    unsigned long long UptimeMilliseconds;
    unsigned long long TotalObserved;
    unsigned long long DroppedObservations;
    unsigned long QueuedObservations;
    unsigned long QueueCapacity;
    unsigned long CalloutIdV4;
    unsigned long CalloutIdV6;
    unsigned long PolicyGeneration;
    unsigned long RuleCount;
    unsigned long RuleCapacity;
    unsigned long FlowCount;
    unsigned long FlowCapacity;
    unsigned long Reserved2;
    unsigned long long TotalPolicyMatches;
    unsigned long long TotalPolicyMisses;
    unsigned long RedirectCalloutIdV4;
    unsigned long RedirectCalloutIdV6;
    unsigned long RouteConfigGeneration;
    unsigned long RouteLeaseRemainingMilliseconds;
    unsigned long long TotalRedirected;
    unsigned long long TotalRedirectFailures;
    unsigned long long TotalRouteFailOpen;
} SERPIUM_FLOW_STATUS, *PSERPIUM_FLOW_STATUS;

typedef struct _SERPIUM_FLOW_PING
{
    unsigned long Size;
    unsigned long ProtocolVersion;
    unsigned long Sequence;
    unsigned long Reserved;
    unsigned long long ClientTimestamp;
    unsigned long long DriverTimestamp;
} SERPIUM_FLOW_PING, *PSERPIUM_FLOW_PING;

typedef struct _SERPIUM_FLOW_OBSERVATION
{
    unsigned long Size;
    unsigned long ProtocolVersion;
    unsigned long long Sequence;
    unsigned long long TimestampMilliseconds;
    unsigned long long ProcessId;
    unsigned long Layer;
    unsigned short AddressFamily;
    unsigned char Protocol;
    unsigned char Flags;
    unsigned short LocalPort;
    unsigned short RemotePort;
    unsigned char RemoteAddress[16];
    unsigned long PolicyGeneration;
    unsigned long Route;
    unsigned long long RuleId;
    unsigned long AppIdByteLength;
    unsigned short AppId[SERPIUM_FLOW_APP_ID_MAX_CHARS];
} SERPIUM_FLOW_OBSERVATION, *PSERPIUM_FLOW_OBSERVATION;

typedef struct _SERPIUM_FLOW_OBSERVATION_BATCH
{
    unsigned long Size;
    unsigned long ProtocolVersion;
    unsigned long EventSize;
    unsigned long EventCount;
    unsigned long long TotalObserved;
    unsigned long long DroppedObservations;
    unsigned long RemainingObservations;
    unsigned long Reserved;
    SERPIUM_FLOW_OBSERVATION Events[SERPIUM_FLOW_OBSERVATION_BATCH_MAX];
} SERPIUM_FLOW_OBSERVATION_BATCH, *PSERPIUM_FLOW_OBSERVATION_BATCH;

typedef struct _SERPIUM_FLOW_RULE_REQUEST
{
    unsigned long Size;
    unsigned long ProtocolVersion;
    unsigned long long RuleId;
    unsigned long Route;
    unsigned long Flags;
    unsigned long AppIdByteLength;
    unsigned long Reserved;
    unsigned short AppId[SERPIUM_FLOW_APP_ID_MAX_CHARS];
} SERPIUM_FLOW_RULE_REQUEST, *PSERPIUM_FLOW_RULE_REQUEST;

typedef struct _SERPIUM_FLOW_REMOVE_RULE_REQUEST
{
    unsigned long Size;
    unsigned long ProtocolVersion;
    unsigned long long RuleId;
} SERPIUM_FLOW_REMOVE_RULE_REQUEST, *PSERPIUM_FLOW_REMOVE_RULE_REQUEST;

typedef struct _SERPIUM_FLOW_ENUM_REQUEST
{
    unsigned long Size;
    unsigned long ProtocolVersion;
    unsigned long StartIndex;
    unsigned long Reserved;
} SERPIUM_FLOW_ENUM_REQUEST, *PSERPIUM_FLOW_ENUM_REQUEST;

typedef struct _SERPIUM_FLOW_MUTATION_RESULT
{
    unsigned long Size;
    unsigned long ProtocolVersion;
    unsigned long Flags;
    unsigned long PolicyGeneration;
    unsigned long RuleCount;
    unsigned long FlowCount;
    unsigned long Reserved[2];
} SERPIUM_FLOW_MUTATION_RESULT, *PSERPIUM_FLOW_MUTATION_RESULT;

typedef struct _SERPIUM_FLOW_RULE_ENTRY
{
    unsigned long Size;
    unsigned long ProtocolVersion;
    unsigned long long RuleId;
    unsigned long Route;
    unsigned long Flags;
    unsigned long AppIdByteLength;
    unsigned long Reserved;
    unsigned short AppId[SERPIUM_FLOW_APP_ID_MAX_CHARS];
} SERPIUM_FLOW_RULE_ENTRY, *PSERPIUM_FLOW_RULE_ENTRY;

typedef struct _SERPIUM_FLOW_REPLACE_RULES_REQUEST
{
    unsigned long Size;
    unsigned long ProtocolVersion;
    unsigned long RuleCount;
    unsigned long Reserved;
    SERPIUM_FLOW_RULE_ENTRY Rules[SERPIUM_FLOW_RULE_CAPACITY];
} SERPIUM_FLOW_REPLACE_RULES_REQUEST, *PSERPIUM_FLOW_REPLACE_RULES_REQUEST;

typedef struct _SERPIUM_FLOW_RULE_BATCH
{
    unsigned long Size;
    unsigned long ProtocolVersion;
    unsigned long EntrySize;
    unsigned long EntryCount;
    unsigned long PolicyGeneration;
    unsigned long TotalCount;
    unsigned long NextIndex;
    unsigned long Reserved;
    SERPIUM_FLOW_RULE_ENTRY Entries[SERPIUM_FLOW_RULE_BATCH_MAX];
} SERPIUM_FLOW_RULE_BATCH, *PSERPIUM_FLOW_RULE_BATCH;

typedef struct _SERPIUM_FLOW_FLOW_ENTRY
{
    unsigned long Size;
    unsigned long ProtocolVersion;
    unsigned long long FlowId;
    unsigned long long FirstSeenMilliseconds;
    unsigned long long LastSeenMilliseconds;
    unsigned long long ObservationCount;
    unsigned long long ProcessId;
    unsigned long long RuleId;
    unsigned long PolicyGeneration;
    unsigned long Layer;
    unsigned short AddressFamily;
    unsigned char Protocol;
    unsigned char Flags;
    unsigned short LocalPort;
    unsigned short RemotePort;
    unsigned char RemoteAddress[16];
    unsigned long Route;
    unsigned long AppIdByteLength;
    unsigned short AppId[SERPIUM_FLOW_APP_ID_MAX_CHARS];
} SERPIUM_FLOW_FLOW_ENTRY, *PSERPIUM_FLOW_FLOW_ENTRY;

typedef struct _SERPIUM_FLOW_FLOW_BATCH
{
    unsigned long Size;
    unsigned long ProtocolVersion;
    unsigned long EntrySize;
    unsigned long EntryCount;
    unsigned long TotalCount;
    unsigned long NextIndex;
    unsigned long Reserved[2];
    SERPIUM_FLOW_FLOW_ENTRY Entries[SERPIUM_FLOW_FLOW_BATCH_MAX];
} SERPIUM_FLOW_FLOW_BATCH, *PSERPIUM_FLOW_FLOW_BATCH;

typedef struct _SERPIUM_FLOW_ROUTE_CONFIG_REQUEST
{
    unsigned long Size;
    unsigned long ProtocolVersion;
    unsigned long Flags;
    unsigned long LeaseMilliseconds;
    unsigned long long BridgeProcessId;
    unsigned long ListenPortV4;
    unsigned long ListenPortV6;
    unsigned long BypassProcessCount;
    unsigned long Reserved;
    unsigned long long BypassProcessIds[SERPIUM_FLOW_BYPASS_PID_CAPACITY];
} SERPIUM_FLOW_ROUTE_CONFIG_REQUEST, *PSERPIUM_FLOW_ROUTE_CONFIG_REQUEST;

typedef struct _SERPIUM_FLOW_ROUTE_CONFIG_RESULT
{
    unsigned long Size;
    unsigned long ProtocolVersion;
    unsigned long Flags;
    unsigned long ConfigGeneration;
    unsigned long LeaseRemainingMilliseconds;
    unsigned long ListenPortV4;
    unsigned long ListenPortV6;
    unsigned long BypassProcessCount;
    unsigned long long BridgeProcessId;
    unsigned long long TotalRedirected;
    unsigned long long TotalRedirectFailures;
    unsigned long long TotalFailOpen;
} SERPIUM_FLOW_ROUTE_CONFIG_RESULT, *PSERPIUM_FLOW_ROUTE_CONFIG_RESULT;

typedef struct _SERPIUM_FLOW_REDIRECT_CONTEXT
{
    unsigned long Size;
    unsigned long ProtocolVersion;
    unsigned long Magic;
    unsigned long PolicyGeneration;
    unsigned long long RuleId;
    unsigned long ResolvedRoute;
    unsigned short AddressFamily;
    unsigned char Protocol;
    unsigned char Reserved0;
    unsigned short RemotePort;
    unsigned short Reserved1;
    unsigned char RemoteAddress[16];
} SERPIUM_FLOW_REDIRECT_CONTEXT, *PSERPIUM_FLOW_REDIRECT_CONTEXT;
