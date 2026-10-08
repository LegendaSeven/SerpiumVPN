#pragma once

//
// Serpium Flow Platform (SFP) ABI v1.
//
// Core v1 owns:
//   - atomic app policy generation,
//   - explicit default DIRECT/VPN route,
//   - realtime CONNECT / FLOW_OPEN / FLOW_CLOSE event stream,
//   - active flow registry,
//   - stale-generation flow abort.
//
// Core v1 intentionally does NOT redirect traffic yet. Route values in events
// are kernel policy decisions. CONNECT_REDIRECT / SFP Bridge is the next layer.
//

#define SERPIUM_SFP_PROTOCOL_VERSION       0x00010001u
#define SERPIUM_SFP_KERNEL_VERSION_MAJOR   1u
#define SERPIUM_SFP_KERNEL_VERSION_MINOR   1u
#define SERPIUM_SFP_KERNEL_VERSION_PATCH   0u

#define SERPIUM_SFP_NT_DEVICE_NAME         L"\\Device\\SerpiumSfp"
#define SERPIUM_SFP_DOS_DEVICE_NAME        L"\\DosDevices\\SerpiumSfp"
#define SERPIUM_SFP_WIN32_DEVICE_NAME      L"\\\\.\\SerpiumSfp"

#define SERPIUM_SFP_DEVICE_TYPE            0x8043u

#ifndef CTL_CODE
#include <winioctl.h>
#endif

#define IOCTL_SERPIUM_SFP_GET_STATUS \
    CTL_CODE(SERPIUM_SFP_DEVICE_TYPE, 0x800u, METHOD_BUFFERED, FILE_READ_DATA)

#define IOCTL_SERPIUM_SFP_PING \
    CTL_CODE(SERPIUM_SFP_DEVICE_TYPE, 0x801u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_SERPIUM_SFP_REPLACE_POLICY \
    CTL_CODE(SERPIUM_SFP_DEVICE_TYPE, 0x802u, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_SERPIUM_SFP_QUERY_FLOWS \
    CTL_CODE(SERPIUM_SFP_DEVICE_TYPE, 0x803u, METHOD_BUFFERED, FILE_READ_DATA)

#define IOCTL_SERPIUM_SFP_ABORT_STALE \
    CTL_CODE(SERPIUM_SFP_DEVICE_TYPE, 0x804u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_SERPIUM_SFP_CONFIGURE_BRIDGE \
    CTL_CODE(SERPIUM_SFP_DEVICE_TYPE, 0x805u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_SERPIUM_SFP_DISARM_BRIDGE \
    CTL_CODE(SERPIUM_SFP_DEVICE_TYPE, 0x806u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define SERPIUM_SFP_ROUTE_UNSPECIFIED       0u
#define SERPIUM_SFP_ROUTE_DIRECT            1u
#define SERPIUM_SFP_ROUTE_VPN               2u

#define SERPIUM_SFP_EVENT_CONNECT_ATTEMPT   1u
#define SERPIUM_SFP_EVENT_FLOW_OPEN         2u
#define SERPIUM_SFP_EVENT_FLOW_CLOSE        3u
#define SERPIUM_SFP_EVENT_POLICY_REPLACED   4u
#define SERPIUM_SFP_EVENT_BRIDGE_CONFIGURED 5u
#define SERPIUM_SFP_EVENT_BRIDGE_DISARMED   6u

#define SERPIUM_SFP_EVENT_FLAG_IPV6         0x00000001u
#define SERPIUM_SFP_EVENT_FLAG_APP_ID       0x00000002u
#define SERPIUM_SFP_EVENT_FLAG_PROCESS_ID   0x00000004u
#define SERPIUM_SFP_EVENT_FLAG_POLICY_HIT   0x00000008u
#define SERPIUM_SFP_EVENT_FLAG_REDIRECTED   0x00000010u
#define SERPIUM_SFP_EVENT_FLAG_FAIL_OPEN    0x00000020u

#define SERPIUM_SFP_APP_ID_MAX_CHARS        520u
#define SERPIUM_SFP_EVENT_QUEUE_CAPACITY    2048u
#define SERPIUM_SFP_MAX_POLICY_ENTRIES      512u
#define SERPIUM_SFP_MAX_ABORT_SNAPSHOT      2048u
#define SERPIUM_SFP_MAX_BYPASS_PROCESSES    16u
#define SERPIUM_SFP_REDIRECT_CONTEXT_MAGIC  0x31504653u

typedef struct _SERPIUM_SFP_STATUS
{
    unsigned long Size;
    unsigned long ProtocolVersion;

    unsigned long KernelVersionMajor;
    unsigned long KernelVersionMinor;
    unsigned long KernelVersionPatch;
    unsigned long Flags;

    unsigned long long Uptime100ns;
    unsigned long long NextSequence;

    unsigned long long TotalEvents;
    unsigned long long DroppedEvents;

    unsigned long QueueCount;
    unsigned long QueueCapacity;

    unsigned long long PolicyGeneration;
    unsigned long PolicyCount;
    unsigned long DefaultRoute;

    unsigned long ActiveFlowCount;
    unsigned long Reserved0;

    unsigned long AuthCalloutIdV4;
    unsigned long AuthCalloutIdV6;
    unsigned long FlowCalloutIdV4;
    unsigned long FlowCalloutIdV6;

    unsigned long RedirectCalloutIdV4;
    unsigned long RedirectCalloutIdV6;

    unsigned long BridgeArmed;
    unsigned long BridgeListenPortV4;
    unsigned long BridgeListenPortV6;
    unsigned long BridgeBypassProcessCount;

    unsigned long long BridgeProcessId;
    unsigned long long TotalRedirected;
    unsigned long long TotalRedirectFailOpen;
} SERPIUM_SFP_STATUS, *PSERPIUM_SFP_STATUS;

typedef struct _SERPIUM_SFP_PING
{
    unsigned long Size;
    unsigned long ProtocolVersion;
    unsigned long Sequence;
    unsigned long Reserved;

    unsigned long long ClientValue;
    unsigned long long KernelTimestamp100ns;
} SERPIUM_SFP_PING, *PSERPIUM_SFP_PING;

typedef struct _SERPIUM_SFP_POLICY_ENTRY
{
    unsigned long long AppIdHash;
    unsigned long Route;
    unsigned long Reserved;
} SERPIUM_SFP_POLICY_ENTRY, *PSERPIUM_SFP_POLICY_ENTRY;

typedef struct _SERPIUM_SFP_POLICY_REPLACE_REQUEST
{
    unsigned long Size;
    unsigned long ProtocolVersion;

    unsigned long long Generation;

    unsigned long DefaultRoute;
    unsigned long EntryCount;

    SERPIUM_SFP_POLICY_ENTRY Entries[1];
} SERPIUM_SFP_POLICY_REPLACE_REQUEST, *PSERPIUM_SFP_POLICY_REPLACE_REQUEST;

typedef struct _SERPIUM_SFP_FLOW_RECORD
{
    unsigned long long FlowId;
    unsigned long long ProcessId;
    unsigned long long AppIdHash;
    unsigned long long PolicyGeneration;

    unsigned long Route;
    unsigned long Flags;

    unsigned short AddressFamily;
    unsigned char Protocol;
    unsigned char Reserved0;

    unsigned short LocalPort;
    unsigned short RemotePort;
} SERPIUM_SFP_FLOW_RECORD, *PSERPIUM_SFP_FLOW_RECORD;

typedef struct _SERPIUM_SFP_FLOW_QUERY_RESPONSE
{
    unsigned long Size;
    unsigned long ProtocolVersion;

    unsigned long TotalFlowCount;
    unsigned long ReturnedFlowCount;

    unsigned long Truncated;
    unsigned long Reserved;

    SERPIUM_SFP_FLOW_RECORD Flows[1];
} SERPIUM_SFP_FLOW_QUERY_RESPONSE, *PSERPIUM_SFP_FLOW_QUERY_RESPONSE;

typedef struct _SERPIUM_SFP_ABORT_STALE_REQUEST
{
    unsigned long Size;
    unsigned long ProtocolVersion;

    unsigned long long AppIdHash;
    unsigned long long KeepGeneration;
} SERPIUM_SFP_ABORT_STALE_REQUEST, *PSERPIUM_SFP_ABORT_STALE_REQUEST;

typedef struct _SERPIUM_SFP_ABORT_STALE_RESPONSE
{
    unsigned long Size;
    unsigned long ProtocolVersion;

    unsigned long Matched;
    unsigned long Aborted;

    unsigned long Failed;
    unsigned long Reserved;
} SERPIUM_SFP_ABORT_STALE_RESPONSE, *PSERPIUM_SFP_ABORT_STALE_RESPONSE;

typedef struct _SERPIUM_SFP_BRIDGE_CONFIG_REQUEST
{
    unsigned long Size;
    unsigned long ProtocolVersion;

    unsigned long long BridgeProcessId;

    unsigned long ListenPortV4;
    unsigned long ListenPortV6;

    unsigned long BypassProcessCount;
    unsigned long Reserved;

    unsigned long long BypassProcessIds[SERPIUM_SFP_MAX_BYPASS_PROCESSES];
} SERPIUM_SFP_BRIDGE_CONFIG_REQUEST, *PSERPIUM_SFP_BRIDGE_CONFIG_REQUEST;

typedef struct _SERPIUM_SFP_BRIDGE_CONFIG_RESPONSE
{
    unsigned long Size;
    unsigned long ProtocolVersion;

    unsigned long Armed;
    unsigned long ListenPortV4;
    unsigned long ListenPortV6;
    unsigned long BypassProcessCount;

    unsigned long long BridgeProcessId;
    unsigned long long TotalRedirected;
    unsigned long long TotalFailOpen;
} SERPIUM_SFP_BRIDGE_CONFIG_RESPONSE, *PSERPIUM_SFP_BRIDGE_CONFIG_RESPONSE;

typedef struct _SERPIUM_SFP_REDIRECT_CONTEXT
{
    unsigned long Size;
    unsigned long ProtocolVersion;
    unsigned long Magic;
    unsigned long Reserved0;

    unsigned long long AppIdHash;
    unsigned long long PolicyGeneration;

    unsigned long Route;
    unsigned long Reserved1;

    unsigned short AddressFamily;
    unsigned char Protocol;
    unsigned char Reserved2;

    unsigned short RemotePort;
    unsigned short Reserved3;

    unsigned char RemoteAddress[16];
} SERPIUM_SFP_REDIRECT_CONTEXT, *PSERPIUM_SFP_REDIRECT_CONTEXT;

typedef struct _SERPIUM_SFP_EVENT
{
    unsigned long Size;
    unsigned long ProtocolVersion;

    unsigned long Type;
    unsigned long Flags;

    unsigned long long Sequence;
    unsigned long long Timestamp100ns;

    unsigned long long FlowId;
    unsigned long long ProcessId;

    unsigned long long AppIdHash;
    unsigned long long PolicyGeneration;

    unsigned long Route;
    unsigned long ReservedRoute;

    unsigned short AddressFamily;
    unsigned char Protocol;
    unsigned char Reserved0;

    unsigned short LocalPort;
    unsigned short RemotePort;

    unsigned char LocalAddress[16];
    unsigned char RemoteAddress[16];

    unsigned long AppIdByteLength;
    unsigned long Reserved1;

    unsigned short AppId[SERPIUM_SFP_APP_ID_MAX_CHARS];
} SERPIUM_SFP_EVENT, *PSERPIUM_SFP_EVENT;
