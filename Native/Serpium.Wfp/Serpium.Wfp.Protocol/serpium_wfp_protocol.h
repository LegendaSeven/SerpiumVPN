#pragma once

//
// Serpium WFP clean-room protocol.
// Phase P1: event-driven observation only.
// No routing, redirect, blocking, packet injection, or old-flow teardown yet.
//

#define SERPIUM_WFP_PROTOCOL_VERSION       0x00010000u
#define SERPIUM_WFP_DRIVER_VERSION_MAJOR   1u
#define SERPIUM_WFP_DRIVER_VERSION_MINOR   0u
#define SERPIUM_WFP_DRIVER_VERSION_PATCH   0u

#define SERPIUM_WFP_NT_DEVICE_NAME         L"\\Device\\SerpiumWfp"
#define SERPIUM_WFP_DOS_DEVICE_NAME        L"\\DosDevices\\SerpiumWfp"
#define SERPIUM_WFP_WIN32_DEVICE_NAME      L"\\\\.\\SerpiumWfp"

#define SERPIUM_WFP_DEVICE_TYPE            0x8042u

#ifndef CTL_CODE
#include <winioctl.h>
#endif

#define IOCTL_SERPIUM_WFP_GET_STATUS \
    CTL_CODE(SERPIUM_WFP_DEVICE_TYPE, 0x800u, METHOD_BUFFERED, FILE_READ_DATA)

#define IOCTL_SERPIUM_WFP_PING \
    CTL_CODE(SERPIUM_WFP_DEVICE_TYPE, 0x801u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define SERPIUM_WFP_EVENT_CONNECT_ATTEMPT  1u
#define SERPIUM_WFP_EVENT_FLOW_OPEN        2u
#define SERPIUM_WFP_EVENT_FLOW_CLOSE       3u

#define SERPIUM_WFP_EVENT_FLAG_IPV6        0x00000001u
#define SERPIUM_WFP_EVENT_FLAG_APP_ID      0x00000002u
#define SERPIUM_WFP_EVENT_FLAG_PROCESS_ID  0x00000004u

#define SERPIUM_WFP_APP_ID_MAX_CHARS       520u
#define SERPIUM_WFP_EVENT_QUEUE_CAPACITY   2048u

typedef struct _SERPIUM_WFP_STATUS
{
    unsigned long Size;
    unsigned long ProtocolVersion;

    unsigned long DriverVersionMajor;
    unsigned long DriverVersionMinor;
    unsigned long DriverVersionPatch;

    unsigned long Flags;

    unsigned long long Uptime100ns;
    unsigned long long NextSequence;

    unsigned long long TotalEvents;
    unsigned long long DroppedEvents;

    unsigned long QueueCount;
    unsigned long QueueCapacity;

    unsigned long AuthCalloutIdV4;
    unsigned long AuthCalloutIdV6;
    unsigned long FlowCalloutIdV4;
    unsigned long FlowCalloutIdV6;
} SERPIUM_WFP_STATUS, *PSERPIUM_WFP_STATUS;

typedef struct _SERPIUM_WFP_PING
{
    unsigned long Size;
    unsigned long ProtocolVersion;
    unsigned long Sequence;
    unsigned long Reserved;
    unsigned long long ClientValue;
    unsigned long long DriverTimestamp100ns;
} SERPIUM_WFP_PING, *PSERPIUM_WFP_PING;

typedef struct _SERPIUM_WFP_EVENT
{
    unsigned long Size;
    unsigned long ProtocolVersion;

    unsigned long Type;
    unsigned long Flags;

    unsigned long long Sequence;
    unsigned long long Timestamp100ns;

    unsigned long long FlowId;
    unsigned long long ProcessId;

    unsigned short AddressFamily;
    unsigned char Protocol;
    unsigned char Reserved0;

    unsigned short LocalPort;
    unsigned short RemotePort;

    unsigned char LocalAddress[16];
    unsigned char RemoteAddress[16];

    unsigned long AppIdByteLength;
    unsigned long Reserved1;

    unsigned short AppId[SERPIUM_WFP_APP_ID_MAX_CHARS];
} SERPIUM_WFP_EVENT, *PSERPIUM_WFP_EVENT;
