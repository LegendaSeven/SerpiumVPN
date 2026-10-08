#pragma once

#include <stdint.h>

#define SERPIUM_SFP_API_MAGIC              0x41504653u /* "SFPA" */
#define SERPIUM_SFP_API_VERSION            0x00010000u
#define SERPIUM_SFP_API_PIPE_NAME          L"\\\\.\\pipe\\Serpium.SFP.v1"

#define SERPIUM_SFP_API_FLAG_HARD_CUTOVER  0x00000001u

#define SERPIUM_SFP_API_ROUTE_DIRECT       1u
#define SERPIUM_SFP_API_ROUTE_VPN          2u

#define SERPIUM_SFP_API_CMD_PING            1u
#define SERPIUM_SFP_API_CMD_GET_STATUS      2u
#define SERPIUM_SFP_API_CMD_SET_DEFAULT     3u
#define SERPIUM_SFP_API_CMD_SET_APP_ROUTE   4u
#define SERPIUM_SFP_API_CMD_REMOVE_APP      5u
#define SERPIUM_SFP_API_CMD_RESET_POLICY    6u
#define SERPIUM_SFP_API_CMD_GET_POLICY      7u
#define SERPIUM_SFP_API_CMD_GET_FLOWS       8u
#define SERPIUM_SFP_API_CMD_ABORT_APP       9u

#define SERPIUM_SFP_API_OK                  0u
#define SERPIUM_SFP_API_E_INVALID           1u
#define SERPIUM_SFP_API_E_PROTOCOL          2u
#define SERPIUM_SFP_API_E_KERNEL_OFFLINE    3u
#define SERPIUM_SFP_API_E_KERNEL_REJECTED   4u
#define SERPIUM_SFP_API_E_NOT_FOUND         5u
#define SERPIUM_SFP_API_E_IO                6u
#define SERPIUM_SFP_API_E_INTERNAL          7u
#define SERPIUM_SFP_API_E_TOO_LARGE         8u

/* For 9-11 the new policy is already active in the kernel; no rollback occurred.
   Win32Error describes persistence when both persistence and cutover failed. */
#define SERPIUM_SFP_API_E_POLICY_NOT_PERSISTED 9u
#define SERPIUM_SFP_API_E_CUTOVER_INCOMPLETE   10u
#define SERPIUM_SFP_API_E_PERSIST_AND_CUTOVER  11u
/* Standalone ABORT_APP failed or could not confirm completion. */
#define SERPIUM_SFP_API_E_ABORT_INCOMPLETE     12u

#define SERPIUM_SFP_API_MAX_PAYLOAD         (1024u * 1024u)

#pragma pack(push, 1)

typedef struct _SERPIUM_SFP_API_REQUEST_HEADER
{
    uint32_t Magic;
    uint32_t Version;
    uint32_t Command;
    uint32_t Flags;
    uint64_t RequestId;
    uint32_t PayloadBytes;
    uint32_t Reserved;
} SERPIUM_SFP_API_REQUEST_HEADER;

typedef struct _SERPIUM_SFP_API_RESPONSE_HEADER
{
    uint32_t Magic;
    uint32_t Version;
    uint32_t Command;
    uint32_t Result;
    uint64_t RequestId;
    uint32_t PayloadBytes;
    uint32_t Win32Error;
} SERPIUM_SFP_API_RESPONSE_HEADER;

typedef struct _SERPIUM_SFP_API_SET_DEFAULT_REQUEST
{
    uint32_t Route;
    uint32_t Reserved;
} SERPIUM_SFP_API_SET_DEFAULT_REQUEST;

typedef struct _SERPIUM_SFP_API_APP_ROUTE_REQUEST
{
    uint32_t Route;
    uint32_t PathChars;
    /* UTF-16 path follows, no NUL */
} SERPIUM_SFP_API_APP_ROUTE_REQUEST;

typedef struct _SERPIUM_SFP_API_APP_PATH_REQUEST
{
    uint32_t PathChars;
    uint32_t Reserved;
    /* UTF-16 path follows, no NUL */
} SERPIUM_SFP_API_APP_PATH_REQUEST;

typedef struct _SERPIUM_SFP_API_STATUS
{
    uint32_t ApiVersion;
    uint32_t KernelProtocolVersion;

    uint64_t PolicyGeneration;

    uint32_t DefaultRoute;
    uint32_t PolicyCount;
    uint32_t ActiveFlowCount;
    uint32_t BridgeArmed;

    uint64_t BridgeProcessId;
    uint64_t TotalRedirected;
    uint64_t TotalRedirectFailOpen;
} SERPIUM_SFP_API_STATUS;

typedef struct _SERPIUM_SFP_API_POLICY_HEADER
{
    uint64_t Generation;
    uint32_t DefaultRoute;
    uint32_t EntryCount;
} SERPIUM_SFP_API_POLICY_HEADER;

typedef struct _SERPIUM_SFP_API_POLICY_ENTRY
{
    uint64_t AppIdHash;
    uint32_t Route;
    uint32_t PathChars;
    /* UTF-16 path follows, no NUL */
} SERPIUM_SFP_API_POLICY_ENTRY;

typedef struct _SERPIUM_SFP_API_FLOWS_HEADER
{
    uint32_t Count;
    uint32_t Truncated;
} SERPIUM_SFP_API_FLOWS_HEADER;

typedef struct _SERPIUM_SFP_API_ABORT_RESPONSE
{
    uint32_t Matched;
    uint32_t Aborted;
    uint32_t Failed;
    uint32_t Reserved;
} SERPIUM_SFP_API_ABORT_RESPONSE;

#pragma pack(pop)
