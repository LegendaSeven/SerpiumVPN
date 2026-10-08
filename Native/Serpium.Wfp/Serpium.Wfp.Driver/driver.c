#include <initguid.h>
#include "driver.h"

#define SERPIUM_WFP_POOL_TAG 'pfWS'

DEFINE_GUID(
    SERPIUM_WFP_PROVIDER_KEY,
    0x78a3b3ac, 0x3dfb, 0x47a3, 0xa5, 0x13, 0x44, 0x81, 0x8a, 0x1f, 0x44, 0x01);

DEFINE_GUID(
    SERPIUM_WFP_SUBLAYER_KEY,
    0xeb89a96a, 0x7148, 0x4f55, 0xa8, 0x7d, 0x84, 0x93, 0x3f, 0x42, 0xe5, 0x32);

DEFINE_GUID(
    SERPIUM_WFP_AUTH_V4_CALLOUT_KEY,
    0x4a5f85d0, 0x65fd, 0x4dbc, 0xb7, 0x0c, 0xb1, 0x38, 0x5e, 0x17, 0x2a, 0x91);

DEFINE_GUID(
    SERPIUM_WFP_AUTH_V6_CALLOUT_KEY,
    0x21802dd4, 0x86a7, 0x4682, 0x91, 0x8d, 0x6d, 0xb2, 0x43, 0xc4, 0xc3, 0x49);

DEFINE_GUID(
    SERPIUM_WFP_FLOW_V4_CALLOUT_KEY,
    0x90ee4f75, 0x4575, 0x4f9f, 0x9c, 0x77, 0x9d, 0x0d, 0x69, 0x45, 0x53, 0xc3);

DEFINE_GUID(
    SERPIUM_WFP_FLOW_V6_CALLOUT_KEY,
    0x5788e59e, 0xd762, 0x4dda, 0x86, 0xf5, 0x40, 0x51, 0x31, 0x24, 0x87, 0xa5);

typedef struct _SERPIUM_WFP_FLOW_CONTEXT
{
    SERPIUM_WFP_EVENT Event;
} SERPIUM_WFP_FLOW_CONTEXT, *PSERPIUM_WFP_FLOW_CONTEXT;

typedef struct _SERPIUM_WFP_RUNTIME
{
    WDFDEVICE Device;
    WDFQUEUE PendingReadQueue;
    WDFSPINLOCK EventLock;

    SERPIUM_WFP_EVENT Events[SERPIUM_WFP_EVENT_QUEUE_CAPACITY];
    ULONG EventHead;
    ULONG EventCount;

    UINT64 NextSequence;
    UINT64 TotalEvents;
    UINT64 DroppedEvents;
    UINT64 Started100ns;

    HANDLE EngineHandle;

    UINT32 AuthCalloutIdV4;
    UINT32 AuthCalloutIdV6;
    UINT32 FlowCalloutIdV4;
    UINT32 FlowCalloutIdV6;

    BOOLEAN Started;
} SERPIUM_WFP_RUNTIME;

static SERPIUM_WFP_RUNTIME g_Runtime;

static
UINT64
SerpiumWfpNow100ns(
    VOID
    )
{
    return KeQueryInterruptTime();
}

static
VOID
SerpiumWfpResetRuntime(
    VOID
    )
{
    RtlZeroMemory(&g_Runtime, sizeof(g_Runtime));
    g_Runtime.Started100ns = SerpiumWfpNow100ns();
    g_Runtime.NextSequence = 1;
}

static
VOID
SerpiumWfpCopyAppId(
    _In_opt_ const FWP_BYTE_BLOB* AppId,
    _Inout_ PSERPIUM_WFP_EVENT Event
    )
{
    ULONG bytes;

    if (AppId == NULL || AppId->data == NULL || AppId->size == 0)
    {
        return;
    }

    bytes = AppId->size;

    if (bytes > ((SERPIUM_WFP_APP_ID_MAX_CHARS - 1u) * sizeof(WCHAR)))
    {
        bytes = (SERPIUM_WFP_APP_ID_MAX_CHARS - 1u) * sizeof(WCHAR);
    }

    RtlCopyMemory(Event->AppId, AppId->data, bytes);
    Event->AppId[bytes / sizeof(WCHAR)] = L'\0';
    Event->AppIdByteLength = bytes;
    Event->Flags |= SERPIUM_WFP_EVENT_FLAG_APP_ID;
}

static
VOID
SerpiumWfpCopyAddressV4(
    _In_ UINT32 Address,
    _Out_writes_bytes_(16) UCHAR Destination[16]
    )
{
    RtlZeroMemory(Destination, 16);
    RtlCopyMemory(Destination, &Address, sizeof(Address));
}

static
VOID
SerpiumWfpCopyAddressV6(
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
SerpiumWfpFillProcessId(
    _In_ const FWPS_INCOMING_METADATA_VALUES0* Metadata,
    _Inout_ PSERPIUM_WFP_EVENT Event
    )
{
    if ((Metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0)
    {
        Event->ProcessId = Metadata->processId;
        Event->Flags |= SERPIUM_WFP_EVENT_FLAG_PROCESS_ID;
    }
}

static
VOID
SerpiumWfpFillAuthEventV4(
    _In_ const FWPS_INCOMING_VALUES0* Values,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* Metadata,
    _Inout_ PSERPIUM_WFP_EVENT Event
    )
{
    RtlZeroMemory(Event, sizeof(*Event));

    Event->Size = sizeof(*Event);
    Event->ProtocolVersion = SERPIUM_WFP_PROTOCOL_VERSION;
    Event->Type = SERPIUM_WFP_EVENT_CONNECT_ATTEMPT;
    Event->AddressFamily = AF_INET;

    Event->Protocol =
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;

    Event->LocalPort =
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;

    Event->RemotePort =
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;

    SerpiumWfpCopyAddressV4(
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32,
        Event->LocalAddress);

    SerpiumWfpCopyAddressV4(
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32,
        Event->RemoteAddress);

    SerpiumWfpCopyAppId(
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID].value.byteBlob,
        Event);

    SerpiumWfpFillProcessId(Metadata, Event);
}

static
VOID
SerpiumWfpFillAuthEventV6(
    _In_ const FWPS_INCOMING_VALUES0* Values,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* Metadata,
    _Inout_ PSERPIUM_WFP_EVENT Event
    )
{
    RtlZeroMemory(Event, sizeof(*Event));

    Event->Size = sizeof(*Event);
    Event->ProtocolVersion = SERPIUM_WFP_PROTOCOL_VERSION;
    Event->Type = SERPIUM_WFP_EVENT_CONNECT_ATTEMPT;
    Event->AddressFamily = AF_INET6;
    Event->Flags |= SERPIUM_WFP_EVENT_FLAG_IPV6;

    Event->Protocol =
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL].value.uint8;

    Event->LocalPort =
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT].value.uint16;

    Event->RemotePort =
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16;

    SerpiumWfpCopyAddressV6(
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS].value.byteArray16,
        Event->LocalAddress);

    SerpiumWfpCopyAddressV6(
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16,
        Event->RemoteAddress);

    SerpiumWfpCopyAppId(
        Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID].value.byteBlob,
        Event);

    SerpiumWfpFillProcessId(Metadata, Event);
}

static
VOID
SerpiumWfpFillFlowEventV4(
    _In_ const FWPS_INCOMING_VALUES0* Values,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* Metadata,
    _In_ UINT64 FlowId,
    _Inout_ PSERPIUM_WFP_EVENT Event
    )
{
    RtlZeroMemory(Event, sizeof(*Event));

    Event->Size = sizeof(*Event);
    Event->ProtocolVersion = SERPIUM_WFP_PROTOCOL_VERSION;
    Event->Type = SERPIUM_WFP_EVENT_FLOW_OPEN;
    Event->FlowId = FlowId;
    Event->AddressFamily = AF_INET;

    Event->Protocol =
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL].value.uint8;

    Event->LocalPort =
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT].value.uint16;

    Event->RemotePort =
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT].value.uint16;

    SerpiumWfpCopyAddressV4(
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS].value.uint32,
        Event->LocalAddress);

    SerpiumWfpCopyAddressV4(
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS].value.uint32,
        Event->RemoteAddress);

    SerpiumWfpCopyAppId(
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_APP_ID].value.byteBlob,
        Event);

    SerpiumWfpFillProcessId(Metadata, Event);
}

static
VOID
SerpiumWfpFillFlowEventV6(
    _In_ const FWPS_INCOMING_VALUES0* Values,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* Metadata,
    _In_ UINT64 FlowId,
    _Inout_ PSERPIUM_WFP_EVENT Event
    )
{
    RtlZeroMemory(Event, sizeof(*Event));

    Event->Size = sizeof(*Event);
    Event->ProtocolVersion = SERPIUM_WFP_PROTOCOL_VERSION;
    Event->Type = SERPIUM_WFP_EVENT_FLOW_OPEN;
    Event->FlowId = FlowId;
    Event->AddressFamily = AF_INET6;
    Event->Flags |= SERPIUM_WFP_EVENT_FLAG_IPV6;

    Event->Protocol =
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL].value.uint8;

    Event->LocalPort =
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT].value.uint16;

    Event->RemotePort =
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT].value.uint16;

    SerpiumWfpCopyAddressV6(
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS].value.byteArray16,
        Event->LocalAddress);

    SerpiumWfpCopyAddressV6(
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS].value.byteArray16,
        Event->RemoteAddress);

    SerpiumWfpCopyAppId(
        Values->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_ALE_APP_ID].value.byteBlob,
        Event);

    SerpiumWfpFillProcessId(Metadata, Event);
}

static
BOOLEAN
SerpiumWfpPopEvent(
    _Out_ PSERPIUM_WFP_EVENT Event
    )
{
    BOOLEAN result = FALSE;

    WdfSpinLockAcquire(g_Runtime.EventLock);

    if (g_Runtime.EventCount > 0)
    {
        *Event = g_Runtime.Events[g_Runtime.EventHead];

        g_Runtime.EventHead =
            (g_Runtime.EventHead + 1u) % SERPIUM_WFP_EVENT_QUEUE_CAPACITY;

        g_Runtime.EventCount--;
        result = TRUE;
    }

    WdfSpinLockRelease(g_Runtime.EventLock);
    return result;
}

static
VOID
SerpiumWfpTrySatisfyReads(
    VOID
    )
{
    WDFREQUEST request;
    NTSTATUS status;

    for (;;)
    {
        SERPIUM_WFP_EVENT event;
        PSERPIUM_WFP_EVENT output = NULL;
        size_t outputSize = 0;

        status = WdfIoQueueRetrieveNextRequest(
            g_Runtime.PendingReadQueue,
            &request);

        if (!NT_SUCCESS(status))
        {
            return;
        }

        if (!SerpiumWfpPopEvent(&event))
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
            sizeof(SERPIUM_WFP_EVENT),
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
            sizeof(SERPIUM_WFP_EVENT));
    }
}

static
VOID
SerpiumWfpPushEvent(
    _In_ const SERPIUM_WFP_EVENT* Source
    )
{
    SERPIUM_WFP_EVENT event = *Source;
    ULONG tail;

    WdfSpinLockAcquire(g_Runtime.EventLock);

    event.Sequence = g_Runtime.NextSequence++;
    event.Timestamp100ns = SerpiumWfpNow100ns();

    if (g_Runtime.EventCount == SERPIUM_WFP_EVENT_QUEUE_CAPACITY)
    {
        g_Runtime.EventHead =
            (g_Runtime.EventHead + 1u) % SERPIUM_WFP_EVENT_QUEUE_CAPACITY;

        g_Runtime.EventCount--;
        g_Runtime.DroppedEvents++;
    }

    tail =
        (g_Runtime.EventHead + g_Runtime.EventCount) %
        SERPIUM_WFP_EVENT_QUEUE_CAPACITY;

    g_Runtime.Events[tail] = event;
    g_Runtime.EventCount++;
    g_Runtime.TotalEvents++;

    WdfSpinLockRelease(g_Runtime.EventLock);

    SerpiumWfpTrySatisfyReads();
}

static
VOID
SerpiumWfpPermit(
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
SerpiumWfpAuthClassifyV4(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    VOID* LayerData,
    const VOID* ClassifyContext,
    const FWPS_FILTER0* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    SERPIUM_WFP_EVENT event;

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    SerpiumWfpFillAuthEventV4(
        InFixedValues,
        InMetaValues,
        &event);

    SerpiumWfpPushEvent(&event);
    SerpiumWfpPermit(ClassifyOut);
}

_Use_decl_annotations_
VOID
NTAPI
SerpiumWfpAuthClassifyV6(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    VOID* LayerData,
    const VOID* ClassifyContext,
    const FWPS_FILTER0* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    SERPIUM_WFP_EVENT event;

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    SerpiumWfpFillAuthEventV6(
        InFixedValues,
        InMetaValues,
        &event);

    SerpiumWfpPushEvent(&event);
    SerpiumWfpPermit(ClassifyOut);
}

static
VOID
SerpiumWfpAttachFlowContext(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _In_ BOOLEAN IsV6,
    _In_ UINT32 CalloutId
    )
{
    UINT64 flowId;
    PSERPIUM_WFP_FLOW_CONTEXT context;
    NTSTATUS status;

    if ((InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) == 0)
    {
        return;
    }

    flowId = InMetaValues->flowHandle;

    context = (PSERPIUM_WFP_FLOW_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(*context),
        SERPIUM_WFP_POOL_TAG);

    if (context == NULL)
    {
        return;
    }

    RtlZeroMemory(context, sizeof(*context));

    if (IsV6)
    {
        SerpiumWfpFillFlowEventV6(
            InFixedValues,
            InMetaValues,
            flowId,
            &context->Event);
    }
    else
    {
        SerpiumWfpFillFlowEventV4(
            InFixedValues,
            InMetaValues,
            flowId,
            &context->Event);
    }

    status = FwpsFlowAssociateContext0(
        flowId,
        InFixedValues->layerId,
        CalloutId,
        (UINT64)(ULONG_PTR)context);

    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(context, SERPIUM_WFP_POOL_TAG);
        return;
    }

    SerpiumWfpPushEvent(&context->Event);
}

_Use_decl_annotations_
VOID
NTAPI
SerpiumWfpFlowClassifyV4(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    VOID* LayerData,
    const VOID* ClassifyContext,
    const FWPS_FILTER0* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);

    if (FlowContext == 0)
    {
        SerpiumWfpAttachFlowContext(
            InFixedValues,
            InMetaValues,
            FALSE,
            g_Runtime.FlowCalloutIdV4);
    }

    SerpiumWfpPermit(ClassifyOut);
}

_Use_decl_annotations_
VOID
NTAPI
SerpiumWfpFlowClassifyV6(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    VOID* LayerData,
    const VOID* ClassifyContext,
    const FWPS_FILTER0* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);

    if (FlowContext == 0)
    {
        SerpiumWfpAttachFlowContext(
            InFixedValues,
            InMetaValues,
            TRUE,
            g_Runtime.FlowCalloutIdV6);
    }

    SerpiumWfpPermit(ClassifyOut);
}

_Use_decl_annotations_
VOID
NTAPI
SerpiumWfpFlowDelete(
    UINT16 LayerId,
    UINT32 CalloutId,
    UINT64 FlowContext
    )
{
    PSERPIUM_WFP_FLOW_CONTEXT context;
    SERPIUM_WFP_EVENT closeEvent;

    UNREFERENCED_PARAMETER(LayerId);
    UNREFERENCED_PARAMETER(CalloutId);

    if (FlowContext == 0)
    {
        return;
    }

    context = (PSERPIUM_WFP_FLOW_CONTEXT)(ULONG_PTR)FlowContext;

    closeEvent = context->Event;
    closeEvent.Type = SERPIUM_WFP_EVENT_FLOW_CLOSE;

    SerpiumWfpPushEvent(&closeEvent);

    ExFreePoolWithTag(
        context,
        SERPIUM_WFP_POOL_TAG);
}

_Use_decl_annotations_
NTSTATUS
NTAPI
SerpiumWfpNotify(
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
SerpiumWfpRegisterRuntimeCallout(
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
    callout.notifyFn = SerpiumWfpNotify;
    callout.flowDeleteFn = FlowDeleteFunction;

    return FwpsCalloutRegister0(
        DeviceObject,
        &callout,
        CalloutId);
}

static
NTSTATUS
SerpiumWfpAddManagementCallout(
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
        L"Serpium WFP clean-room realtime telemetry callout";
    callout.applicableLayer = *LayerKey;
    callout.providerKey = (GUID*)&SERPIUM_WFP_PROVIDER_KEY;

    return FwpmCalloutAdd0(
        g_Runtime.EngineHandle,
        &callout,
        NULL,
        NULL);
}

static
NTSTATUS
SerpiumWfpAddInspectionFilter(
    _In_ const GUID* CalloutKey,
    _In_ const GUID* LayerKey,
    _In_ PWSTR Name
    )
{
    FWPM_FILTER0 filter;

    RtlZeroMemory(&filter, sizeof(filter));

    filter.displayData.name = Name;
    filter.displayData.description =
        L"Observation only; never blocks or redirects traffic";
    filter.layerKey = *LayerKey;
    filter.subLayerKey = SERPIUM_WFP_SUBLAYER_KEY;
    filter.providerKey = (GUID*)&SERPIUM_WFP_PROVIDER_KEY;
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey = *CalloutKey;
    filter.weight.type = FWP_EMPTY;

    return FwpmFilterAdd0(
        g_Runtime.EngineHandle,
        &filter,
        NULL,
        NULL);
}

_Use_decl_annotations_
NTSTATUS
SerpiumWfpStart(
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

    status = SerpiumWfpRegisterRuntimeCallout(
        DeviceObject,
        &SERPIUM_WFP_AUTH_V4_CALLOUT_KEY,
        SerpiumWfpAuthClassifyV4,
        NULL,
        &g_Runtime.AuthCalloutIdV4);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumWfpRegisterRuntimeCallout(
        DeviceObject,
        &SERPIUM_WFP_AUTH_V6_CALLOUT_KEY,
        SerpiumWfpAuthClassifyV6,
        NULL,
        &g_Runtime.AuthCalloutIdV6);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumWfpRegisterRuntimeCallout(
        DeviceObject,
        &SERPIUM_WFP_FLOW_V4_CALLOUT_KEY,
        SerpiumWfpFlowClassifyV4,
        SerpiumWfpFlowDelete,
        &g_Runtime.FlowCalloutIdV4);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = SerpiumWfpRegisterRuntimeCallout(
        DeviceObject,
        &SERPIUM_WFP_FLOW_V6_CALLOUT_KEY,
        SerpiumWfpFlowClassifyV6,
        SerpiumWfpFlowDelete,
        &g_Runtime.FlowCalloutIdV6);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    RtlZeroMemory(&session, sizeof(session));
    session.displayData.name =
        L"Serpium WFP CleanRoom P1";
    session.displayData.description =
        L"Dynamic observation-only WFP session";
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
    provider.providerKey = SERPIUM_WFP_PROVIDER_KEY;
    provider.displayData.name =
        L"Serpium WFP CleanRoom Provider";
    provider.displayData.description =
        L"Serpium event-driven WFP core";

    status = FwpmProviderAdd0(
        g_Runtime.EngineHandle,
        &provider,
        NULL);

    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    RtlZeroMemory(&subLayer, sizeof(subLayer));
    subLayer.subLayerKey = SERPIUM_WFP_SUBLAYER_KEY;
    subLayer.displayData.name =
        L"Serpium WFP CleanRoom Realtime";
    subLayer.displayData.description =
        L"Observe-only realtime application flow telemetry";
    subLayer.providerKey = (GUID*)&SERPIUM_WFP_PROVIDER_KEY;
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
    status = SerpiumWfpAddManagementCallout(&(calloutKey), &(layerKey), (nameText)); \
    if (!NT_SUCCESS(status)) goto Exit; \
    status = SerpiumWfpAddInspectionFilter(&(calloutKey), &(layerKey), (nameText)); \
    if (!NT_SUCCESS(status)) goto Exit;

    ADD_CALLOUT_AND_FILTER(
        SERPIUM_WFP_AUTH_V4_CALLOUT_KEY,
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        L"Serpium WFP AUTH_CONNECT V4");

    ADD_CALLOUT_AND_FILTER(
        SERPIUM_WFP_AUTH_V6_CALLOUT_KEY,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        L"Serpium WFP AUTH_CONNECT V6");

    ADD_CALLOUT_AND_FILTER(
        SERPIUM_WFP_FLOW_V4_CALLOUT_KEY,
        FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
        L"Serpium WFP FLOW_ESTABLISHED V4");

    ADD_CALLOUT_AND_FILTER(
        SERPIUM_WFP_FLOW_V6_CALLOUT_KEY,
        FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
        L"Serpium WFP FLOW_ESTABLISHED V6");

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

    SerpiumWfpStop();

    return status;
}

_Use_decl_annotations_
VOID
SerpiumWfpStop(
    VOID
    )
{
    g_Runtime.Started = FALSE;

    if (g_Runtime.EngineHandle != NULL)
    {
        FwpmEngineClose0(g_Runtime.EngineHandle);
        g_Runtime.EngineHandle = NULL;
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
SerpiumWfpEvtIoRead(
    WDFQUEUE Queue,
    WDFREQUEST Request,
    size_t Length
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Queue);

    if (Length < sizeof(SERPIUM_WFP_EVENT))
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

    SerpiumWfpTrySatisfyReads();
}

_Use_decl_annotations_
VOID
SerpiumWfpEvtIoDeviceControl(
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

    if (IoControlCode == IOCTL_SERPIUM_WFP_GET_STATUS)
    {
        PSERPIUM_WFP_STATUS output = NULL;
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
                SERPIUM_WFP_PROTOCOL_VERSION;

            output->DriverVersionMajor =
                SERPIUM_WFP_DRIVER_VERSION_MAJOR;
            output->DriverVersionMinor =
                SERPIUM_WFP_DRIVER_VERSION_MINOR;
            output->DriverVersionPatch =
                SERPIUM_WFP_DRIVER_VERSION_PATCH;

            output->Uptime100ns =
                SerpiumWfpNow100ns() -
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
                SERPIUM_WFP_EVENT_QUEUE_CAPACITY;

            output->AuthCalloutIdV4 =
                g_Runtime.AuthCalloutIdV4;
            output->AuthCalloutIdV6 =
                g_Runtime.AuthCalloutIdV6;
            output->FlowCalloutIdV4 =
                g_Runtime.FlowCalloutIdV4;
            output->FlowCalloutIdV6 =
                g_Runtime.FlowCalloutIdV6;

            information = sizeof(*output);
        }
    }
    else if (IoControlCode == IOCTL_SERPIUM_WFP_PING)
    {
        PSERPIUM_WFP_PING buffer = NULL;
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
                    SERPIUM_WFP_PROTOCOL_VERSION)
            {
                status = STATUS_REVISION_MISMATCH;
            }
            else
            {
                buffer->DriverTimestamp100ns =
                    SerpiumWfpNow100ns();

                information = sizeof(*buffer);
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
SerpiumWfpEvtDriverUnload(
    WDFDRIVER Driver
    )
{
    UNREFERENCED_PARAMETER(Driver);

    SerpiumWfpStop();
}

_Use_decl_annotations_
NTSTATUS
SerpiumWfpCreateControlDevice(
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
        SERPIUM_WFP_NT_DEVICE_NAME);

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
        SERPIUM_WFP_DOS_DEVICE_NAME);

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

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &defaultQueueConfig,
        WdfIoQueueDispatchParallel);

    defaultQueueConfig.EvtIoRead =
        SerpiumWfpEvtIoRead;

    defaultQueueConfig.EvtIoDeviceControl =
        SerpiumWfpEvtIoDeviceControl;

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

    status = SerpiumWfpStart(
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

    SerpiumWfpResetRuntime();

    WDF_DRIVER_CONFIG_INIT(
        &config,
        WDF_NO_EVENT_CALLBACK);

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = NULL;

    config.EvtDriverUnload =
        SerpiumWfpEvtDriverUnload;

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

    return SerpiumWfpCreateControlDevice(driver);
}
