#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ntstrsafe.h>

#include "..\Serpium.SFP.Protocol\serpium_sfp_protocol.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD SerpiumSfpEvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_READ SerpiumSfpEvtIoRead;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL SerpiumSfpEvtIoDeviceControl;

NTSTATUS
SerpiumSfpCreateControlDevice(
    _In_ WDFDRIVER Driver
    );

NTSTATUS
SerpiumSfpStart(
    _In_ PDEVICE_OBJECT DeviceObject
    );

VOID
SerpiumSfpStop(
    VOID
    );

VOID
NTAPI
SerpiumSfpAuthClassifyV4(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_ const FWPS_FILTER0* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
    );

VOID
NTAPI
SerpiumSfpAuthClassifyV6(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_ const FWPS_FILTER0* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
    );

VOID
NTAPI
SerpiumSfpFlowClassifyV4(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_ const FWPS_FILTER0* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
    );

VOID
NTAPI
SerpiumSfpFlowClassifyV6(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_ const FWPS_FILTER0* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
    );

VOID
NTAPI
SerpiumSfpFlowDelete(
    _In_ UINT16 LayerId,
    _In_ UINT32 CalloutId,
    _In_ UINT64 FlowContext
    );

NTSTATUS
NTAPI
SerpiumSfpNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID* FilterKey,
    _Inout_ FWPS_FILTER0* Filter
    );


VOID
NTAPI
SerpiumSfpRedirectClassifyV4(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_opt_ const VOID* ClassifyContext,
    _In_ const FWPS_FILTER1* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
    );

VOID
NTAPI
SerpiumSfpRedirectClassifyV6(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_opt_ const VOID* ClassifyContext,
    _In_ const FWPS_FILTER1* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
    );
