#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ntstrsafe.h>

#include "..\Serpium.Wfp.Protocol\serpium_wfp_protocol.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD SerpiumWfpEvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_READ SerpiumWfpEvtIoRead;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL SerpiumWfpEvtIoDeviceControl;

NTSTATUS
SerpiumWfpCreateControlDevice(
    _In_ WDFDRIVER Driver
    );

NTSTATUS
SerpiumWfpStart(
    _In_ PDEVICE_OBJECT DeviceObject
    );

VOID
SerpiumWfpStop(
    VOID
    );

VOID
NTAPI
SerpiumWfpAuthClassifyV4(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_opt_ const VOID* ClassifyContext,
    _In_ const FWPS_FILTER0* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
    );

VOID
NTAPI
SerpiumWfpAuthClassifyV6(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_opt_ const VOID* ClassifyContext,
    _In_ const FWPS_FILTER0* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
    );

VOID
NTAPI
SerpiumWfpFlowClassifyV4(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_opt_ const VOID* ClassifyContext,
    _In_ const FWPS_FILTER0* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
    );

VOID
NTAPI
SerpiumWfpFlowClassifyV6(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_opt_ const VOID* ClassifyContext,
    _In_ const FWPS_FILTER0* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
    );

VOID
NTAPI
SerpiumWfpFlowDelete(
    _In_ UINT16 LayerId,
    _In_ UINT32 CalloutId,
    _In_ UINT64 FlowContext
    );

NTSTATUS
NTAPI
SerpiumWfpNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID* FilterKey,
    _Inout_ FWPS_FILTER0* Filter
    );
