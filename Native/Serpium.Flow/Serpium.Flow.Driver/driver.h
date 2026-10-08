#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ntstrsafe.h>

#include "..\Serpium.Flow.Protocol\serpium_flow_protocol.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD SerpiumFlowEvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL SerpiumFlowEvtIoDeviceControl;

NTSTATUS
SerpiumFlowCreateControlDevice(
    _In_ WDFDRIVER Driver
    );

NTSTATUS
SerpiumFlowWfpStart(
    _In_ PDEVICE_OBJECT DeviceObject
    );

VOID
SerpiumFlowWfpStop(
    VOID
    );

VOID
NTAPI
SerpiumFlowClassifyV4(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_ const FWPS_FILTER0* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
    );

VOID
NTAPI
SerpiumFlowClassifyV6(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_ const FWPS_FILTER0* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
    );

NTSTATUS
NTAPI
SerpiumFlowNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID* FilterKey,
    _Inout_ FWPS_FILTER0* Filter
    );
