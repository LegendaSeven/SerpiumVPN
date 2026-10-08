# SFP Runtime Gate v1

The kernel ABI is frozen at `0x00010001`.

`Serpium.SFP.Runtime.exe` is an explicit, demand-start runtime controller.

Commands:

```text
Serpium.SFP.Runtime.exe signature <sys>
Serpium.SFP.Runtime.exe start <sys>
Serpium.SFP.Runtime.exe probe
Serpium.SFP.Runtime.exe stop
Serpium.SFP.Runtime.exe smoke <sys>
```

`start` verifies the file with WinVerifyTrust, creates a temporary
`SERVICE_KERNEL_DRIVER` with `SERVICE_DEMAND_START`, lets the Windows kernel
loader make the final signature decision, opens `\\.\SerpiumSfp`, and checks
ABI `0x00010001`.

`smoke` performs start -> ABI probe -> stop/delete.

The patch application itself never starts the driver. It does not change boot
configuration, install the INF, or create a boot-start service.

The temporary service name is `SerpiumSfpRuntimeTest`.

A Windows error 577 (`ERROR_INVALID_IMAGE_HASH`) means the kernel loader
rejected the image/signature.
