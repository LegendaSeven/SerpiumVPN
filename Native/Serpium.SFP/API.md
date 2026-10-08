# Serpium Flow Platform API v1

Kernel ABI remains frozen at `0x00010001`.

The public user-mode API has a separate ABI:

```text
0x00010000
```

and is exposed locally through:

```text
\\.\pipe\Serpium.SFP.v1
```

## Product boundary

```text
SerpiumVPN.exe
      |
      | SfpClient
      v
\\.\pipe\Serpium.SFP.v1
      |
      v
Serpium.SFP.ApiHost.exe
      |
      | stable frozen kernel ABI
      v
\\.\SerpiumSfp
      |
      v
Serpium.SFP.Kernel.sys
```

The GUI no longer needs to know WFP layers, IOCTL layouts, AppId hashes or
policy generations.

## API operations

- GetStatus
- SetDefaultRoute(DIRECT/VPN, hardCutover)
- SetAppRoute(exe, DIRECT/VPN, hardCutover)
- RemoveAppRoute(exe, hardCutover)
- ResetPolicy(hardCutover)
- GetPolicy
- GetFlows
- AbortAppFlows(exe)

Route mutations calculate the canonical WFP application ID, select a generation
greater than both saved state and kernel state, atomically replace the complete
kernel policy, persist the accepted state, and optionally perform hard cutover.

For a default-route hard cutover the API uses the existing flow-query ABI to
collect unique active application hashes and abort their stale generations.
No kernel change is required.

## Partial completion and errors

The kernel ABI and the API v1 message layouts are unchanged. These additional
result codes are nonzero, so existing v1 clients already treat them as errors:

| Result | Meaning |
|---|---|
| 9 | Policy applied to the kernel, but not persisted |
| 10 | Policy applied and persisted, but hard cutover incomplete |
| 11 | Policy applied, persistence failed, and hard cutover incomplete |
| 12 | Standalone AbortAppFlows failed or could not confirm completion |

For 9–11, no rollback is performed: the accepted policy remains active and
GetPolicy reports it. A restart can restore an older policy if persistence
failed. When both steps fail, Win32Error describes the persistence failure;
result 11 additionally identifies incomplete cutover. Hard cutover is attempted
even when saving fails. A false result is never reported as full success.

Hard cutover checks IOCTL failures, failed-abort counts, flow-query failures,
truncated results, and the frozen kernel ABI's 2048-flow per-app abort snapshot
limit. A full snapshot is reported as incomplete because this ABI cannot prove
that additional stale flows were not omitted. This does not provide an atomic
network transition: policy replacement and flow termination remain separate
operations, and new connections can occur concurrently.

CLI prints the partial-completion reason and exits nonzero. SfpApiException
retains the numeric ApiResult and Win32Error, and exposes Result, PolicyApplied,
PersistenceFailed and CutoverIncomplete. PolicyApplied=false means the error
does not assert a successful policy change; it is not a rollback guarantee for
transport failures. AbortAppFlowsAsync also checks the old v1 success response
for unsuccessful abort counts.

Mutations are serialized across API clients through apply, save and cutover.
The kernel ABI stays frozen at 0x00010001; the API version stays 0x00010000.

## Persistence

Accepted policy is stored under:

```text
%ProgramData%\Serpium\SFP\policy.state
```

The host loads the state on startup and, when the kernel is available, restores
it with a fresh monotonic generation.

## Local security

The Named Pipe rejects remote clients. LocalSystem and Administrators have full
access; interactive local users have read/write access. The kernel device itself
remains System/Administrators only.

This means normal Serpium UI can use a privileged/service API host without
opening the kernel device itself.

## Other computers

The API is local to each machine, not a network RPC service. On another PC the
same signed SFP system component and the same API host/client are installed;
Serpium uses the identical API there.

## C# usage

`Serpium.SFP.Client\SfpClient.cs` is ready to add to the C# application.

```csharp
var sfp = new SfpClient();

await sfp.SetAppRouteAsync(
    browserPath,
    SfpRoute.Vpn,
    hardCutover: true);
```
