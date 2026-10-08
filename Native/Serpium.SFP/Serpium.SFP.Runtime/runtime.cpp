#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsvc.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

#include <cwchar>
#include <iostream>
#include <string>

#include "..\Serpium.SFP.Protocol\serpium_sfp_protocol.h"

static const wchar_t* kServiceName = L"SerpiumSfpRuntimeTest";
static const wchar_t* kServiceDisplayName =
    L"Serpium SFP Runtime Test";

static std::wstring FormatError(DWORD error)
{
    wchar_t* message = nullptr;

    DWORD flags =
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS;

    DWORD count =
        FormatMessageW(
            flags,
            nullptr,
            error,
            0,
            reinterpret_cast<wchar_t*>(&message),
            0,
            nullptr);

    std::wstring result =
        count > 0 && message != nullptr
            ? message
            : L"<no system message>";

    if (message != nullptr)
        LocalFree(message);

    while (!result.empty() &&
           (result.back() == L'\r' ||
            result.back() == L'\n'))
    {
        result.pop_back();
    }

    return result;
}

static LONG VerifyAuthenticode(const std::wstring& path)
{
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA data = {};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags =
        WTD_CACHE_ONLY_URL_RETRIEVAL |
        WTD_SAFER_FLAG;

    GUID action =
        WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG result =
        WinVerifyTrust(
            nullptr,
            &action,
            &data);

    data.dwStateAction =
        WTD_STATEACTION_CLOSE;

    WinVerifyTrust(
        nullptr,
        &action,
        &data);

    return result;
}

static bool IsAdministrator()
{
    BOOL isMember = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority =
        SECURITY_NT_AUTHORITY;
    PSID administrators = nullptr;

    if (!AllocateAndInitializeSid(
            &ntAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &administrators))
    {
        return false;
    }

    CheckTokenMembership(
        nullptr,
        administrators,
        &isMember);

    FreeSid(administrators);
    return isMember != FALSE;
}

static bool ProbeKernelAbi()
{
    HANDLE device =
        CreateFileW(
            SERPIUM_SFP_WIN32_DEVICE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

    if (device == INVALID_HANDLE_VALUE)
    {
        DWORD error = GetLastError();

        std::wcerr
            << L"DEVICE_OPEN_FAILED Win32="
            << error
            << L" "
            << FormatError(error)
            << L"\n";

        return false;
    }

    SERPIUM_SFP_STATUS status = {};
    DWORD returned = 0;

    BOOL ok =
        DeviceIoControl(
            device,
            IOCTL_SERPIUM_SFP_GET_STATUS,
            nullptr,
            0,
            &status,
            sizeof(status),
            &returned,
            nullptr);

    CloseHandle(device);

    if (!ok)
    {
        DWORD error = GetLastError();

        std::wcerr
            << L"GET_STATUS_FAILED Win32="
            << error
            << L" "
            << FormatError(error)
            << L"\n";

        return false;
    }

    std::wcout
        << L"KernelProtocol=0x"
        << std::hex
        << status.ProtocolVersion
        << std::dec
        << L"\nKernelVersion="
        << status.KernelVersionMajor
        << L"."
        << status.KernelVersionMinor
        << L"."
        << status.KernelVersionPatch
        << L"\nPolicyGeneration="
        << status.PolicyGeneration
        << L"\nActiveFlows="
        << status.ActiveFlowCount
        << L"\nRedirectCalloutV4="
        << status.RedirectCalloutIdV4
        << L"\nRedirectCalloutV6="
        << status.RedirectCalloutIdV6
        << L"\nBridgeArmed="
        << status.BridgeArmed
        << L"\n";

    if (status.ProtocolVersion !=
        SERPIUM_SFP_PROTOCOL_VERSION)
    {
        std::wcerr
            << L"ABI_MISMATCH expected=0x"
            << std::hex
            << SERPIUM_SFP_PROTOCOL_VERSION
            << L" actual=0x"
            << status.ProtocolVersion
            << std::dec
            << L"\n";

        return false;
    }

    std::wcout
        << L"SERPIUM_SFP_RUNTIME_ABI_PASS\n";

    return true;
}

static SC_HANDLE OpenManager()
{
    return OpenSCManagerW(
        nullptr,
        nullptr,
        SC_MANAGER_CONNECT |
        SC_MANAGER_CREATE_SERVICE);
}

static bool StopAndDeleteDriver();

static SC_HANDLE CreateFreshDriverService(
    SC_HANDLE manager,
    const std::wstring& sysPath)
{
    SC_HANDLE oldService =
        OpenServiceW(
            manager,
            kServiceName,
            SERVICE_STOP |
            SERVICE_QUERY_STATUS |
            DELETE);

    if (oldService != nullptr)
    {
        SERVICE_STATUS status = {};
        ControlService(
            oldService,
            SERVICE_CONTROL_STOP,
            &status);

        for (int attempt = 0; attempt < 100; ++attempt)
        {
            SERVICE_STATUS_PROCESS state = {};
            DWORD needed = 0;

            if (!QueryServiceStatusEx(
                    oldService,
                    SC_STATUS_PROCESS_INFO,
                    reinterpret_cast<BYTE*>(&state),
                    sizeof(state),
                    &needed))
            {
                break;
            }

            if (state.dwCurrentState == SERVICE_STOPPED)
                break;

            Sleep(25);
        }

        DeleteService(oldService);
        CloseServiceHandle(oldService);

        for (int attempt = 0; attempt < 100; ++attempt)
        {
            SC_HANDLE check =
                OpenServiceW(
                    manager,
                    kServiceName,
                    SERVICE_QUERY_STATUS);

            if (check == nullptr &&
                GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
            {
                break;
            }

            if (check != nullptr)
                CloseServiceHandle(check);

            Sleep(25);
        }
    }

    return CreateServiceW(
        manager,
        kServiceName,
        kServiceDisplayName,
        SERVICE_START |
        SERVICE_STOP |
        SERVICE_QUERY_STATUS |
        DELETE,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        sysPath.c_str(),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr);
}

static bool WaitForState(
    SC_HANDLE service,
    DWORD desired,
    DWORD timeoutMs)
{
    DWORD start = GetTickCount();

    for (;;)
    {
        SERVICE_STATUS_PROCESS status = {};
        DWORD needed = 0;

        if (!QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                reinterpret_cast<BYTE*>(&status),
                sizeof(status),
                &needed))
        {
            return false;
        }

        if (status.dwCurrentState == desired)
            return true;

        if (desired == SERVICE_RUNNING &&
            status.dwCurrentState == SERVICE_STOPPED)
        {
            SetLastError(
                status.dwWin32ExitCode != 0
                    ? status.dwWin32ExitCode
                    : ERROR_SERVICE_NOT_ACTIVE);

            return false;
        }

        if (GetTickCount() - start >= timeoutMs)
        {
            SetLastError(ERROR_TIMEOUT);
            return false;
        }

        Sleep(50);
    }
}

static bool StartDriver(const std::wstring& sysPath)
{
    if (!IsAdministrator())
    {
        std::wcerr << L"ADMIN_REQUIRED\n";
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }

    SC_HANDLE manager = OpenManager();

    if (manager == nullptr)
        return false;

    SC_HANDLE service =
        CreateFreshDriverService(
            manager,
            sysPath);

    if (service == nullptr)
    {
        DWORD error = GetLastError();
        CloseServiceHandle(manager);
        SetLastError(error);
        return false;
    }

    if (!StartServiceW(
            service,
            0,
            nullptr))
    {
        DWORD error = GetLastError();

        DeleteService(service);
        CloseServiceHandle(service);
        CloseServiceHandle(manager);

        SetLastError(error);
        return false;
    }

    bool running =
        WaitForState(
            service,
            SERVICE_RUNNING,
            5000);

    DWORD waitError =
        running ? ERROR_SUCCESS : GetLastError();

    CloseServiceHandle(service);
    CloseServiceHandle(manager);

    if (!running)
    {
        SetLastError(waitError);
        return false;
    }

    return true;
}

static bool StopAndDeleteDriver()
{
    if (!IsAdministrator())
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return false;
    }

    SC_HANDLE manager = OpenManager();

    if (manager == nullptr)
        return false;

    SC_HANDLE service =
        OpenServiceW(
            manager,
            kServiceName,
            SERVICE_STOP |
            SERVICE_QUERY_STATUS |
            DELETE);

    if (service == nullptr)
    {
        DWORD error = GetLastError();
        CloseServiceHandle(manager);

        if (error == ERROR_SERVICE_DOES_NOT_EXIST)
            return true;

        SetLastError(error);
        return false;
    }

    SERVICE_STATUS serviceStatus = {};

    if (!ControlService(
            service,
            SERVICE_CONTROL_STOP,
            &serviceStatus))
    {
        DWORD error = GetLastError();

        if (error != ERROR_SERVICE_NOT_ACTIVE)
        {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            SetLastError(error);
            return false;
        }
    }
    else
    {
        if (!WaitForState(
                service,
                SERVICE_STOPPED,
                5000))
        {
            DWORD error = GetLastError();

            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            SetLastError(error);
            return false;
        }
    }

    if (!DeleteService(service))
    {
        DWORD error = GetLastError();

        if (error != ERROR_SERVICE_MARKED_FOR_DELETE)
        {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            SetLastError(error);
            return false;
        }
    }

    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return true;
}

static int ProbeSignature(const std::wstring& sysPath)
{
    DWORD attributes =
        GetFileAttributesW(
            sysPath.c_str());

    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        std::wcerr << L"SYS_NOT_FOUND\n";
        return 10;
    }

    LONG trust =
        VerifyAuthenticode(sysPath);

    std::wcout
        << L"AuthenticodeWinVerifyTrust="
        << trust
        << L"\n";

    if (trust == ERROR_SUCCESS)
    {
        std::wcout << L"AUTHENTICODE_VALID\n";
        return 0;
    }

    std::wcout << L"AUTHENTICODE_NOT_VALID\n";
    return 11;
}

static int StartCommand(const std::wstring& sysPath)
{
    int signature = ProbeSignature(sysPath);

    if (signature != 0)
    {
        std::wcerr
            << L"START_BLOCKED_BY_SIGNATURE_GATE\n";
        return 20;
    }

    if (!StartDriver(sysPath))
    {
        DWORD error = GetLastError();

        std::wcerr
            << L"DRIVER_START_FAILED Win32="
            << error
            << L" "
            << FormatError(error)
            << L"\n";

        if (error == ERROR_INVALID_IMAGE_HASH)
        {
            std::wcerr
                << L"WINDOWS_KERNEL_SIGNATURE_REJECTED\n";
        }

        return 21;
    }

    std::wcout << L"DRIVER_STARTED\n";

    if (!ProbeKernelAbi())
    {
        std::wcerr
            << L"ABI_PROBE_FAILED; stopping runtime test service\n";

        StopAndDeleteDriver();
        return 22;
    }

    std::wcout
        << L"SERPIUM_SFP_RUNTIME_START_PASS\n";

    return 0;
}

static int SmokeCommand(const std::wstring& sysPath)
{
    int start = StartCommand(sysPath);

    if (start != 0)
        return start;

    if (!StopAndDeleteDriver())
    {
        DWORD error = GetLastError();

        std::wcerr
            << L"DRIVER_STOP_FAILED Win32="
            << error
            << L" "
            << FormatError(error)
            << L"\n";

        return 30;
    }

    std::wcout
        << L"DRIVER_STOPPED_AND_SERVICE_DELETED\n"
        << L"SERPIUM_SFP_RUNTIME_SMOKE_PASS\n";

    return 0;
}

static void Usage()
{
    std::wcerr
        << L"Serpium.SFP.Runtime.exe commands:\n"
        << L"  signature <full-path-to-sys>\n"
        << L"  start     <full-path-to-sys>\n"
        << L"  probe\n"
        << L"  stop\n"
        << L"  smoke     <full-path-to-sys>\n\n"
        << L"start/smoke require Administrator.\n"
        << L"The controller does not change boot configuration.\n";
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2)
    {
        Usage();
        return 1;
    }

    std::wstring command = argv[1];

    if (_wcsicmp(command.c_str(), L"signature") == 0)
    {
        if (argc != 3)
        {
            Usage();
            return 1;
        }

        return ProbeSignature(argv[2]);
    }

    if (_wcsicmp(command.c_str(), L"start") == 0)
    {
        if (argc != 3)
        {
            Usage();
            return 1;
        }

        return StartCommand(argv[2]);
    }

    if (_wcsicmp(command.c_str(), L"probe") == 0)
        return ProbeKernelAbi() ? 0 : 2;

    if (_wcsicmp(command.c_str(), L"stop") == 0)
    {
        if (!StopAndDeleteDriver())
        {
            DWORD error = GetLastError();

            std::wcerr
                << L"DRIVER_STOP_FAILED Win32="
                << error
                << L" "
                << FormatError(error)
                << L"\n";

            return 3;
        }

        std::wcout
            << L"DRIVER_STOPPED_AND_SERVICE_DELETED\n";

        return 0;
    }

    if (_wcsicmp(command.c_str(), L"smoke") == 0)
    {
        if (argc != 3)
        {
            Usage();
            return 1;
        }

        return SmokeCommand(argv[2]);
    }

    Usage();
    return 1;
}
