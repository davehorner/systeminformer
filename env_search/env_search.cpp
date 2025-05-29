// env_search.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <iostream>
#include <windows.h>
#include "ph.h" // Ensure this header is available in your include path
#include "phnative.h"
#include "ksisup.h" // Add this include for PhInitializeKsi
#include <tlhelp32.h> // Add this include for process enumeration
#include "kphuser.h"


    HANDLE tokenHandle;

    if (NT_SUCCESS(PhOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES,
        &tokenHandle
        )))
    {
        const LUID_AND_ATTRIBUTES privileges[] =
        {
            { RtlConvertUlongToLuid(SE_DEBUG_PRIVILEGE), SE_PRIVILEGE_ENABLED },
            { RtlConvertUlongToLuid(SE_INC_BASE_PRIORITY_PRIVILEGE), SE_PRIVILEGE_ENABLED },
            { RtlConvertUlongToLuid(SE_INC_WORKING_SET_PRIVILEGE), SE_PRIVILEGE_ENABLED },
            { RtlConvertUlongToLuid(SE_LOAD_DRIVER_PRIVILEGE), SE_PRIVILEGE_ENABLED },
            { RtlConvertUlongToLuid(SE_PROF_SINGLE_PROCESS_PRIVILEGE), SE_PRIVILEGE_ENABLED },
            { RtlConvertUlongToLuid(SE_BACKUP_PRIVILEGE), SE_PRIVILEGE_ENABLED },
            { RtlConvertUlongToLuid(SE_RESTORE_PRIVILEGE), SE_PRIVILEGE_ENABLED },
            { RtlConvertUlongToLuid(SE_SHUTDOWN_PRIVILEGE), SE_PRIVILEGE_ENABLED },
            { RtlConvertUlongToLuid(SE_TAKE_OWNERSHIP_PRIVILEGE), SE_PRIVILEGE_ENABLED },
            { RtlConvertUlongToLuid(SE_SECURITY_PRIVILEGE), SE_PRIVILEGE_ENABLED },
        };
        UCHAR privilegesBuffer[FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges) + sizeof(privileges)];
        PTOKEN_PRIVILEGES tokenPrivileges;

        tokenPrivileges = (PTOKEN_PRIVILEGES)privilegesBuffer;
        tokenPrivileges->PrivilegeCount = RTL_NUMBER_OF(privileges);
        memcpy(tokenPrivileges->Privileges, privileges, sizeof(privileges));

        NtAdjustPrivilegesToken(
            tokenHandle,
            FALSE,
            tokenPrivileges,
            0,
            NULL,
            NULL
            );

        NtClose(tokenHandle);
    }
DWORD EngineSetDebugPrivilege(HANDLE hProcess, bool bEnablePrivilege)
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tokenPrivileges;
    LUID luid;

    if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return GetLastError();

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
    {
        DWORD err = GetLastError();
        CloseHandle(hToken);
        return err;
    }

    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = luid;
    tokenPrivileges.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        DWORD err = GetLastError();
        CloseHandle(hToken);
        return err;
    }

    CloseHandle(hToken);
    return ERROR_SUCCESS;
}

int wmain(int argc, wchar_t* argv[])
{
    // Enable SeDebugPrivilege
    DWORD result = EngineSetDebugPrivilege(GetCurrentProcess(), true);
    if (result != ERROR_SUCCESS) {
        std::wcerr << L"Failed to enable debug privilege. Error: " << result << std::endl;
        return 1;
    }

    // Initialize the kernel driver (KPH) using the PH API
    PhInitializeKsi();

    // Check if the driver is loaded and at a sufficient privilege level
    KPH_LEVEL level = KsiLevel();
    if (level < KphLevelLow) {
        std::wcerr << L"Kernel driver is not loaded or insufficient privilege. Please run as administrator and ensure the driver is enabled." << std::endl;
        return 1;
    }

    DWORD pid = 0;

    if (argc != 2)
    {
        // Try to find a running notepad.exe
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE)
        {
            PROCESSENTRY32W pe = { sizeof(pe) };
            if (Process32FirstW(hSnap, &pe))
            {
                do
                {
                    if (_wcsicmp(pe.szExeFile, L"notepad.exe") == 0)
                    {
                        pid = pe.th32ProcessID;
                        break;
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }

        if (pid == 0)
        {
            std::wcerr << L"No running notepad.exe found, starting notepad.exe...\n";
            STARTUPINFOW si = { sizeof(si) };
            PROCESS_INFORMATION pi = {};
            if (CreateProcessW(
                L"C:\\Windows\\System32\\notepad.exe",
                nullptr,
                nullptr,
                nullptr,
                FALSE,
                0,
                nullptr,
                nullptr,
                &si,
                &pi))
            {
                pid = pi.dwProcessId;
                std::wcout << L"Notepad started. PID: " << pid << std::endl;
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                // Optionally, wait a moment for process to initialize
                Sleep(500);
            }
            else
            {
                std::wcerr << L"Failed to start notepad.exe. Error: " << GetLastError() << std::endl;
                return 1;
            }
        }
        else
        {
            std::wcout << L"Found running notepad.exe. PID: " << pid << std::endl;
        }
    }
    else
    {
        pid = _wtoi(argv[1]);
    }

    std::wcout << L"Searching environment variables for process ID: " << pid << std::endl;

    HANDLE hProcess = nullptr;
    NTSTATUS status = PhOpenProcess(
        &hProcess,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
        (HANDLE)(ULONG_PTR)pid // Cast DWORD to HANDLE
    );
    if (!NT_SUCCESS(status) || !hProcess)
    {
        std::wcerr << L"Failed to open process. NTSTATUS: 0x" << std::hex << status << std::endl;
        return 1;
    }

    // Use PH API to check WOW64 status
    BOOLEAN isWow64Process = FALSE;
    PhGetProcessIsWow64(hProcess, &isWow64Process);

    PVOID envBlock = nullptr;
    ULONG envLen = 0;
    status = PhGetProcessEnvironment(hProcess, isWow64Process, &envBlock, &envLen);
    if (!NT_SUCCESS(status))
    {
        std::wcerr << L"Failed to get process environment. NTSTATUS: 0x" << std::hex << status << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    ULONG key = 0;
    PH_ENVIRONMENT_VARIABLE var;
    while (PhEnumProcessEnvironmentVariables(envBlock, envLen, &key, &var) == STATUS_SUCCESS)
    {
        wprintf(L"%.*s = %.*s\n",
            (int)(var.Name.Length / sizeof(WCHAR)), var.Name.Buffer,
            (int)(var.Value.Length / sizeof(WCHAR)), var.Value.Buffer);
    }

    PhFree(envBlock);
    CloseHandle(hProcess);
    return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
