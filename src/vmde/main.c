/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2013 - 2017
*
*  TITLE:       MAIN.C
*
*  DATE:        30 Apr 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

#define PROGRAM_NAME TEXT("Virtual Machine Detector")
#define VERSION_NAME TEXT("VMD 1.1 build 20 30/04/2017")

//output data
#define VM_VPC TEXT("VirtualPC VM")
#define VM_VMWARE TEXT("VMWare VM")
#define VM_PARALLELS TEXT("Parallels VM")
#define VM_VBOX TEXT("VirtualBox VM")
#define VM_UNKNOWN  TEXT("Unknown VM")
#define VM_MSHV TEXT("Microsoft VMM")
#define VM_VMWAREHV TEXT("VMWare VMM")
#define VM_PRLHV TEXT("Parallels VMM")
#define VM_SANDBOXIE TEXT("Sandboxie present")
#define VM_SANDBOXIE_INSIDE TEXT("Inside Sandboxie")
#define VM_SANDBOXED TEXT("Running inside Sandboxie")
#define VM_UNKNOWNHV TEXT("Unknown VMM")
#define VM_HYPER_V TEXT("Microsoft Hyper-V")

BOOL        g_IsWow64 = FALSE;
BOOL        g_IsWin64 = FALSE;
HANDLE      g_ConOut = NULL;
HANDLE      g_ConIn = NULL;
BOOL        g_ConsoleOutput = FALSE;
WCHAR       g_BE = 0xFEFF;

RTL_OSVERSIONINFOW g_osver;
SYSTEM_INFO g_siSysInfo;
CONSOLE_SCREEN_BUFFER_INFO g_csbi;

/*
* DetectSystemInfo
*
* Purpose:
*
* Remember system version and system info to global variables.
*
*/
VOID DetectSystemInfo(
    VOID
)
{
    NTSTATUS Status;

    g_IsWin64 = supIs64BitWindows(&g_IsWow64);
    if (g_IsWow64) {
        GetNativeSystemInfo(&g_siSysInfo);
    }
    else {
        GetSystemInfo(&g_siSysInfo);
    }

    RtlSecureZeroMemory(&g_osver, sizeof(g_osver));
    g_osver.dwOSVersionInfoSize = sizeof(g_osver);

    Status = RtlGetVersion(&g_osver);
    if (NT_SUCCESS(Status)) {
        if (g_osver.dwMajorVersion < 6) {
            supEnablePrivilege(SE_DEBUG_PRIVILEGE, TRUE);
        }
    }
}

/*
* PrintResult
*
* Purpose:
*
* Parse flags and output result.
*
*/
VOID PrintResult(
    _In_ LPWSTR Text,
    _In_ DETECT_FLAG Flags
)
{
    SetConsoleTextAttribute(g_ConOut, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    cuiPrintText(g_ConOut, Text, g_ConsoleOutput, TRUE);
    SetConsoleTextAttribute(g_ConOut, g_csbi.wAttributes);

    if (Flags == DETECT_BASE_NOTHING) {
        SetConsoleTextAttribute(g_ConOut, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        cuiPrintText(g_ConOut, TEXT("Nothing detected"), g_ConsoleOutput, TRUE);
        SetConsoleTextAttribute(g_ConOut, g_csbi.wAttributes);
        return;
    }

    SetConsoleTextAttribute(g_ConOut, FOREGROUND_RED | FOREGROUND_INTENSITY);

    if (Flags & DETECT_HYPERVISOR_BIT) {
        cuiPrintText(g_ConOut, TEXT("Hypervisor Bit"), g_ConsoleOutput, TRUE);
    }
    if (Flags & DETECT_DEVICE_OBJECT_NAME) {
        cuiPrintText(g_ConOut, TEXT("Device Object Name"), g_ConsoleOutput, TRUE);
    }
    if (Flags & DETECT_DRIVER_OBJECT_NAME) {
        cuiPrintText(g_ConOut, TEXT("Driver Object Name"), g_ConsoleOutput, TRUE);
    }
    if (Flags & DETECT_MUTEX_NAME) {
        cuiPrintText(g_ConOut, TEXT("Mutex Object Name"), g_ConsoleOutput, TRUE);
    }
    if (Flags & DETECT_PORT_NAME) {
        cuiPrintText(g_ConOut, TEXT("Port Object Name"), g_ConsoleOutput, TRUE);
    }
    if (Flags & DETECT_DIRECTORY_OBJECT_NAME) {
        cuiPrintText(g_ConOut, TEXT("Object Directory Name"), g_ConsoleOutput, TRUE);
    }
    if (Flags & DETECT_HANDLE_TABLE) {
        cuiPrintText(g_ConOut, TEXT("Handle Table"), g_ConsoleOutput, TRUE);
    }
    if (Flags & DETECT_MEMORY_TAG) {
        cuiPrintText(g_ConOut, TEXT("Memory Tag"), g_ConsoleOutput, TRUE);
    }
    if (Flags & DETECT_VIRTUAL_REGISTRY) {
        cuiPrintText(g_ConOut, TEXT("Virtual Registry"), g_ConsoleOutput, TRUE);
    }
    if (Flags & DETECT_INSTRUCTION_BACKDOOR) {
        cuiPrintText(g_ConOut, TEXT("Instruction Backdoor"), g_ConsoleOutput, TRUE);
    }
    if (Flags & DETECT_SIGNATURE_SCAN_FIRM) {
        cuiPrintText(g_ConOut, TEXT("Signature Scan Firmware"), g_ConsoleOutput, TRUE);
    }
    if (Flags & DETECT_SIGNATURE_SCAN_RSMB) {
        cuiPrintText(g_ConOut, TEXT("Signature Scan RSMB"), g_ConsoleOutput, TRUE);
    }
    if (Flags & DETECT_PCI_HWID) {
        cuiPrintText(g_ConOut, TEXT("PCI Hardware ID"), g_ConsoleOutput, TRUE);
    }
    SetConsoleTextAttribute(g_ConOut, g_csbi.wAttributes);
}

/*
* DetectVMS
*
* Purpose:
*
* Execute detection methods.
*
*/
VOID DetectVMS(
    VOID
)
{
    BOOL Found = FALSE;
    ULONG HvType = 0;
    DETECT_FLAG Flags = DETECT_BASE_NOTHING;

    WCHAR szOutput[MAX_PATH];

    RtlSecureZeroMemory(szOutput, sizeof(szOutput));

    Found = IsSandboxiePresent(&Flags);
    PrintResult(TEXT("[VMDE] Checking for SandboxIE"), Flags);

    if (Found) {
        Flags = DETECT_BASE_NOTHING;
        AmISandboxed(&Flags);
        PrintResult(TEXT("\n[VMDE] Checking for Sandboxing"), Flags);
    }

    Flags = DETECT_BASE_NOTHING;
    Found = IsHypervisor(&Flags);
    PrintResult(TEXT("\n[VMDE] Checking for Hypervisor"), Flags);

    if (Found) {
        HvType = GetHypervisorType();

        SetConsoleTextAttribute(g_ConOut, FOREGROUND_RED | FOREGROUND_INTENSITY);
        _strcpy(szOutput, TEXT("Detected "));

        switch (HvType) {
        case 1:
            _strcat(szOutput, TEXT("Microsoft Hv")); //Viridian
            break;
        case 2:
            _strcat(szOutput, TEXT("VMWare Hv"));
            break;
        case 3:
            _strcat(szOutput, TEXT("Parallels Hv"));
            break;
        case 4:
            _strcat(szOutput, TEXT("VirtualBox Hv"));
            break;
        default:
            _strcat(szOutput, TEXT("Unknown Hv"));
            break;
        }

        cuiPrintText(g_ConOut, szOutput, g_ConsoleOutput, TRUE);
    }

    SetConsoleTextAttribute(g_ConOut, g_csbi.wAttributes);

    Flags = DETECT_BASE_NOTHING;
    CheckForParallelsVM(&Flags);
    PrintResult(TEXT("\n[VMDE] Checking for Parallels"), Flags);

    Flags = DETECT_BASE_NOTHING;
    CheckForVMWareVM(&Flags);
    PrintResult(TEXT("\n[VMDE] Checking for VMWare"), Flags);

#ifndef _WIN64
    //there is no x64 guests support
    Flags = DETECT_BASE_NOTHING;
    CheckForVirtualPC(&Flags);
    PrintResult(TEXT("\n[VMDE] Checking for VirtualPC"), Flags);

#endif
    Flags = DETECT_BASE_NOTHING;
    CheckForVirtualBoxVM(&Flags);
    PrintResult(TEXT("\n[VMDE] Checking for VirtualBox"), Flags);
}

/*
* main
*
* Purpose:
*
* Program entry point.
*
*/
VOID main(
    VOID
)
{
    DWORD l;
    INPUT_RECORD inp1;
    WCHAR szOutput[100];

    __security_init_cookie();

    g_ConOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_ConOut != INVALID_HANDLE_VALUE) {

        g_ConsoleOutput = TRUE;
        if (!GetConsoleMode(g_ConOut, &l)) {
            g_ConsoleOutput = FALSE;
        }

        SetConsoleMode(g_ConOut, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_OUTPUT);
        if (g_ConsoleOutput == FALSE) {
            WriteFile(g_ConOut, &g_BE, sizeof(WCHAR), &l, NULL);
        }
        g_csbi.wAttributes = 0;
        GetConsoleScreenBufferInfo(g_ConOut, &g_csbi);

        cuiClrScr(g_ConOut);

        DetectSystemInfo();

        InitializeListHead(&VendorsListHead);

        EnumPCIDevsReg();

        DetectVMS();

#ifdef _DEBUG
        DumpFirmwareTable();
#endif

        g_ConIn = GetStdHandle(STD_INPUT_HANDLE);
        if (g_ConIn != INVALID_HANDLE_VALUE) {
            _strcpy(szOutput, TEXT("\nPress Enter for exit"));
            cuiPrintText(g_ConOut, szOutput, g_ConsoleOutput, TRUE);
            RtlSecureZeroMemory(&inp1, sizeof(inp1));
            ReadConsoleInput(GetStdHandle(STD_INPUT_HANDLE), &inp1, 1, &l);
            ReadConsole(g_ConIn, &szOutput, sizeof(szOutput), &l, NULL);
        }
    }

    ExitProcess((UINT)0);
}
