/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       DETECT.C
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
#include <intrin.h>

//Firmware data
CHAR VENDOR_VBOX[] = { "VirtualBox" };
CHAR VENDOR_ORACLE[] = { "Oracle" };
CHAR VENDOR_INNOTEK[] = { "innotek" };
CHAR VENDOR_VMWARE[] = { "VMware" };
CHAR VENDOR_VPC[] = { "S3 Corp." };
CHAR VENDOR_PARALLELS[] = { "Parallels(R)" };

//SMB data
CHAR SMB_VMWARE[] = { "VMware, Inc." };
CHAR SMB_VPC[] = { "VS2005R2" }; // Microsoft Virtual Server 2005 R2 
CHAR SMB_PARALLELS[] = { "Parallels Software International" };
CHAR SMB_UNKNOWN[] = { "Virtual" };

LIST_ENTRY VendorsListHead;

#pragma section(".poi",	read,execute)

typedef unsigned long(*PASMFN)();

__declspec(allocate(".poi")) static const unsigned char query_vpc[32] = {
    //   push    ebx
    0x53,
    //   xor     ebx, ebx
    0x31, 0xDB,
    //   xor     eax, eax
    0x31, 0xc0,
    //   mov     al,1
    0xb0, 0x01,
    //   #ud
    0x0f, 0x3f,
    //   magic opcode
    0x0d, 0x00,
    //   xor     eax, eax
    0x31, 0xC0,
    //   test    ebx, ebx
    0x85, 0xdb,
    //   setz    al
    0x0F, 0x94, 0xC0,
    //   pop     ebx
    0x5B,
    //   retn
    0xC3
};

__declspec(allocate(".poi")) static const unsigned char query_vmware[34] = {
    //   push    rbx/ebx
    0x53,
    //   mov     eax, 0564D5868; 'VMXh'
    0xB8, 0x68, 0x58, 0x4D, 0x56,
    //   xor     ebx, ebx
    0x31, 0xDB,
    //   not     ebx
    0xF7, 0xD3,
    //   xor     ecx, ecx
    0x31, 0xC9,
    //   mov     cl, 0A
    0xB1, 0xA,
    //   xor     edx, edx
    0x31, 0xd2,
    //   mov     dl, 058; 'X'
    0xB2, 0x58,
    //   mov     dh, 056; 'V'
    0xB6, 0x56,
    //   in      eax, dx,
    0xED,
    //   xor     eax, eax
    0x31, 0xC0,
    //   cmp     ebx, 0564D5868; 'VMXh'
    0x81, 0xFB, 0x68, 0x58, 0x4D, 0x56,
    //   setz    al
    0x0F, 0x94, 0xC0,
    //   pop     rbx/ebx
    0x5B,
    //   retn
    0xC3
};

static PASMFN QueryVPCBackdoor = (PASMFN)query_vpc;
static PASMFN QueryVMWareBackdoor = (PASMFN)query_vmware;

/*
* IsVmwareGuest
*
* Purpose:
*
* Return TRUE on VMWare backdoor detection, FALSE otherwise.
*
*/
BOOL IsVMWareGuest()
{
    __try {
        return QueryVMWareBackdoor();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        //exception - privileged instruction
        return FALSE;
    }
}

/*
* IsVPCGuest
*
* Purpose:
*
* Return TRUE on VirtualPC backdoor detection, FALSE otherwise.
*
*/
BOOL IsVPCGuest()
{
    __try {
        return QueryVPCBackdoor();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        //exception - illegal instruction
        return FALSE;
    }
}

/*
* vIsInList
*
* Purpose:
*
* Return TRUE if the given VendorID is in list, FALSE otherwise.
*
*/
PVENDOR_ENTRY vIsInList(
    DWORD VendorID
)
{
    PLIST_ENTRY entry = VendorsListHead.Flink;
    PVENDOR_ENTRY vendorEntry;

    while ((entry != NULL) && (entry != &VendorsListHead)) {

        vendorEntry = CONTAINING_RECORD(entry, VENDOR_ENTRY, ListEntry);
        if (vendorEntry != NULL) {
            if (vendorEntry->VendorID == VendorID)
                return vendorEntry;
        }

        entry = entry->Flink;
    }
    return FALSE;
}

/*
* vExtractID
*
* Purpose:
*
* Extract ID from string.
*
*/
VOID vExtractID(
    PVENDOR_ENTRY entry
)
{
    WCHAR szBuffer[MAX_PATH + 1];

    if (entry == NULL) {
        return;
    }

    if (entry->VendorFullName[0] == 0)
        return;

    // e.g. "VEN_XXXX&DEV_XXXX&SUBSYS_XXXXXXXX&REV_XX" 
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    _strcpy_w(szBuffer, &entry->VendorFullName[4]);
    szBuffer[4] = 0;
    entry->VendorID = (DWORD)hextou64_w(szBuffer);

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    _strcpy_w(szBuffer, &entry->VendorFullName[13]);
    szBuffer[4] = 0;
    entry->DeviceID = (DWORD)hextou64_w(szBuffer);
}


/*
* CheckForVirtualPC
*
* Purpose:
*
* Detect VirtualPC VM.
* Note: there is no x64 Guest support in VirtualPC.
*
*/
VOID CheckForVirtualPC(
    _Out_ DETECT_FLAG *VirtualPC
)
{
    BOOL IsVM = FALSE;
    ULONG dwDataSize = 0L;
    SYSTEM_FIRMWARE_TABLE_INFORMATION *sfti = NULL;
    DETECT_FLAG Type = DETECT_BASE_NOTHING;

    // Devs of XP Mode we're so kind so they added special mutex, check it.
    if (supMutexExist(MUTEX_VPCXPMODE))
        Type |= DETECT_MUTEX_NAME;

    //  Use well-known trick with illegal instructions.
    if (IsVPCGuest())
        Type |= DETECT_INSTRUCTION_BACKDOOR;

    //
    // Query virtual pc device. 
    //
    if (supIsObjectExists(DEVICELINK, DEVICE_VIRTUALPC))
        Type |= DETECT_DEVICE_OBJECT_NAME;

    // Query virtual pc driver, reg. rights elevation. 
    if (supIsObjectExists(DRIVERLINK, DRIVER_VIRTUALPC))
        Type |= DETECT_DRIVER_OBJECT_NAME;

    // Scan raw firmware for specific string patterns. 
    sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, FIRM, 0xC0000);
    if (sfti) {
        IsVM = supScanDump((CHAR*)sfti, dwDataSize, VENDOR_VPC, (ULONG)_strlen_a(VENDOR_VPC));
        HeapFree(GetProcessHeap(), 0, sfti);
        if (IsVM != FALSE) {
            Type |= DETECT_SIGNATURE_SCAN_FIRM;
        }
    }

    // Scan raw smbios data for specific string patters.
    sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, RSMB, 0);
    if (sfti) {
        IsVM = supScanDump((CHAR*)sfti, dwDataSize, SMB_VPC, (ULONG)_strlen_a(SMB_VPC));
        HeapFree(GetProcessHeap(), 0, sfti);
        if (IsVM != FALSE) {
            Type |= DETECT_SIGNATURE_SCAN_RSMB;
        }
    }

    // Query S3 VID on PCI bus devices. 
    if (vIsInList(VID_S3MS) != NULL)
        Type |= DETECT_PCI_HWID;

    *VirtualPC = Type;
}

/*
* CheckForVMwareVM
*
* Purpose:
*
* Detect VMWare VM.
*
*/
VOID CheckForVMWareVM(
    _Out_ DETECT_FLAG *VMWare
)
{
    BOOL IsVM = FALSE;
    ULONG dwDataSize = 0L;
    SYSTEM_FIRMWARE_TABLE_INFORMATION *sfti = NULL;
    DETECT_FLAG Type = DETECT_BASE_NOTHING;

    // Query vmware additions device presence.
    if (supIsObjectExists(DEVICELINK, DEVICE_VMWARE))
        Type |= DETECT_DEVICE_OBJECT_NAME;

    //
    // Query vmware presence by hypervisor port.
    // http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1009458
    //   
    if (IsVMWareGuest()) Type |= DETECT_INSTRUCTION_BACKDOOR;

    // Scan raw firmware for specific string patterns.
    sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, FIRM, 0xC0000);
    if (sfti) {
        IsVM = supScanDump((CHAR*)sfti, dwDataSize, VENDOR_VMWARE, (ULONG)_strlen_a(VENDOR_VMWARE));
        HeapFree(GetProcessHeap(), 0, sfti);
        if (IsVM != FALSE) Type |= DETECT_SIGNATURE_SCAN_FIRM;
    }

    // Scan raw SMBIOS firmware table for specific string patterns.
    sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, RSMB, 0);
    if (sfti) {
        IsVM = supScanDump((CHAR*)sfti, dwDataSize, VENDOR_VMWARE, (ULONG)_strlen_a(VENDOR_VMWARE));
        if (IsVM == FALSE) {
            IsVM = supScanDump((CHAR*)sfti, dwDataSize, SMB_VMWARE, (ULONG)_strlen_a(SMB_VMWARE));
        }
        HeapFree(GetProcessHeap(), 0, sfti);
        if (IsVM) Type |= DETECT_SIGNATURE_SCAN_RSMB;
    }

    // Query VmWare VID on PCI bus devices.
    if (vIsInList(VID_VMWARE) != NULL)
        Type |= DETECT_PCI_HWID;

    *VMWare = Type;
}

/*
* CheckForParallelsVM
*
* Purpose:
*
* Detect Parallels VM.
*
*/
VOID CheckForParallelsVM(
    _Out_ DETECT_FLAG *Parallels
)
{
    BOOL IsVM = FALSE;
    ULONG dwDataSize = 0L;
    SYSTEM_FIRMWARE_TABLE_INFORMATION *sfti = NULL;
    DETECT_FLAG Type = DETECT_BASE_NOTHING;

    // query parallels additions device presence
    if (supIsObjectExists(DEVICELINK, DEVICE_PARALLELS1))
        Type |= DETECT_DEVICE_OBJECT_NAME;

    if (supIsObjectExists(DEVICELINK, DEVICE_PARALLELS2))
        Type |= DETECT_DEVICE_OBJECT_NAME;

    if (supIsObjectExists(DEVICELINK, DEVICE_PARALLELS3))
        Type |= DETECT_DEVICE_OBJECT_NAME;

    // Scan raw firmware for specific string patterns.
    sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, FIRM, 0xC0000);
    if (sfti) {
        IsVM = supScanDump((CHAR*)sfti, dwDataSize, VENDOR_PARALLELS, (ULONG)_strlen_a(VENDOR_PARALLELS));
        HeapFree(GetProcessHeap(), 0, sfti);
        if (IsVM != FALSE) Type |= DETECT_SIGNATURE_SCAN_FIRM;
    }

    // Scan raw SMBIOS firmware table for specific string patterns. 
    sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, RSMB, 0);
    if (sfti) {
        IsVM = supScanDump((CHAR*)sfti, dwDataSize, SMB_PARALLELS, (ULONG)_strlen_a(SMB_PARALLELS));
        HeapFree(GetProcessHeap(), 0, sfti);
        if (IsVM != FALSE) Type |= DETECT_SIGNATURE_SCAN_RSMB;
    }

    // Query Parallels on PCI bus devices.
    if (vIsInList(VID_PRLS) != NULL)
        Type |= DETECT_PCI_HWID;

    *Parallels = Type;
}

/*
* IsHypervisor
*
* Purpose:
*
* Query if hypervisor present.
*
*/
BOOL IsHypervisor(
    _Out_ DETECT_FLAG *Hypervisor
)
{
    int CPUInfo[4] = { -1 };
    DETECT_FLAG Type = DETECT_BASE_NOTHING;

    //
    // Query hypervisor presence.
    // http://msdn.microsoft.com/en-us/library/windows/hardware/ff538624(v=vs.85).aspx
    // be aware this detection can be bogus
    //

    __cpuid(CPUInfo, 1);
    if ((CPUInfo[2] >> 31) & 1) {
        Type |= DETECT_HYPERVISOR_BIT;
    }

    //
    // Hypervisor additional special case
    //
    if (supIsObjectExists(DEVICELINK, DEVICE_HYPER_V))
        Type |= DETECT_DEVICE_OBJECT_NAME;

    *Hypervisor = Type;
    return (Type != DETECT_BASE_NOTHING);
}

/*
* GetHypervisorType
*
* Purpose:
*
* Query hypervisor name using cpuid.
*
*/
BYTE GetHypervisorType(
    VOID
)
{
    BOOL bCond = FALSE;
    BYTE result = 0;
    int CPUInfo[4] = { -1 };

    char szHvProductName[MAX_PATH];

    do {

        RtlSecureZeroMemory(szHvProductName, sizeof(szHvProductName));
        __cpuid(CPUInfo, 0x40000000);

        supCopyMemory(szHvProductName, 12, CPUInfo + 1, 12);

        // http://msdn.microsoft.com/en-us/library/windows/hardware/ff542428(v=vs.85).aspx 
        if (_strcmpi_a(szHvProductName, "Microsoft Hv") == 0) {
            result = 1;
            break;
        }

        // http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1009458 
        if (_strcmpi_a(szHvProductName, "VMwareVMware") == 0) {
            result = 2;
            break;
        }

        // Parallels VMM
        if (_strcmpi_a(szHvProductName, " lrpepyh vr") == 0) {
            result = 3;
            break;
        }

        // VirtualBox VMM
        if (_strcmpi_a(szHvProductName, "VBoxVBoxVBox") == 0) {
            result = 4;
            break;
        }

    } while (bCond);

    return result;
}

/*
* CheckForVirtualBoxVM
*
* Purpose:
*
* Detect VirtualBox VM.
*
*/
VOID CheckForVirtualBoxVM(
    _Out_ DETECT_FLAG *VirtualBox
)
{
    BOOL IsVM = FALSE;
    ULONG dwDataSize = 0L;
    SYSTEM_FIRMWARE_TABLE_INFORMATION *sfti = NULL;
    DETECT_FLAG Type = DETECT_BASE_NOTHING;

    // Query vbox additions guest device.
    if (supIsObjectExists(DEVICELINK, DEVICE_VIRTUALBOX1))
        Type |= DETECT_DEVICE_OBJECT_NAME;

    // Query vbox additions symbolic link.
    if (supIsObjectExists(DEVICELINK, DEVICE_VIRTUALBOX2))
        Type |= DETECT_DEVICE_OBJECT_NAME;

    // Query vbox additions video driver, reg. rights elevation.
    if (supIsObjectExists(DRIVERLINK, DRIVER_VIRTUALBOX1))
        Type |= DETECT_DRIVER_OBJECT_NAME;

    // Query vbox additions mouse driver, reg. admin rights elevation.
    if (supIsObjectExists(DRIVERLINK, DRIVER_VIRTUALBOX2))
        Type |= DETECT_DRIVER_OBJECT_NAME;

    // Scan raw firmware for specific string patterns.
    sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, FIRM, 0xC0000);
    if (sfti) {
        IsVM = supScanDump((CHAR*)sfti, dwDataSize, VENDOR_VBOX, (ULONG)_strlen_a(VENDOR_VBOX));
        if (IsVM == FALSE) {
            IsVM = supScanDump((CHAR*)sfti, dwDataSize, VENDOR_ORACLE, (ULONG)_strlen_a(VENDOR_ORACLE));
        }
        if (IsVM == FALSE) {
            IsVM = supScanDump((CHAR*)sfti, dwDataSize, VENDOR_INNOTEK, (ULONG)_strlen_a(VENDOR_INNOTEK));
        }
        HeapFree(GetProcessHeap(), 0, sfti);

        if (IsVM != FALSE) Type |= DETECT_SIGNATURE_SCAN_FIRM;
    }

    // Scan raw SMBIOS firmware table for specific string patterns.
    sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, RSMB, 0);
    if (sfti) {
        IsVM = supScanDump((CHAR*)sfti, dwDataSize, VENDOR_VBOX, (ULONG)_strlen_a(VENDOR_VBOX));
        if (IsVM == FALSE) {
            IsVM = supScanDump((CHAR*)sfti, dwDataSize, VENDOR_ORACLE, (ULONG)_strlen_a(VENDOR_ORACLE));
        }
        if (IsVM == FALSE) {
            IsVM = supScanDump((CHAR*)sfti, dwDataSize, VENDOR_INNOTEK, (ULONG)_strlen_a(VENDOR_INNOTEK));
        }
        HeapFree(GetProcessHeap(), 0, sfti);

        if (IsVM != FALSE) Type |= DETECT_SIGNATURE_SCAN_RSMB;
    }

    // Query oracle VID on PCI bus devices. 
    if (vIsInList(VID_ORACLE) != NULL)
        Type |= DETECT_PCI_HWID;

    *VirtualBox = Type;
}

/*
* IsSandboxiePresent
*
* Purpose:
*
* Return TRUE on Sandboxie detection success, FALSE otherwise.
*
*/
BOOL IsSandboxiePresent(
    _Out_ DETECT_FLAG *Sandboxie
)
{
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING ustrName;
    HANDLE hObject = NULL;
    DETECT_FLAG Type = DETECT_BASE_NOTHING;

    // Check Sandboxie device.
    if (supIsObjectExists(DEVICELINK, DEVICE_SANDBOXIE))
        Type |= DETECT_DEVICE_OBJECT_NAME;

    // Check Sandboxie object directory presence.
    RtlSecureZeroMemory(&ustrName, sizeof(ustrName));
    RtlInitUnicodeString(&ustrName, DIRECTORY_SANDBOXIE);
    InitializeObjectAttributes(&attr, &ustrName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (NT_SUCCESS(NtOpenDirectoryObject(&hObject, DIRECTORY_QUERY, &attr))) {
        NtClose(hObject);
        Type |= DETECT_DIRECTORY_OBJECT_NAME;
    }

    // Query Sandboxie mutex.
    if (supMutexExist(MUTEX_SANDBOXIE))
        Type |= DETECT_MUTEX_NAME;

    if (supMutexExist(MUTEX_SANDBOXIE2))
        Type |= DETECT_MUTEX_NAME;

    // Query Sandboxie rpc port presence.
    if (supIsObjectExists(RPCCONTROLLINK, PORT_SANDBOXIE))
        Type |= DETECT_PORT_NAME;

    // Query driver object, reg. rights elevation.
    if (supIsObjectExists(DRIVERLINK, DRIVER_SANDBOXIE))
        Type |= DETECT_DRIVER_OBJECT_NAME;

    *Sandboxie = Type;
    return (Type != DETECT_BASE_NOTHING);
}

/*
* IsSandboxieVirtualRegistryPresent
*
* Purpose:
*
* Return TRUE if Sandboxie registry virtualization detected, FALSE otherwise.
*
*/
BOOL IsSandboxieVirtualRegistryPresent(
    VOID
)
{
    BOOL IsSB = FALSE;
    HANDLE hKey;
    NTSTATUS Status;
    UNICODE_STRING ustrRegPath;
    OBJECT_ATTRIBUTES obja;
    WCHAR szObjectName[MAX_PATH + 1];

    RtlSecureZeroMemory(&ustrRegPath, sizeof(ustrRegPath));
    RtlInitUnicodeString(&ustrRegPath, REGSTR_KEY_USER);
    InitializeObjectAttributes(&obja, &ustrRegPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenKey(&hKey, MAXIMUM_ALLOWED, &obja);
    if (NT_SUCCESS(Status)) {
        RtlSecureZeroMemory(szObjectName, sizeof(szObjectName));
        if (supQueryObjectName((HKEY)hKey, &szObjectName, MAX_PATH * sizeof(WCHAR))) {
            if (_strcmp_w(REGSTR_KEY_USER, szObjectName) != 0) {
                IsSB = TRUE;
            }
        }
        NtClose(hKey);
    }
    return IsSB;
}

/*
* AmISandboxed
*
* Purpose:
*
* Return TRUE if current application is running in Sandboxie.
*
*/
BOOL AmISandboxed(
    _Out_ DETECT_FLAG *IsAppSandboxed
)
{
    BOOL cond = FALSE;
    BOOL IsSB = FALSE;
    SIZE_T Length = 0L;
    NTSTATUS Status;
    HANDLE hDummy;
    DETECT_FLAG Type = DETECT_BASE_NOTHING;
    ULONG_PTR k, i, FileID = 0xFFFFFFFF, OurID = GetCurrentProcessId();
    PSYSTEM_HANDLE_INFORMATION HandleTable;
    MEMORY_BASIC_INFORMATION RegionInfo;
    WCHAR szObjectName[MAX_PATH + 1];

    hDummy = NULL;
    HandleTable = NULL;

    do {

        // Find Sandboxie API device inside our handle table.
        if (!supOpenDevice(L"\\Device\\Null", GENERIC_READ, &hDummy))
            break;

        HandleTable = (PSYSTEM_HANDLE_INFORMATION)supGetSystemInfo(SystemHandleInformation);
        if (HandleTable == NULL)
            break;

        for (k = 0; k < 2; k++) {
            for (i = 0; i < HandleTable->NumberOfHandles; i++) {
                if (HandleTable->Handles[i].UniqueProcessId == OurID)
                    if (k == 0) {
                        if (HandleTable->Handles[i].HandleValue == (USHORT)(ULONG_PTR)hDummy) {
                            FileID = HandleTable->Handles[i].ObjectTypeIndex;
                            break;
                        }
                    }
                    else {
                        if (HandleTable->Handles[i].ObjectTypeIndex == FileID) {

                            RtlSecureZeroMemory(&szObjectName, sizeof(szObjectName));
                            if (supQueryObjectName(
                                (HANDLE)(ULONG_PTR)HandleTable->Handles[i].HandleValue,
                                &szObjectName, MAX_PATH * sizeof(WCHAR))
                                )
                            {
                                if (_strstr_w(szObjectName, VENDOR_SANDBOXIE) != NULL) {
                                    Type |= DETECT_HANDLE_TABLE;
                                    IsSB = TRUE;
                                    break;
                                }
                            }

                        }
                    }
            }
        }

        // Brute-force memory to locate Sandboxie injected code and locate sandboxie tag.

        i = (ULONG_PTR)g_siSysInfo.lpMinimumApplicationAddress;
        do {

            Status = NtQueryVirtualMemory(GetCurrentProcess(), (PVOID)i, MemoryBasicInformation,
                &RegionInfo, sizeof(MEMORY_BASIC_INFORMATION), &Length);
            if (NT_SUCCESS(Status)) {

                if (supIsExecutableCode(RegionInfo.AllocationProtect, RegionInfo.State)) {
                    for (k = i; k < i + RegionInfo.RegionSize; k += sizeof(DWORD)) {
                        if (
                            (*(PDWORD)k == 'kuzt') ||
                            (*(PDWORD)k == 'xobs')
                            )
                        {
                            IsSB = TRUE;
                            Type |= DETECT_MEMORY_TAG;
                            break;
                        }
                    }
                }
                i += RegionInfo.RegionSize;
            }
            else {
                i += 0x1000;
            }
        } while (i < (ULONG_PTR)g_siSysInfo.lpMaximumApplicationAddress);

        // Check if Sandboxie virtual registry present.

        IsSB = IsSandboxieVirtualRegistryPresent();
        if (IsSB) Type |= DETECT_VIRTUAL_REGISTRY;

    } while (cond);

    if (HandleTable) {
        HeapFree(GetProcessHeap(), 0, HandleTable);
    }
    if (hDummy != NULL) {
        NtClose(hDummy);
    }

    *IsAppSandboxed = Type;
    return IsSB;
}

/*
* IsUnknownVM
*
* Purpose:
*
* Return TRUE on generic VM scan success, FALSE otherwise.
*
*/
BOOL IsUnknownVM(
    _Out_ DETECT_FLAG *GenericVM
)
{
    BOOL IsVM = FALSE;
    ULONG dwDataSize = 0L;
    SYSTEM_FIRMWARE_TABLE_INFORMATION *sfti = NULL;
    DETECT_FLAG Type = DETECT_BASE_NOTHING;

    sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, RSMB, 0);
    if (sfti) {
        IsVM = supScanDump((CHAR*)sfti, dwDataSize, SMB_UNKNOWN, (ULONG)_strlen_a(SMB_UNKNOWN));
        if (IsVM) {
            Type |= DETECT_SIGNATURE_SCAN_RSMB;
        }
        HeapFree(GetProcessHeap(), 0, sfti);
    }
    *GenericVM = Type;
    return IsVM;
}

/*
* DumpFirmwareTable
*
* Purpose:
*
* Dump firmware tables to the disk, DEBUG only routine.
*
*/
VOID DumpFirmwareTable(
    VOID
)
{
    HANDLE hFile;
    ULONG dwDataSize = 0L, bytesIO;
    SYSTEM_FIRMWARE_TABLE_INFORMATION *sfti = NULL;

    sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, FIRM, 0xC0000);
    if (sfti) {
        hFile = CreateFile(TEXT("firm.dat"), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            WriteFile(hFile, sfti, dwDataSize, &bytesIO, NULL);
            CloseHandle(hFile);
        }
        HeapFree(GetProcessHeap(), 0, sfti);
    }

    sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, RSMB, 0);
    if (sfti) {
        hFile = CreateFile(TEXT("rsmb.dat"), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            WriteFile(hFile, sfti, dwDataSize, &bytesIO, NULL);
            CloseHandle(hFile);
        }
        HeapFree(GetProcessHeap(), 0, sfti);
    }
}

/*
* EnumPCIDevsReg
*
* Purpose:
*
* Build PCI devices list.
*
*/
VOID EnumPCIDevsReg(
    VOID
)
{
    BOOL cond = FALSE;
    HANDLE hKey = NULL;
    SIZE_T sz;
    DWORD dwKeySubIndex = 0;
    ULONG ResultLength = 0;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNICODE_STRING ustrKeyName;
    OBJECT_ATTRIBUTES obja;
    PKEY_BASIC_INFORMATION pKeyInfo = NULL;

    PVENDOR_ENTRY entry;

    RtlSecureZeroMemory(&ustrKeyName, sizeof(ustrKeyName));
    RtlInitUnicodeString(&ustrKeyName, REGSTR_KEY_PCIENUM);
    InitializeObjectAttributes(&obja, &ustrKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    do {

        Status = NtOpenKey(&hKey, KEY_ENUMERATE_SUB_KEYS, &obja);
        if ((hKey == NULL) && (!NT_SUCCESS(Status))) {
            break;
        }

        do {
            NtEnumerateKey(hKey, dwKeySubIndex, KeyBasicInformation,
                NULL, 0, &ResultLength);

            pKeyInfo = (PKEY_BASIC_INFORMATION)HeapAlloc(GetProcessHeap(),
                HEAP_ZERO_MEMORY, ResultLength);

            if (pKeyInfo == NULL) {
                break;
            }

            Status = NtEnumerateKey(hKey, dwKeySubIndex, KeyBasicInformation,
                pKeyInfo, ResultLength, &ResultLength);

            if (NT_SUCCESS(Status)) {

                entry = (PVENDOR_ENTRY)HeapAlloc(GetProcessHeap(),
                    HEAP_ZERO_MEMORY, sizeof(VENDOR_ENTRY));

                if (entry) {

                    sz = pKeyInfo->NameLength / sizeof(WCHAR);
                    if (sz > MAX_PATH) sz = MAX_PATH;

                    supCopyMemory(entry->VendorFullName, MAX_PATH * sizeof(WCHAR),
                        pKeyInfo->Name, sz * sizeof(WCHAR));

                    vExtractID(entry);
                    InsertHeadList(&VendorsListHead, &entry->ListEntry);
                }

                HeapFree(GetProcessHeap(), 0, pKeyInfo);
                pKeyInfo = NULL;
            }
            dwKeySubIndex++;

        } while (NT_SUCCESS(Status));

    } while (cond);

    if (hKey != NULL) {
        NtClose(hKey);
    }
    if (pKeyInfo != NULL) {
        HeapFree(GetProcessHeap(), 0, pKeyInfo);
    }
}
