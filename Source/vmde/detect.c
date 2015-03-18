/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2015
*
*  TITLE:       DETECT.C
*
*  DATE:        18 Mar 2015
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#define _FULLOUT

#include "global.h"
#include "detect.h"
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
* vFreeList
*
* Purpose:
*
* Free Vendors ID list.
*
*/
VOID vFreeList(
	VOID
	)
{
	PVENDOR_ENTRY vendorEntry;

	while (!IsListEmpty(&VendorsListHead)) {
		if (VendorsListHead.Flink == NULL) {
			break;
		}
		vendorEntry = CONTAINING_RECORD(VendorsListHead.Flink, VENDOR_ENTRY, ListEntry);
		RemoveEntryList(VendorsListHead.Flink);
		if (vendorEntry != NULL) {
			HeapFree(GetProcessHeap(), 0, vendorEntry);
		}
	}
}

/*
* IsVirtualPC
*
* Purpose:
*
* Return TRUE on VM detection success, FALSE otherwise.
* Note: there is no x64 Guest support in VirtualPC.
*
*/
BOOL IsVirtualPC(
	VOID
	)
{
	BOOL IsVM = FALSE, bFound = FALSE;
	ULONG dwDataSize = 0L;
	SYSTEM_FIRMWARE_TABLE_INFORMATION *sfti = NULL;

	// Devs of XP Mode we're so kind so they added special mutex, check it.
	if (supMutexExist(MUTEX_VPCXPMODE) != FALSE) {
		bFound = TRUE;
		DebugLog(TEXT("IsVirtualPC, mutex"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}

	//  Use well-known trick with illegal instructions.
	if (IsVPCGuest() != FALSE) {
		if (bFound != TRUE) bFound = TRUE;
		DebugLog(TEXT("IsVirtualPC, backdoor"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}

	//
	// Query virtual pc device. 
	//
	if (supIsObjectExists(DEVICELINK, DEVICE_VIRTUALPC) != FALSE) {
		if (bFound != TRUE) bFound = TRUE;
		DebugLog(TEXT("IsVirtualPC, devobj"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}

	// Query virtual pc driver, reg. rights elevation. 
	if (supIsObjectExists(DRIVERLINK, DRIVER_VIRTUALPC) != FALSE) {
		if (bFound != TRUE) bFound = TRUE;
		DebugLog(TEXT("IsVirtualPC, drvobj"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}

	// Scan raw firmware for specific string patterns. 
	sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, FIRM, 0xC0000);
	if (sfti) {
		IsVM = supScanDump((CHAR*)sfti, dwDataSize, VENDOR_VPC, (ULONG)_strlen_a(VENDOR_VPC));
		HeapFree(GetProcessHeap(), 0, sfti);
		if (IsVM != FALSE) {
			if (bFound != TRUE) bFound = TRUE;
			DebugLog(TEXT("IsVirtualPC, firmware"));
#ifndef _FULLOUT
			return TRUE;
#endif
		}
	}

	// Scan raw smbios data for specific string patters.
	sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, RSMB, 0);
	if (sfti) {
		IsVM = supScanDump((CHAR*)sfti, dwDataSize, SMB_VPC, (ULONG)_strlen_a(SMB_VPC));
		HeapFree(GetProcessHeap(), 0, sfti);
		if (IsVM != FALSE) {
			if (bFound != TRUE) bFound = TRUE;
			DebugLog(TEXT("IsVirtualPC, RSMB"));
#ifndef _FULLOUT
			return TRUE;
#endif
		}
	}

	// Query S3 VID on PCI bus devices. 
	if (vIsInList(VID_S3MS) != NULL) {
		if (bFound != TRUE) bFound = TRUE;
		DebugLog(TEXT("IsVirtualPC, PCI"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}
	return bFound;
}

/*
* IsVmWare
*
* Purpose:
*
* Return TRUE on VM detection success, FALSE otherwise.
*
*/
BOOL IsVmWare(
	VOID
	)
{
	BOOL IsVM = FALSE, bFound = FALSE;
	ULONG dwDataSize = 0L;
	SYSTEM_FIRMWARE_TABLE_INFORMATION *sfti = NULL;

	// Query vmware additions device presence.
	if (supIsObjectExists(DEVICELINK, DEVICE_VMWARE) != FALSE) {
		DebugLog(TEXT("IsVmWare, devobj"));
#ifndef _FULLOUT
		return TRUE;
#endif	
	}

	//
	// Query vmware presence by hypervisor port.
	// http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1009458
	//   
	if (IsVMWareGuest() != FALSE) {
		bFound = TRUE;
		DebugLog(TEXT("IsVmWare, backdoor"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}

	// Scan raw firmware for specific string patterns.
	sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, FIRM, 0xC0000);
	if (sfti) {
		IsVM = supScanDump((CHAR*)sfti, dwDataSize, VENDOR_VMWARE, (ULONG)_strlen_a(VENDOR_VMWARE));
		HeapFree(GetProcessHeap(), 0, sfti);
		if (IsVM != FALSE) {
			if (bFound != TRUE) bFound = TRUE;
			DebugLog(TEXT("IsVmWare, firmware"));
#ifndef _FULLOUT
			return TRUE;
#endif
		}
	}

	// Scan raw SMBIOS firmware table for specific string patterns.
	sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, RSMB, 0);
	if (sfti) {
		IsVM = supScanDump((CHAR*)sfti, dwDataSize, VENDOR_VMWARE, (ULONG)_strlen_a(VENDOR_VMWARE));
		if (IsVM != TRUE) {
			IsVM = supScanDump((CHAR*)sfti, dwDataSize, SMB_VMWARE, (ULONG)_strlen_a(SMB_VMWARE));
		}
		HeapFree(GetProcessHeap(), 0, sfti);

		if (IsVM != FALSE) {
			if (bFound != TRUE) bFound = TRUE;
			DebugLog(TEXT("IsVmWare, SMB"));
#ifndef _FULLOUT
			return TRUE;
#endif
		}
	}

	// Query VmWare VID on PCI bus devices.
	if (vIsInList(VID_VMWARE) != NULL) {
		if (bFound != TRUE) bFound = TRUE;
		DebugLog(TEXT("IsVmWare, PCI"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}

	return bFound;
}

/*
* IsParallels
*
* Purpose:
*
* Return TRUE on VM detection success, FALSE otherwise.
*
*/
BOOL IsParallels(
	VOID
	)
{
	BOOL IsVM = FALSE, bFound = FALSE;
	ULONG dwDataSize = 0L;
	SYSTEM_FIRMWARE_TABLE_INFORMATION *sfti = NULL;

	/* query parallels additions device presence */
	if (supIsObjectExists(DEVICELINK, DEVICE_PARALLELS1) != FALSE) {
		bFound = TRUE;
		DebugLog(TEXT("IsParallels, devobj1"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}

	if (supIsObjectExists(DEVICELINK, DEVICE_PARALLELS2) != FALSE) {
		if (bFound != TRUE) bFound = TRUE;
		DebugLog(TEXT("IsParallels, devobj2"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}

	if (supIsObjectExists(DEVICELINK, DEVICE_PARALLELS3) != FALSE) {
		if (bFound != TRUE) bFound = TRUE;
		DebugLog(TEXT("IsParallels, devobj3"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}

	// Scan raw firmware for specific string patterns.
	sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, FIRM, 0xC0000);
	if (sfti) {
		IsVM = supScanDump((CHAR*)sfti, dwDataSize, VENDOR_PARALLELS, (ULONG)_strlen_a(VENDOR_PARALLELS));
		HeapFree(GetProcessHeap(), 0, sfti);
		if (IsVM != FALSE) {
			if (bFound != TRUE) bFound = TRUE;
			DebugLog(TEXT("IsParallels, firmware"));
#ifndef _FULLOUT
			return TRUE;
#endif
		}
	}

	// Scan raw SMBIOS firmware table for specific string patterns. 
	sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, RSMB, 0);
	if (sfti) {
		IsVM = supScanDump((CHAR*)sfti, dwDataSize, SMB_PARALLELS, (ULONG)_strlen_a(SMB_PARALLELS));
		HeapFree(GetProcessHeap(), 0, sfti);
		if (IsVM != FALSE) {
			if (bFound != TRUE) bFound = TRUE;
			DebugLog(TEXT("IsParallels, RSMB"));
#ifndef _FULLOUT
			return TRUE;
#endif
		}
	}

	// Query Parallels on PCI bus devices.
	if (vIsInList(VID_PRLS) != NULL) {
		if (bFound != TRUE) bFound = TRUE;
		DebugLog(TEXT("IsParallels, PCI"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}
	return bFound;
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
	VOID
	)
{
	int CPUInfo[4] = { -1 };

	//
	// Query hypervisor presence.
	// http://msdn.microsoft.com/en-us/library/windows/hardware/ff538624(v=vs.85).aspx
	// be aware this detection can be bogus
	//

	__cpuid(CPUInfo, 1);
	if ((CPUInfo[2] >> 31) & 1) {
		DebugLog(TEXT("IsHypervisor, flag set"));
		return TRUE;
	}

	//
	// Microsoft Hyper-V additional special case
	//
	if (supIsObjectExists(DEVICELINK, DEVICE_HYPER_V) != FALSE) {
		DebugLog(TEXT("IsHypervisor, hyper-v devobj"));
		return TRUE;
	}

	return FALSE;
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
	int CPUInfo[4] = { -1 };
	char HvProductName[0x40];

	__cpuid(CPUInfo, 0x40000000);
	RtlSecureZeroMemory(HvProductName, sizeof(HvProductName));
	memcpy(HvProductName, CPUInfo + 1, 12);

	// http://msdn.microsoft.com/en-us/library/windows/hardware/ff542428(v=vs.85).aspx 
	if (_strcmpi_a(HvProductName, "Microsoft Hv") == 0) {
		DebugLog(TEXT("GetHypervisorType, Hyper-V"));
		return 1;
	}

	// http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1009458 
	if (_strcmpi_a(HvProductName, "VMwareVMware") == 0) {
		DebugLog(TEXT("GetHypervisorType, VMware"));
		return 2;
	}

	// Parallels VMM ids.
	if (_strcmpi_a(HvProductName, "prl hyperv") == 0) {
		DebugLog(TEXT("GetHypervisorType, Parallels"));
		return 3;
	}
	return 0;
}

/*
* IsVirtualBox
*
* Purpose:
*
* Return TRUE on VM detection success, FALSE otherwise.
*
*/
BOOL IsVirtualBox(
	VOID
	)
{
	BOOL IsVM = FALSE, bFound = FALSE;
	ULONG dwDataSize = 0L;
	SYSTEM_FIRMWARE_TABLE_INFORMATION *sfti = NULL;


	// Query vbox additions guest device.
	if (supIsObjectExists(DEVICELINK, DEVICE_VIRTUALBOX1) != FALSE) {
		bFound = TRUE;
		DebugLog(TEXT("IsVirtualBox, devobj1"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}

	// Query vbox additions symbolic link.
	if (supIsObjectExists(DEVICELINK, DEVICE_VIRTUALBOX2) != FALSE) {
		if (bFound != TRUE) bFound = TRUE;
		DebugLog(TEXT("IsVirtualBox, symlink1"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}

	// Query vbox additions video driver, reg. rights elevation.
	if (supIsObjectExists(DRIVERLINK, DRIVER_VIRTUALBOX1) != FALSE) {
		if (bFound != TRUE) bFound = TRUE;
		DebugLog(TEXT("IsVirtualBox, drvobj1"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}

	// Query vbox additions mouse driver, reg. admin rights elevation.
	if (supIsObjectExists(DRIVERLINK, DRIVER_VIRTUALBOX2) != FALSE) {
		if (bFound != TRUE) bFound = TRUE;
		DebugLog(TEXT("IsVirtualBox, drvobj2"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}

	// Scan raw firmware for specific string patterns.
	sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, FIRM, 0xC0000);
	if (sfti) {
		IsVM = supScanDump((CHAR*)sfti, dwDataSize, VENDOR_VBOX, (ULONG)_strlen_a(VENDOR_VBOX));
		if (IsVM != TRUE) {
			IsVM = supScanDump((CHAR*)sfti, dwDataSize, VENDOR_ORACLE, (ULONG)_strlen_a(VENDOR_ORACLE));
		}
		if (IsVM != TRUE) {
			IsVM = supScanDump((CHAR*)sfti, dwDataSize, VENDOR_INNOTEK, (ULONG)_strlen_a(VENDOR_INNOTEK));
		}
		HeapFree(GetProcessHeap(), 0, sfti);

		if (IsVM != FALSE) {
			if (bFound != TRUE) bFound = TRUE;
			DebugLog(TEXT("IsVirtualBox, firmware"));
#ifndef _FULLOUT
			return TRUE;
#endif
		}
	}

	// Scan raw SMBIOS firmware table for specific string patterns.
	sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, RSMB, 0);
	if (sfti) {
		IsVM = supScanDump((CHAR*)sfti, dwDataSize, VENDOR_VBOX, (ULONG)_strlen_a(VENDOR_VBOX));
		if (IsVM != TRUE) {
			IsVM = supScanDump((CHAR*)sfti, dwDataSize, VENDOR_ORACLE, (ULONG)_strlen_a(VENDOR_ORACLE));
		}
		if (IsVM != TRUE) {
			IsVM = supScanDump((CHAR*)sfti, dwDataSize, VENDOR_INNOTEK, (ULONG)_strlen_a(VENDOR_INNOTEK));
		}
		HeapFree(GetProcessHeap(), 0, sfti);

		if (IsVM != FALSE) {
			if (bFound != TRUE) bFound = TRUE;
			DebugLog(TEXT("IsVirtualBox, RSMB"));
#ifndef _FULLOUT
			return TRUE;
#endif
		}
	}

	// Query oracle VID on PCI bus devices. 
	if (vIsInList(VID_ORACLE) != NULL) {
		if (bFound != TRUE) bFound = TRUE;
		DebugLog(TEXT("IsVirtualBox, PCI"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}
	return bFound;
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
	VOID
	)
{
	BOOL bFound = FALSE;
	OBJECT_ATTRIBUTES attr;
	UNICODE_STRING ustrName;
	NTSTATUS Status;
	HANDLE hObject = NULL;

	// Check Sandboxie device.
	if (supIsObjectExists(DEVICELINK, DEVICE_SANDBOXIE) != FALSE) {
		bFound = TRUE;
		DebugLog(TEXT("IsSandboxiePresent, devobj"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}

	// Check Sandboxie object directory presence.
	RtlSecureZeroMemory(&ustrName, sizeof(ustrName));
	RtlInitUnicodeString(&ustrName, DIRECTORY_SANDBOXIE);
	InitializeObjectAttributes(&attr, &ustrName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	Status = NtOpenDirectoryObject(&hObject, DIRECTORY_QUERY, &attr);
	if (NT_SUCCESS(Status)) {
		if (bFound != TRUE) bFound = TRUE;
		NtClose(hObject);
		DebugLog(TEXT("IsSandboxiePresent, dirobj"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}

	// Query Sandboxie mutex.
	if (supMutexExist(MUTEX_SANDBOXIE) != FALSE) {
		if (bFound != TRUE) bFound = TRUE;
		DebugLog(TEXT("IsSandboxiePresent, mutex"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}

	// Query Sandboxie rpc port presence.
	if (supIsObjectExists(RPCCONTROLLINK, PORT_SANDBOXIE) != FALSE) {
		if (bFound != TRUE) bFound = TRUE;
		DebugLog(TEXT("IsSandboxiePresent, port"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}

	// Query driver object, reg. rights elevation.
	if (supIsObjectExists(DRIVERLINK, DRIVER_SANDBOXIE) != FALSE) {
		if (bFound != TRUE) bFound = TRUE;
		DebugLog(TEXT("IsSandboxiePresent, drvobj"));
#ifndef _FULLOUT
		return TRUE;
#endif
	}
	return bFound;
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
	VOID
	)
{
	BOOL cond = FALSE;
	BOOL IsSB = FALSE;
	SIZE_T Length = 0L;
	NTSTATUS Status;
	HANDLE hDummy;
	ULONG_PTR k, i, FileID = 0xFFFFFFFF, OurID = GetCurrentProcessId();
	PSYSTEM_HANDLE_INFORMATION HandleTable;
	MEMORY_BASIC_INFORMATION RegionInfo;
	WCHAR szObjectName[MAX_PATH + 1];

	hDummy = NULL;
	HandleTable = NULL;

	do {

		// Find Sandboxie API device inside our handle table.
		if (!supOpenDevice(L"\\Device\\Null", GENERIC_READ, &hDummy)) {
			break;
		}

		HandleTable = (PSYSTEM_HANDLE_INFORMATION)supGetSystemInfo(SystemHandleInformation);
		if (HandleTable == NULL) {
			break;
		}

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
									DebugLog(TEXT("AmISandboxed, handle table"));
									IsSB = TRUE;
									break;
								}
							}

						}
					}
			}
		}

		// Brute-force memory to locate Sandboxie injected code and locate sandboxie tag.
#ifndef _FULLOUT
		if (IsSB != TRUE) {
#endif
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
								DebugLog(TEXT("AmISandboxed, tag"));
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
#ifndef _FULLOUT
		}
#endif
		// Check if Sandboxie virtual registry present.
#ifndef _FULLOUT
		if (IsSB != TRUE) {
#endif
			IsSB = IsSandboxieVirtualRegistryPresent();
			if (IsSB != FALSE) {
				DebugLog(TEXT("AmISandboxed, vtreg"));
			}
#ifndef _FULLOUT
		}
#endif
	} while (cond);
	
	if (HandleTable) {
		HeapFree(GetProcessHeap(), 0, HandleTable);
	}
	if (hDummy != NULL) {
		NtClose(hDummy);
	}

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
	VOID
	)
{
	BOOL IsVM = FALSE;
	ULONG dwDataSize = 0L;
	SYSTEM_FIRMWARE_TABLE_INFORMATION *sfti = NULL;

	sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, RSMB, 0);
	if (sfti) {
		IsVM = supScanDump((CHAR*)sfti, dwDataSize, SMB_UNKNOWN, (ULONG)_strlen_a(SMB_UNKNOWN));
		if (IsVM) {
			DebugLog(TEXT("IsUnknownVM, SMB detect"));
		}
		HeapFree(GetProcessHeap(), 0, sfti);
	}
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
		hFile = CreateFile(TEXT("C:\\temp\\firm.dat"), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		if (hFile != INVALID_HANDLE_VALUE) {
			WriteFile(hFile, sfti, dwDataSize, &bytesIO, NULL);
			CloseHandle(hFile);
		}
		HeapFree(GetProcessHeap(), 0, sfti);
	}

	sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)supGetFirmwareTable(&dwDataSize, RSMB, 0);
	if (sfti) {
		hFile = CreateFile(TEXT("C:\\temp\\rsmb.dat"), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
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

	vFreeList();

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
