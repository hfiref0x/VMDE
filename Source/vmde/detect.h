/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2013 - 2015
*
*  TITLE:       DETECT.H
*
*  VERSION:     1.10
*
*  DATE:        18 Mar 2015
*
*  Common definitions for vmdetection unit.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#ifndef _DETECTUNIT_
#define _DETECTUNIT_

typedef struct _VENDOR_ENTRY {
	LIST_ENTRY ListEntry;
	DWORD VendorID;
	DWORD DeviceID;
	WCHAR VendorFullName[MAX_PATH + 1];
} VENDOR_ENTRY, *PVENDOR_ENTRY;

#define FIRM 'FIRM'
#define RSMB 'RSMB'

#define VID_VMWARE 0x15AD
#define VID_ORACLE 0x80EE
#define VID_S3MS 0x5333
#define VID_PRLS 0x1AB8

#define REGSTR_KEY_PCIENUM L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\PCI"
#define REGSTR_KEY_USER L"\\REGISTRY\\USER"

#define DEVICELINK L"\\Device"
#define DRIVERLINK L"\\Driver"
#define RPCCONTROLLINK L"\\RPC Control"

//vm objects
#define DIRECTORY_SANDBOXIE L"\\Sandbox"
#define MUTEX_SANDBOXIE L"Sandboxie_SingleInstanceMutex_Control"
#define MUTEX_VPCXPMODE L"MicrosoftVirtualPC7UserServiceMakeSureWe'reTheOnlyOneMutex"
#define DEVICE_SANDBOXIE L"SandboxieDriverApi"
#define DEVICE_VIRTUALPC L"VirtualMachineServices" 
#define DRIVER_VIRTUALPC L"1-driver-vmsrvc"
#define DEVICE_VIRTUALBOX1 L"VBoxGuest"
#define DEVICE_VIRTUALBOX2 L"VBoxMiniRdr"
#define DEVICE_PARALLELS1 L"prl_pv"
#define DEVICE_PARALLELS2 L"prl_tg"
#define DEVICE_PARALLELS3 L"prl_time"
#define DEVICE_HYPER_V L"VmGenerationCounter"

#define DRIVER_VIRTUALBOX1 L"VBoxVideo"
#define DRIVER_VIRTUALBOX2 L"VBoxMouse"
#define DEVICE_VMWARE L"vmmemctl"
#define DRIVER_SANDBOXIE L"SbieDrv"
#define PORT_SANDBOXIE L"SbieSvcPort"
#define DEVICE_NULL L"Null"

#define VENDOR_SANDBOXIE L"Sandboxie"


BOOL IsVirtualBox(
	VOID
	);

BOOL IsHypervisor(
	VOID
	);

BOOL IsVmWare(
	VOID
	);

BOOL IsVirtualPC(
	VOID
	);

BOOL IsSandboxiePresent(
	VOID
	);

BOOL AmISandboxed(
	VOID
	);

BYTE GetHypervisorType(
	VOID
	);

BOOL IsParallels(
	VOID
	);

BOOL IsUnknownVM(
	VOID
	);

VOID DumpFirmwareTable(
	VOID
	);

VOID Test(
	VOID
	);

BOOL IsSandboxieVirtualRegistryPresent(
	VOID
	);

VOID vInitList(
	VOID
	);

VOID vFreeList(
    VOID
    );


VOID EnumPCIDevsReg(
	VOID
	);

#endif /* _DETECTUNIT_ */
