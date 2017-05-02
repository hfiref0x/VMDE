/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2013 - 2017
*
*  TITLE:       DETECT.H
*
*  VERSION:     1.11
*
*  DATE:        30 Apr 2017
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

#define DETECT_BASE_NOTHING             0x00000000
#define DETECT_DEVICE_OBJECT_NAME       0x00000002
#define DETECT_DRIVER_OBJECT_NAME       0x00000004
#define DETECT_MUTEX_NAME               0x00000008
#define DETECT_INSTRUCTION_BACKDOOR     0x00000010
#define DETECT_SIGNATURE_SCAN_FIRM      0x00000020
#define DETECT_SIGNATURE_SCAN_RSMB      0x00000040
#define DETECT_PCI_HWID                 0x00000080

#define DETECT_DIRECTORY_OBJECT_NAME    0x00001000
#define DETECT_PORT_NAME                0x00002000
#define DETECT_HANDLE_TABLE             0x00004000
#define DETECT_MEMORY_TAG               0x00008000
#define DETECT_VIRTUAL_REGISTRY         0x00010000

#define DETECT_HYPERVISOR_BIT           0x00020000

typedef ULONG DETECT_FLAG;

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
#define MUTEX_SANDBOXIE2 L"SBIE_BOXED_ServiceInitComplete_Mutex1"
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

BOOL IsHypervisor(
    _Out_ DETECT_FLAG *Hypervisor);

VOID CheckForVirtualBoxVM(
    _Out_ DETECT_FLAG *VirtualBox);

VOID CheckForVMWareVM(
    _Out_ DETECT_FLAG *VMWare);

VOID CheckForVirtualPC(
    _Out_ DETECT_FLAG *VirtualPC);

VOID CheckForParallelsVM(
    _Out_ DETECT_FLAG *Parallels);

BOOL IsSandboxiePresent(
    _Out_ DETECT_FLAG *Sandboxie);

BOOL AmISandboxed(
    _Out_ DETECT_FLAG *IsAppSandboxed);

BOOL IsUnknownVM(
    _Out_ DETECT_FLAG *GenericVM);

BYTE GetHypervisorType(
    VOID);

BOOL IsSandboxieVirtualRegistryPresent(
    VOID);

VOID EnumPCIDevsReg(
    VOID);

VOID DumpFirmwareTable(
    VOID);


#endif /* _DETECTUNIT_ */
