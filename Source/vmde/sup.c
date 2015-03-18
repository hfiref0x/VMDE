/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015
*
*  TITLE:       SUP.C
*
*  DATE:        18 Mar 2015
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "detect.h"

/*
* supCopyMemory
*
* Purpose:
*
* Copies bytes between buffers.
*
* dest - Destination buffer
* cbdest - Destination buffer size in bytes
* src - Source buffer
* cbsrc - Source buffer size in bytes
*
*/
void supCopyMemory(
	_Inout_ void *dest,
	_In_ size_t cbdest,
	_In_ const void *src,
	_In_ size_t cbsrc
	)
{
	char *d = (char*)dest;
	char *s = (char*)src;

	if ((dest == 0) || (src == 0) || (cbdest == 0))
		return;
	if (cbdest<cbsrc)
		cbsrc = cbdest;

	while (cbsrc>0) {
		*d++ = *s++;
		cbsrc--;
	}
}

/*
* supDetectObjectCallback
*
* Purpose:
*
* Comparer callback routine used in objects enumeration.
*
*/
NTSTATUS NTAPI supDetectObjectCallback(
	_In_ POBJECT_DIRECTORY_INFORMATION Entry, 
	_In_ PVOID CallbackParam
	)
{
	POBJSCANPARAM Param = (POBJSCANPARAM)CallbackParam;
	
	if (Entry == NULL) {
		return STATUS_INVALID_PARAMETER_1;
	}

	if (CallbackParam == NULL) {
		return STATUS_INVALID_PARAMETER_2;
	}

	if (Param->Buffer == NULL || Param->BufferSize == 0) {
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	if (Entry->Name.Buffer) {
		if (_strcmpi_w(Entry->Name.Buffer, Param->Buffer) == 0) {
			return STATUS_SUCCESS;
		}
	}
	return STATUS_UNSUCCESSFUL;
}

/*
* supIsProcess32bit
*
* Purpose:
*
* Return TRUE if given process is under WOW64, FALSE otherwise.
*
*/
BOOLEAN supIsProcess32bit(
	_In_ HANDLE hProcess
	)
{
	NTSTATUS status;
	PROCESS_EXTENDED_BASIC_INFORMATION pebi;

	if (hProcess == NULL) {
		return FALSE;
	}

	//query if this is wow64 process
	RtlSecureZeroMemory(&pebi, sizeof(pebi));
	pebi.Size = sizeof(PROCESS_EXTENDED_BASIC_INFORMATION);
	status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pebi, sizeof(pebi), NULL);
	if (NT_SUCCESS(status)) {
		return (pebi.IsWow64Process == 1);
	}
	return FALSE;
}

/*
* supIs64BitWindows
*
* Purpose:
*
* Detect win32 subsystem execution mode and platform.
*
*/
BOOL supIs64BitWindows(
	_In_ PBOOL pf64
	)
{
	if (!pf64) 
		return FALSE;

#if defined(_WIN64)
	return TRUE;  // 64-bit programs run only on Win64
#elif defined(_WIN32)
	// 32-bit programs run on both 32-bit and 64-bit Windows
	*pf64 = supIsProcess32bit(GetCurrentProcess());
	return *pf64;
#else
	return FALSE; // Win64 does not support Win16
#endif
}

/*
* supEnumSystemObjects
*
* Purpose:
*
* Lookup object by name in given directory.
*
*/
NTSTATUS NTAPI supEnumSystemObjects(
	_In_opt_ LPWSTR pwszRootDirectory,
	_In_opt_ HANDLE hRootDirectory,
	_In_ PENUMOBJECTSCALLBACK CallbackProc,
	_In_opt_ PVOID CallbackParam
	)
{
	BOOL				cond = TRUE;
	ULONG				ctx, rlen;
	HANDLE				hDirectory = NULL;
	NTSTATUS			status;
	NTSTATUS			CallbackStatus;
	OBJECT_ATTRIBUTES	attr;
	UNICODE_STRING		sname;

	POBJECT_DIRECTORY_INFORMATION	objinf;

	if (CallbackProc == NULL) {
		return STATUS_INVALID_PARAMETER_4;
	}

	status = STATUS_UNSUCCESSFUL;

	__try {

		// We can use root directory.
		if (pwszRootDirectory != NULL) {
			RtlSecureZeroMemory(&sname, sizeof(sname));
			RtlInitUnicodeString(&sname, pwszRootDirectory);
			InitializeObjectAttributes(&attr, &sname, OBJ_CASE_INSENSITIVE, NULL, NULL);
			status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &attr);
			if (!NT_SUCCESS(status)) {
				return status;
			}
		}
		else {
			if (hRootDirectory == NULL) {
				return STATUS_INVALID_PARAMETER_2;
			}
			hDirectory = hRootDirectory;
		}

		// Enumerate objects in directory.
		ctx = 0;
		do {

			rlen = 0;
			status = NtQueryDirectoryObject(hDirectory, NULL, 0, TRUE, FALSE, &ctx, &rlen);
			if (status != STATUS_BUFFER_TOO_SMALL)
				break;

			objinf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, rlen);
			if (objinf == NULL)
				break;

			status = NtQueryDirectoryObject(hDirectory, objinf, rlen, TRUE, FALSE, &ctx, &rlen);
			if (!NT_SUCCESS(status)) {
				HeapFree(GetProcessHeap(), 0, objinf);
				break;
			}

			CallbackStatus = CallbackProc(objinf, CallbackParam);

			HeapFree(GetProcessHeap(), 0, objinf);

			if (NT_SUCCESS(CallbackStatus)) {
				status = STATUS_SUCCESS;
				break;
			}

		} while (cond);

		if (hDirectory != NULL) {
			NtClose(hDirectory);
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = STATUS_ACCESS_VIOLATION;
	}

	return status;
}

/*
* supIsObjectExists
*
* Purpose:
*
* Return TRUE if the given object exists, FALSE otherwise.
*
*/
BOOL supIsObjectExists(
	_In_ LPWSTR RootDirectory,
	_In_ LPWSTR ObjectName
	)
{
	OBJSCANPARAM Param;

	if (ObjectName == NULL) {
		return FALSE;
	}

	Param.Buffer = ObjectName;
	Param.BufferSize = (ULONG)_strlen_w(ObjectName);

	return NT_SUCCESS(supEnumSystemObjects(RootDirectory, NULL, supDetectObjectCallback, &Param));
}

/*
* supScanDump
*
* Purpose:
*
* Return TRUE if the given data already exists, FALSE otherwise.
*
*/
BOOL supScanDump(
	_In_ CHAR *Data,
	_In_ ULONG dwDataSize,
	_In_ CHAR *lpFindData,
	_In_ ULONG dwFindDataSize
	)
{
	UINT i;

	if (
		(Data == NULL) ||
		(lpFindData == NULL)
		)
	{
		return FALSE;
	}

	if (dwFindDataSize > dwDataSize) {
		return FALSE;
	}

	for (i = 0; i < dwDataSize - dwFindDataSize; i++) {
		if (RtlCompareMemory(Data + i, lpFindData, dwFindDataSize) == dwFindDataSize) {
			return TRUE;
		}
	}
	return FALSE;
}

/*
* supMutexExist
*
* Purpose:
*
* Return TRUE if given mutex already exists, FALSE otherwise.
*
*/
BOOL supMutexExist(
	_In_ LPWSTR lpMutexName
	)
{
	DWORD dwError;
	HANDLE hObject = NULL;

	if (lpMutexName == NULL) {
		return FALSE;
	}

	SetLastError(0);
	hObject = CreateMutex(NULL, FALSE, lpMutexName);
	dwError = GetLastError();

	if (hObject) {
		CloseHandle(hObject);
	}
	return (dwError == ERROR_ALREADY_EXISTS);
}

/*
* supOpenDevice
*
* Purpose:
*
* Open handle by device name.
*
*/
BOOL supOpenDevice(
	_In_ LPWSTR lpDeviceName,
	_In_ ACCESS_MASK DesiredAccess,
	_Out_opt_ PHANDLE phDevice
	)
{
	OBJECT_ATTRIBUTES attr;
	IO_STATUS_BLOCK iost;

	UNICODE_STRING uDevName;

	HANDLE hDevice;
	NTSTATUS Status;

	if (phDevice) {
		*phDevice = NULL;
	}
	if (lpDeviceName == NULL) {
		return FALSE;
	}

	hDevice = NULL;
	RtlSecureZeroMemory(&uDevName, sizeof(uDevName));
	RtlInitUnicodeString(&uDevName, lpDeviceName);
	InitializeObjectAttributes(&attr, &uDevName, OBJ_CASE_INSENSITIVE, 0, NULL);

	Status = NtCreateFile(&hDevice, DesiredAccess, &attr, &iost, NULL, 0,
		0, FILE_OPEN, 0, NULL, 0);
	if (NT_SUCCESS(Status)) {
		if (phDevice != NULL) {
			*phDevice = hDevice;
		}
	}

	return NT_SUCCESS(Status);
}

/*
* supGetFirmwareTable
*
* Purpose:
*
* GetSystemFirmwareTable reimplemented.
*
*/
PVOID supGetFirmwareTable(
	_In_opt_	PULONG pdwDataSize,
	_In_		DWORD dwSignature,
	_In_		DWORD dwTableID
	)
{
	NTSTATUS Status;
	ULONG Length;
	HANDLE hProcess = NULL;
	ULONG uAddress;
	SYSTEM_FIRMWARE_TABLE_INFORMATION *sfti = NULL;
	SIZE_T memIO = 0;

	CLIENT_ID cid;
	OBJECT_ATTRIBUTES attr;
	MEMORY_REGION_INFORMATION memInfo;

	// Use documented GetSystemFirmwareTable instead, this is it raw implementation.
	if (g_osver.dwMajorVersion > 5) {

		Length = 0x1000;
		sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Length);
		if (sfti != NULL) {
			sfti->Action = SystemFirmwareTable_Get;
			sfti->ProviderSignature = dwSignature;
			sfti->TableID = dwTableID;
			sfti->TableBufferLength = Length;

			// Query if info class available and if how many memory we need.
			Status = NtQuerySystemInformation(SystemFirmwareTableInformation, sfti, Length, &Length);
			if (
				(Status == STATUS_INVALID_INFO_CLASS) ||
				(Status == STATUS_INVALID_DEVICE_REQUEST) ||
				(Status == STATUS_NOT_IMPLEMENTED) ||
				(Length == 0)
				)
			{
				HeapFree(GetProcessHeap(), 0, sfti);
				return NULL;
			}

			if ((!NT_SUCCESS(Status)) || (Status == STATUS_BUFFER_TOO_SMALL)) {

				HeapFree(GetProcessHeap(), 0, sfti);

				sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Length);
				if (sfti != NULL) {
					sfti->Action = SystemFirmwareTable_Get;
					sfti->ProviderSignature = dwSignature;
					sfti->TableID = dwTableID;
					sfti->TableBufferLength = Length;
					Status = NtQuerySystemInformation(SystemFirmwareTableInformation, sfti, Length, &Length);
					if (!NT_SUCCESS(Status)) {
						HeapFree(GetProcessHeap(), 0, sfti);
						return NULL;
					}
					if (pdwDataSize) {
						*pdwDataSize = Length;
					}
				}
			}
			else {
				if (pdwDataSize) {
					*pdwDataSize = Length;
				}
			}
		}
	}
	else {
		//
		//  On pre Vista systems the above info class unavailable, but all required information.
		//  can be found inside csrss  memory space (stored here for VDM purposes) at few fixed addresses.
		//
		if ((dwSignature != FIRM) && (dwSignature != RSMB)) {
			return NULL;
		}

		// we are interested only in two memory regions 
		switch (dwSignature) {
		case FIRM:
			uAddress = 0xC0000; // FIRM analogue 
			break;
		case RSMB:
			uAddress = 0xE0000; // RSMB analogue 
			break;
		default:
			return NULL;
			break;
		}

		Length = 0;
		cid.UniqueProcess = (HANDLE)CsrGetProcessId();
		cid.UniqueThread = 0;
		InitializeObjectAttributes(&attr, NULL, 0, 0, NULL);

		// open csrss, reg. client debug privilege set 
		Status = NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &attr, &cid);
		if (NT_SUCCESS(Status)) {

			// get memory data region size for buffer allocation
			Status = NtQueryVirtualMemory(hProcess, (PVOID)uAddress, MemoryRegionInformation, &memInfo, sizeof(MEMORY_REGION_INFORMATION), &memIO);
			if (NT_SUCCESS(Status)) {

				sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, memInfo.RegionSize);
				if (sfti != NULL) {

					// read data to our allocated buffer 
					Status = NtReadVirtualMemory(hProcess, (PVOID)uAddress, sfti, memInfo.RegionSize, &memIO);
					if (NT_SUCCESS(Status)) {

						if (pdwDataSize) {
							*pdwDataSize = (ULONG)memInfo.RegionSize;
						}
					}
					else {
						HeapFree(GetProcessHeap(), 0, sfti);
						return NULL;
					}
				}
			}
			NtClose(hProcess);
		}
	}
	return sfti;
}

/*
* supQueryObjectName
*
* Purpose:
*
* Return object name in Native format.
*
*/
BOOL supQueryObjectName(
	_In_	HKEY hKey,
	_Inout_	PVOID Buffer,
	_In_	ULONG BufferSize //size of input buffer in bytes
	)
{
	BOOL cond = FALSE;
	POBJECT_NAME_INFORMATION pObjName;
	NTSTATUS Status;
	ULONG ReturnLength;
	BOOL bResult;

	pObjName = NULL;
	ReturnLength = 0;
	bResult = FALSE;

	do {

		NtQueryObject(hKey, ObjectNameInformation, NULL, ReturnLength, &ReturnLength);
		if (ReturnLength == 0L) {
			break;
		}

		pObjName = (POBJECT_NAME_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ReturnLength);
		if (pObjName == NULL) {
			break;
		}

		Status = NtQueryObject(hKey, ObjectNameInformation, pObjName, ReturnLength, NULL);
		if (NT_SUCCESS(Status)) {

			if ((pObjName->Name.Buffer != NULL) && (pObjName->Name.Length > 0)) {
				bResult = TRUE;
				_strncpy_w(Buffer, BufferSize / sizeof(WCHAR), pObjName->Name.Buffer, 
					pObjName->Name.Length / sizeof(WCHAR));
			}
		}
	} while (cond);

	if (pObjName != NULL) {
		HeapFree(GetProcessHeap(), 0, pObjName);
	}
	return bResult;
}

/*
* supEnablePrivilege
*
* Purpose:
*
* Enable/Disable given privilege.
*
* Return FALSE on any error.
*
*/
BOOL supEnablePrivilege(
	_In_ DWORD	PrivilegeName,
	_In_ BOOL	fEnable
	)
{
	BOOL bResult = FALSE;
	NTSTATUS status;
	HANDLE hToken;
	TOKEN_PRIVILEGES TokenPrivileges;

	status = NtOpenProcessToken(
		GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken);

	if (!NT_SUCCESS(status)) {
		return bResult;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Luid.LowPart = PrivilegeName;
	TokenPrivileges.Privileges[0].Luid.HighPart = 0;
	TokenPrivileges.Privileges[0].Attributes = (fEnable) ? SE_PRIVILEGE_ENABLED : 0;
	status = NtAdjustPrivilegesToken(hToken, FALSE, &TokenPrivileges,
		sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, NULL);
	if (status == STATUS_NOT_ALL_ASSIGNED) {
		status = STATUS_PRIVILEGE_NOT_HELD;
	}
	bResult = NT_SUCCESS(status);
	NtClose(hToken);
	return bResult;
}


/*
* supGetSystemInfo
*
* Purpose:
*
* Returns buffer with system information by given InfoClass.
*
* Returned buffer must be freed with HeapFree after usage.
* Function will return error after 100 attempts.
*
*/
PVOID supGetSystemInfo(
	_In_ SYSTEM_INFORMATION_CLASS InfoClass
	)
{
	INT			c = 0;
	PVOID		Buffer = NULL;
	ULONG		Size = 0x1000;
	NTSTATUS	status;
	ULONG       memIO;

	do {
		Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
		if (Buffer != NULL) {
			status = NtQuerySystemInformation(InfoClass, Buffer, Size, &memIO);
		}
		else {
			return NULL;
		}
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			HeapFree(GetProcessHeap(), 0, Buffer);
			Size *= 2;
		}
		c++;
		if (c > 100) {
			status = STATUS_SECRET_TOO_LONG;
			break;
		}
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (NT_SUCCESS(status)) {
		return Buffer;
	}

	if (Buffer) {
		HeapFree(GetProcessHeap(), 0, Buffer);
	}
	return NULL;
}
