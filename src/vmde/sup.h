/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2014 - 2017
*
*  TITLE:       SUP.H
*
*  VERSION:     1.11
*
*  DATE:        28 Apr 2017
*
*  Common header file for the program support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#define DebugLog(x) OutputDebugString(x)
#define DisplayText(Text, Type) MessageBox(GetDesktopWindow(), Text, PROGRAM_NAME, Type)

typedef NTSTATUS(NTAPI *PENUMOBJECTSCALLBACK)(POBJECT_DIRECTORY_INFORMATION Entry, PVOID CallbackParam);

typedef struct _OBJSCANPARAM {
    PWSTR Buffer;
    ULONG BufferSize;
} OBJSCANPARAM, *POBJSCANPARAM;

BOOLEAN supIsProcess32bit(
    _In_ HANDLE hProcess);

BOOL supIs64BitWindows(
    _In_ PBOOL pf64);

BOOL supQueryObjectName(
    _In_	HKEY hKey,
    _Inout_	PVOID Buffer,
    _In_	ULONG BufferSize);

void supCopyMemory(
    _Inout_ void *dest,
    _In_ size_t cbdest,
    _In_ const void *src,
    _In_ size_t cbsrc);

PVOID supGetFirmwareTable(
    _In_opt_	PULONG pdwDataSize,
    _In_		DWORD dwSignature,
    _In_		DWORD dwTableID);

BOOL supIsObjectExists(
    _In_ LPWSTR RootDirectory,
    _In_ LPWSTR ObjectName);

BOOL supOpenDevice(
    _In_ LPWSTR lpDeviceName,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_opt_ PHANDLE phDevice);

BOOL supScanDump(
    _In_ CHAR *Data,
    _In_ ULONG dwDataSize,
    _In_ CHAR *lpFindData,
    _In_ ULONG dwFindDataSize);

BOOL supMutexExist(
    _In_ LPWSTR lpMutexName);

BOOL supEnablePrivilege(
    _In_ DWORD	PrivilegeName,
    _In_ BOOL	fEnable);

PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS InfoClass);

BOOLEAN FORCEINLINE supIsExecutableCode(
    ULONG Protection,
    ULONG State
)
{
    return (((Protection & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) &&
        ((State & MEM_COMMIT) == MEM_COMMIT));
}

VOID FORCEINLINE InitializeListHead(
    _In_ PLIST_ENTRY ListHead
)
{
    ListHead->Flink = ListHead->Blink = ListHead;
}

#define IsListEmpty(ListHead) \
    ((ListHead)->Flink == (ListHead))

BOOLEAN FORCEINLINE RemoveEntryList(
    _In_ PLIST_ENTRY Entry
)
{
    PLIST_ENTRY Blink;
    PLIST_ENTRY Flink;

    Flink = Entry->Flink;
    Blink = Entry->Blink;
    Blink->Flink = Flink;
    Flink->Blink = Blink;
    return (BOOLEAN)(Flink == Blink);
}

PLIST_ENTRY FORCEINLINE RemoveHeadList(
    _In_ PLIST_ENTRY ListHead
)
{
    PLIST_ENTRY Flink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Flink;
    Flink = Entry->Flink;
    ListHead->Flink = Flink;
    Flink->Blink = ListHead;
    return Entry;
}

VOID FORCEINLINE InsertHeadList(
    _In_ PLIST_ENTRY ListHead,
    _In_ PLIST_ENTRY Entry
)
{
    PLIST_ENTRY Flink;

    Flink = ListHead->Flink;
    Entry->Flink = Flink;
    Entry->Blink = ListHead;
    Flink->Blink = Entry;
    ListHead->Flink = Entry;
}
