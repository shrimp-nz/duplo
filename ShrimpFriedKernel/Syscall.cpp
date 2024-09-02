#include "Syscall.hpp"
#include "Util.hpp"
#include <intrin.h>

SHORT Syscall::GetSyscallNumber(PVOID FunctionAddress)
{
	return *(SHORT*)((ULONG64)FunctionAddress + 4);
}

BOOLEAN Syscall::GetNtSyscallNumber(SHORT* syscallNumberOut, const char* syscall)
{
	UNICODE_STRING knownDlls{};
	RtlInitUnicodeString(&knownDlls, LR"(\KnownDlls\ntdll.dll)");

	OBJECT_ATTRIBUTES objAttributes{};
	InitializeObjectAttributes(&objAttributes, &knownDlls, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

	HANDLE section{};
	if (!NT_SUCCESS(ZwOpenSection(&section, SECTION_MAP_READ, &objAttributes)))
		return false;

	PVOID ntdllBase{};
	size_t ntdllSize{};
	LARGE_INTEGER sectionOffset{};
	if (!NT_SUCCESS(ZwMapViewOfSection(section, ZwCurrentProcess(), &ntdllBase, 0, 0, &sectionOffset, &ntdllSize, ViewShare, 0, PAGE_READONLY)))
	{
		ZwClose(section);
		return false;
	}

	auto status = true;
	const auto functionAddress = Util::GetExportedFunctionAddress(0, ntdllBase, syscall);
	if (!functionAddress)
	{
		status = false;
	}
	else {
		*syscallNumberOut = GetSyscallNumber(functionAddress);
	}

	ZwClose(section);
	ZwUnmapViewOfSection(ZwCurrentProcess(), ntdllBase);

	return status;
}

PVOID Syscall::GetNtSyscallFunc(_PSSDT ssdt, SHORT index)
{
    return (PVOID)((ULONG64)ssdt->ServiceTable + (ssdt->ServiceTable[index] >> 4));
}

extern "C" NTKERNELAPI SHORT NtBuildNumber;

// https://github.com/JakubGlisz/GetSSDT
// https://www.unknowncheats.me/forum/3383983-post3.html
_PSSDT Syscall::GetSSDT()
{
    ULONGLONG KiSystemCall64 = __readmsr(0xC0000082 /* lstar */);
    INT32 Limit = 4096;

    for (int i = 0; i < Limit; i++) {
        if (*(PUINT8)(KiSystemCall64 + i) == 0x4C
            && *(PUINT8)(KiSystemCall64 + i + 1) == 0x8D
            && *(PUINT8)(KiSystemCall64 + i + 2) == 0x15
            && *(PUINT8)(KiSystemCall64 + i + 7) == 0x4C
            && *(PUINT8)(KiSystemCall64 + i + 8) == 0x8D
            && *(PUINT8)(KiSystemCall64 + i + 9) == 0x1D)
        {
            ULONGLONG KiSystemServiceRepeat = KiSystemCall64 + i;

            // convert relative address to absolute address
            return (_PSSDT)((ULONGLONG)*(PINT32)(KiSystemServiceRepeat + 3) + KiSystemServiceRepeat + 7);
        }
    }

    if (NtBuildNumber > 17134)
    {
        for (int i = 0; i < Limit; i++) {
            if (*(PUINT8)(KiSystemCall64 + i) == 0xE9
                && *(PUINT8)(KiSystemCall64 + i + 5) == 0xC3
                && !*(PUINT8)(KiSystemCall64 + i + 6))
            {
                ULONGLONG KiSystemServiceUser = *(ULONGLONG*)(KiSystemCall64 + 1) + KiSystemCall64 + 5;
                for (int j = 0; j < Limit; j++) {
                    if (*(PUINT8)(KiSystemServiceUser + i) == 0x4C
                        && *(PUINT8)(KiSystemServiceUser + i + 1) == 0x8D
                        && *(PUINT8)(KiSystemServiceUser + i + 2) == 0x15
                        && *(PUINT8)(KiSystemServiceUser + i + 7) == 0x4C
                        && *(PUINT8)(KiSystemServiceUser + i + 8) == 0x8D
                        && *(PUINT8)(KiSystemServiceUser + i + 9) == 0x1D)
                    {
                        ULONGLONG KiSystemServiceRepeat = KiSystemServiceUser + i;

                        // convert relative address to absolute address
                        return (_PSSDT)((ULONGLONG)*(PINT32)(KiSystemServiceRepeat + 3) + KiSystemServiceRepeat + 7);
                    }
                }
            }
        }
    }

    return 0;
}
