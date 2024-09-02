#include "Util.hpp"
#include <ntimage.h>

PVOID Util::GetExportedFunctionAddress(PEPROCESS TargetProcess, PVOID ModuleBase, const CHAR* ExportedFunctionName)
{
	KAPC_STATE State;
	PVOID FunctionAddress = 0;
	if (TargetProcess != NULL)
		KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);

	do
	{
		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
		PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)(DosHeader->e_lfanew + (ULONG64)ModuleBase);
		IMAGE_DATA_DIRECTORY ImageDataDirectory = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		if (ImageDataDirectory.Size == 0 || ImageDataDirectory.VirtualAddress == 0)
			break;

		PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)ModuleBase + ImageDataDirectory.VirtualAddress);
		ULONG* Address = (ULONG*)((ULONG64)ModuleBase + ExportDirectory->AddressOfFunctions);
		ULONG* Name = (ULONG*)((ULONG64)ModuleBase + ExportDirectory->AddressOfNames);
		USHORT* Ordinal = (USHORT*)((ULONG64)ModuleBase + ExportDirectory->AddressOfNameOrdinals);

		STRING TargetExportedFunctionName;
		RtlInitString(&TargetExportedFunctionName, ExportedFunctionName);

		for (size_t i = 0; i < ExportDirectory->NumberOfFunctions; i++)
		{
			STRING CurrentExportedFunctionName;
			RtlInitString(&CurrentExportedFunctionName, (PCHAR)ModuleBase + Name[i]);

			if (RtlCompareString(&TargetExportedFunctionName, &CurrentExportedFunctionName, TRUE) == 0)
			{
				FunctionAddress = (PVOID)((ULONG64)ModuleBase + Address[Ordinal[i]]);
				break;
			}
		}

	} while (0);

	if (TargetProcess != NULL)
		KeUnstackDetachProcess(&State);

	return FunctionAddress;
}

NTSTATUS Util::Sleep(ULONGLONG microseconds)
{
	LARGE_INTEGER delay;
	delay.QuadPart = -1 * microseconds * 10;
	return KeDelayExecutionThread(KernelMode, 0, &delay);
}
