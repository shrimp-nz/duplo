#pragma once
extern "C" {
#include <ntifs.h>
}

namespace Util {
	template<typename... Ts>
	__forceinline void Ensure(NTSTATUS status, [[maybe_unused]] const char* format, [[maybe_unused]] Ts... args) {
		if (!NT_SUCCESS(status)) {
			KdPrint(("shrimp failure :c (status: 0x%X): ", status));
			KdPrint((format, args...));
			DbgRaiseAssertionFailure();
		}
	}

	__forceinline void EnsureDebug([[maybe_unused]] NTSTATUS status, [[maybe_unused]] const char* message) {
#if DBG
		Ensure(status, message);
#endif
	}

	PVOID GetExportedFunctionAddress(PEPROCESS TargetProcess, PVOID ModuleBase, CONST CHAR* ExportedFunctionName);
}