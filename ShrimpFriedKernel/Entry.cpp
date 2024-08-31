// cwopywight jujhar singh 2024
// a shrimp fried this kernel a shrimp fried this kernel a shrimp fried this kernel a shrimp fried this kernel

//    _________
//   / /  /  :D\
//  /  |  |    /
// /          /
// |    ||//\/\
//  |  /  \\\//
//  \ |
//  /|\
// | \ \

// open the gate to hell ~

extern "C" {
#include <ntifs.h>
}

#include <InfinityHook_latest/etwhook_utils.hpp>
#include <InfinityHook_latest/etwhook_manager.hpp>
#include <kstl/kpe_parse.hpp>
#include <NoPgCallback/Npg.h>
#include <PteUtils/PteUtils.hpp>

#include "Util.hpp"
#include "Syscall.hpp"

#define _e Util::Ensure 

extern "C" {
	NTKERNELAPI PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);
	NTKERNELAPI PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
}

HANDLE targetProcId;

NTSTATUS(*NtQueryPerformanceCounter)(PLARGE_INTEGER perfCounter, PLARGE_INTEGER perfFreq);
NTSTATUS NtQueryPerformanceCounterHook(PLARGE_INTEGER perfCounter, PLARGE_INTEGER perfFreq) {
	if (PsGetCurrentProcessId() == targetProcId) {
		auto proc = PsGetCurrentProcess();
		auto exeStart = PsGetProcessSectionBaseAddress(proc);
		void* backTrace[20];
		auto backTraceLen = RtlCaptureStackBackTrace(0, sizeof(backTrace) / sizeof(backTrace[0]), backTrace, nullptr);
		KdPrint(("backtrace start\n"));
		for (auto i = 0; i < backTraceLen; i++) {
			auto p = backTrace[i];
			if (p >= exeStart && p <= (void*)((uintptr_t)exeStart + 0x9D17600)) {
				KdPrint(("base+0x%p\n", p));
			}
			else {
				KdPrint(("<?dml?><exec cmd=\"ln %p\">%p</exec>\n", p, p));
			}
		}
		KdPrint(("backtrace end\n"));
	}
	return NtQueryPerformanceCounter(perfCounter, perfFreq);
}

extern "C" char* PsGetProcessImageFileName(PEPROCESS p);

void OnProcessCreate(HANDLE /*parentId*/, HANDLE procId, BOOLEAN create) {
	if (create) {
		PEPROCESS proc;
		if (NT_SUCCESS(PsLookupProcessByProcessId(procId, &proc))) {
			// TODO: lol
			auto procName = PsGetProcessImageFileName(proc);
			auto targetProc = "RobloxStudioBe";
			if (strcmp(procName, targetProc) == 0) {
				KdPrint(("found game process (id: 0x%p)\n", procId));
				targetProcId = procId;
				// TODO: replace kernel-user shared data
				DbgRaiseAssertionFailure();
			}
		}
	}
	else {
		if (procId == targetProcId) {
			targetProcId = nullptr;
		}
	}
}

extern "C" PSHORT NtBuildNumber;

NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING) {
	KdPrint(("~ You’re telling me a shrimp fried this kernel? ~\n"));
	targetProcId = nullptr;

	//InitializeDebuggerBlock();
	//if (*NtBuildNumber > 10586)
	//{
	//	PteUtils::PteInitialize(g_KdBlock.PteBase, *(PMMPFN*)g_KdBlock.MmPfnDatabase);
	//}

	SHORT queryPerfCounterSyscallNumber;
	if (!Syscall::GetNtSyscallNumber(&queryPerfCounterSyscallNumber, "NtQueryPerformanceCounter")) {
		KdPrint(("failed to find NtQueryPerformanceCounter syscall number\n"));
		DbgRaiseAssertionFailure();
	}
	KdPrint(("NtQueryPerformanceCounter syscall #: %hi\n", queryPerfCounterSyscallNumber));

	auto ssdt = Syscall::GetSSDT();
	if (!ssdt) {
		KdPrint(("failed to find SSDT\n"));
		DbgRaiseAssertionFailure();
	}
	KdPrint(("SSDT: <?dml?><exec cmd=\"ln %p\">0x%p</exec>\n", ssdt, ssdt));
	NtQueryPerformanceCounter = (decltype(NtQueryPerformanceCounter))Syscall::GetNtSyscallFunc(ssdt, queryPerfCounterSyscallNumber);
	KdPrint(("NtQueryPerformanceCounter: <?dml?><exec cmd=\"ln %p\">0x%p</exec>\n", NtQueryPerformanceCounter, NtQueryPerformanceCounter));

	auto hookManager = EtwHookManager::get_instance();
	_e(hookManager->init(), "failed to initialize hook manager\n");
	_e(hookManager->add_hook(NtQueryPerformanceCounter, NtQueryPerformanceCounterHook), "failed to add NtQueryPerformanceCounterHook hook\n");

	void* trampoline;
	_e(SetCreateProcessNotifyRoutine(OnProcessCreate, &trampoline), "failed to register process creation callback\n");

	return 0;
}
