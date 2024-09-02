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
#include "DbgBlock.hpp"

#define _e Util::Ensure

#define KUSER_SHARED_DATA_RING3 ((PVOID)0x7FFE0000)

extern "C" {
	NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);
	NTKERNELAPI PVOID NTAPI PsGetProcessSectionBaseAddress(IN PEPROCESS Process);
	NTKERNELAPI NTSTATUS NTAPI PsGetContextThread(IN PETHREAD Thread, IN OUT PCONTEXT Context, IN KPROCESSOR_MODE PreviousMode);
}

HANDLE targetProcId;
PKUSER_SHARED_DATA fakeSharedData;

NTSTATUS(*NtQueryPerformanceCounter)(PLARGE_INTEGER perfCounter, PLARGE_INTEGER perfFreq);
NTSTATUS NtQueryPerformanceCounterHook(PLARGE_INTEGER perfCounter, PLARGE_INTEGER perfFreq) {
	if (PsGetCurrentProcessId() == targetProcId) {
		auto proc = PsGetCurrentProcess();
		auto exeStart = PsGetProcessSectionBaseAddress(proc);
		CONTEXT context;
		if (NT_SUCCESS(PsGetContextThread(PsGetCurrentThread(), &context, UserMode))) {
			KAPC_STATE apcState;
			KeStackAttachProcess(proc, &apcState);
			auto stack = (void**)context.Rsp;
			KdPrint(("backtrace start\n"));
			for (int i = 0; i < 10; ++i) {
				if (!MmIsAddressValid(stack + i)) {
					break;
				}
				auto p = stack[i];
				if (p >= exeStart && p <= (void*)((uintptr_t)exeStart + 0x9D17600)) {
					KdPrint(("base+0x%p\n", p));
				}
				else {
					KdPrint(("<?dml?><exec cmd=\"ln %p\">%p</exec>\n", p, p));
				}
			}
			KdPrint(("backtrace end\n"));
			KeUnstackDetachProcess(&apcState);
		}
	}

	*perfCounter = KeQueryPerformanceCounter(perfFreq);
	return STATUS_SUCCESS;
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
				// replace kernel-user shared data
				// https://blog.csdn.net/zhangmiaoping23/article/details/54682935
				KAPC_STATE apcState;
				KeStackAttachProcess(proc, &apcState);
				// load shared data into tlb
				[[maybe_unused]] volatile auto x = *(void**)KUSER_SHARED_DATA_RING3;
				auto pte = PteUtils::MiGetPteAddress(KUSER_SHARED_DATA_RING3);
				auto physAddr = MmGetPhysicalAddress(fakeSharedData);
				pte->u.Hard.PageFrameNumber = physAddr.QuadPart >> 12;
				_ReadWriteBarrier();
				__invlpg(KUSER_SHARED_DATA_RING3);
				KeUnstackDetachProcess(&apcState);
			}
		}
	}
	else {
		if (procId == targetProcId) {
			targetProcId = nullptr;
		}
	}
}

extern "C" NTKERNELAPI SHORT NtBuildNumber;

NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING) {
	KdPrint(("~ You’re telling me a shrimp fried this kernel? ~\n"));
	targetProcId = nullptr;
	// If NumberOfBytes is PAGE_SIZE or greater, a page-aligned buffer is allocated.
	fakeSharedData = (PKUSER_SHARED_DATA)ExAllocatePool2(POOL_FLAG_NON_PAGED, max(PAGE_SIZE, sizeof(KUSER_SHARED_DATA)), 'temp');
	ASSERT(PAGE_ALIGN(fakeSharedData) == fakeSharedData);
	memcpy(fakeSharedData, SharedUserData, sizeof(KUSER_SHARED_DATA));
	fakeSharedData->QpcBypassEnabled = FALSE;

	DbgBlock::Initialize();
	KdPrint(("Initialized KdBlock\n"));
	if (NtBuildNumber > 10586)
	{
		PteUtils::PteInitialize(DbgBlock::KdBlock.PteBase, *(PVOID*)DbgBlock::KdBlock.MmPfnDatabase);
	}

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
