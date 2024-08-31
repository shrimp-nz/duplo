extern "C" {
#include <ntifs.h>
}

typedef struct _MMPTE_HARDWARE64
{
    ULONGLONG Valid : 1;
    ULONGLONG Dirty1 : 1;
    ULONGLONG Owner : 1;
    ULONGLONG WriteThrough : 1;
    ULONGLONG CacheDisable : 1;
    ULONGLONG Accessed : 1;
    ULONGLONG Dirty : 1;
    ULONGLONG LargePage : 1;
    ULONGLONG Global : 1;
    ULONGLONG CopyOnWrite : 1;
    ULONGLONG Unused : 1;
    ULONGLONG Write : 1;
    ULONGLONG PageFrameNumber : 36;
    ULONGLONG reserved1 : 4;
    ULONGLONG SoftwareWsIndex : 11;
    ULONGLONG NoExecute : 1;
} MMPTE_HARDWARE64, * PMMPTE_HARDWARE64;

typedef struct _MMPTE
{
    union
    {
        ULONG_PTR Long;
        MMPTE_HARDWARE64 Hard;
    } u;
} MMPTE;
typedef MMPTE* PMMPTE;

namespace PteUtils {
	VOID PteInitialize(ULONG_PTR PteBase, /*PMMPFN*/ PVOID PfnDatabase);
	PHYSICAL_ADDRESS MmGetPhysicalAddress(IN PVOID BaseAddress);
    PMMPTE MiGetPteAddress(IN PVOID VirtualAddress);
    PMMPTE MiGetPdeAddress(IN PVOID VirtualAddress);
    PMMPTE MiGetPpeAddress(IN PVOID VirtualAddress);
    PMMPTE MiGetPxeAddress(IN PVOID VirtualAddress);
    PVOID MiGetVirtualAddressMappedByPte(IN PMMPTE PteAddress);
    PHYSICAL_ADDRESS MmGetPhysicalAddress(IN PVOID BaseAddress);
    //PVOID MmGetVirtualForPhysical(PHYSICAL_ADDRESS PhysicalAddress);
}