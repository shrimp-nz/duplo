#include "PteUtils.hpp"

#define MiGetPteOffset(va) ((ULONG)(((ULONG_PTR)(va) >> 12) & 511))

/*PMMPFN*/ PVOID MmPfnDatabase = (PVOID)0xFFFFFA8000000000;
ULONG_PTR MmPteBase = 0xFFFFF68000000000U;
ULONG_PTR MmPdeBase = 0xFFFFF6FB40000000U;
ULONG_PTR MmPpeBase = 0xFFFFF6FB7DA00000U;
ULONG_PTR MmPxeBase = 0xFFFFF6FB7DBED000U;//PxeBase is the virtual address  DirectoryTableBase of the system process and cr3
ULONG_PTR MmPxeSelf = 0xFFFFF6FB7DBEDF68U;

VOID PteUtils::PteInitialize(ULONG_PTR PteBase, /*PMMPFN*/ PVOID PfnDatabase)
{
    MmPteBase = PteBase;
    MmPdeBase = MmPteBase + (MmPteBase >> 9 & 0x7FFFFFFFFF);
    MmPpeBase = MmPdeBase + (MmPdeBase >> 9 & 0x3FFFFFFF);
    MmPxeBase = MmPpeBase + (MmPpeBase >> 9 & 0x1FFFFF);
    MmPxeSelf = MmPxeBase + (MmPxeBase >> 9 & 0xFFF);
    MmPfnDatabase = PfnDatabase;
}

PMMPTE PteUtils::MiGetPteAddress(IN PVOID VirtualAddress)
{
    return (PMMPTE)(MmPteBase + (((ULONG_PTR)VirtualAddress >> 9) & 0x7FFFFFFFF8));
}
PMMPTE PteUtils::MiGetPdeAddress(IN PVOID VirtualAddress)
{
    return (PMMPTE)(MmPdeBase + (((ULONG_PTR)VirtualAddress >> 18) & 0x3FFFFFF8));
}
PMMPTE PteUtils::MiGetPpeAddress(IN PVOID VirtualAddress)
{
    return (PMMPTE)(MmPpeBase + (((ULONG_PTR)VirtualAddress >> 27) & 0x1FFFF8));
}
PMMPTE PteUtils::MiGetPxeAddress(IN PVOID VirtualAddress)
{
    return ((PMMPTE)MmPxeBase + (((ULONG_PTR)VirtualAddress >> 39) & 0x1FF));
}
PVOID PteUtils::MiGetVirtualAddressMappedByPte(IN PMMPTE PteAddress)
{
    return ((PVOID)((((LONG_PTR)PteAddress - (LONG_PTR)MmPteBase) << 25) >> 16));
}

PHYSICAL_ADDRESS PteUtils::MmGetPhysicalAddress(IN PVOID BaseAddress)
{
    PHYSICAL_ADDRESS PhysicalAddress;
    PMMPTE PteAddress;

    PhysicalAddress.QuadPart = 0;

    PteAddress = MiGetPxeAddress(BaseAddress);
    if (PteAddress->u.Hard.Valid == 0)
    {
        KdPrint(("MiGetPxeAddress(0x%p) Failed\n", BaseAddress));
        return PhysicalAddress;
    }

    PteAddress = MiGetPpeAddress(BaseAddress);
    if (PteAddress->u.Hard.Valid == 0)
    {
        KdPrint(("MiGetPpeAddress(0x%p) Failed\n", BaseAddress));
        return PhysicalAddress;
    }

    PteAddress = MiGetPdeAddress(BaseAddress);
    if (PteAddress->u.Hard.Valid == 0)
    {
        KdPrint(("MiGetPdeAddress(0x%p) Failed\n", BaseAddress));
        return PhysicalAddress;
    }

    if (PteAddress->u.Hard.LargePage == 1)
    {
        PhysicalAddress.QuadPart = PteAddress->u.Hard.PageFrameNumber + MiGetPteOffset(BaseAddress);
    }
    else
    {
        PteAddress = MiGetPteAddress(BaseAddress);
        if (PteAddress->u.Hard.Valid == 0)
        {
            KdPrint(("MiGetPteAddress(0x%p) Failed\n", BaseAddress));
            return PhysicalAddress;
        }
        PhysicalAddress.QuadPart = PteAddress->u.Hard.PageFrameNumber;
    }

    PhysicalAddress.QuadPart = PhysicalAddress.QuadPart << PAGE_SHIFT;
    PhysicalAddress.LowPart += BYTE_OFFSET(BaseAddress);
    return PhysicalAddress;
}

//PVOID PteUtils::MmGetVirtualForPhysical(PHYSICAL_ADDRESS PhysicalAddress)
//{
//    ULONG PageIndex = PhysicalAddress.LowPart >> 12;
//    ULONG PageOffset = PhysicalAddress.LowPart & 0xFFF;
//
//    PMMPTE PteAddress = MmPfnDatabase[PageIndex].PteAddress;
//    return (PUCHAR)MiGetVirtualAddressMappedByPte(PteAddress) + PageOffset;
//}