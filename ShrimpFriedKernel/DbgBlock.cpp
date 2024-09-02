#include "DbgBlock.hpp"

typedef struct _DUMP_HEADER
{
    ULONG Signature;
    ULONG ValidDump;
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG_PTR DirectoryTableBase;
    ULONG_PTR PfnDataBase;
    PLIST_ENTRY PsLoadedModuleList;
    PLIST_ENTRY PsActiveProcessHead;
    ULONG MachineImageType;
    ULONG NumberProcessors;
    ULONG BugCheckCode;
    ULONG_PTR BugCheckParameter1;
    ULONG_PTR BugCheckParameter2;
    ULONG_PTR BugCheckParameter3;
    ULONG_PTR BugCheckParameter4;
    CHAR VersionUser[32];
    struct _KDDEBUGGER_DATA64* KdDebuggerDataBlock;
} DUMP_HEADER, * PDUMP_HEADER;

#ifndef _WIN64
#define DUMP_BLOCK_SIZE 0x20000
#else
#define DUMP_BLOCK_SIZE 0x40000
#endif

#ifndef _WIN64
#define KDDEBUGGER_DATA_OFFSET 0x1068
#else
#define KDDEBUGGER_DATA_OFFSET 0x2080
#endif

extern "C" NTKERNELAPI ULONG NTAPI
KeCapturePersistentThreadState(
    IN PCONTEXT Context,
    IN PKTHREAD Thread,
    IN ULONG BugCheckCode,
    IN ULONG BugCheckParameter1,
    IN ULONG BugCheckParameter2,
    IN ULONG BugCheckParameter3,
    IN ULONG BugCheckParameter4,
    OUT PVOID VirtualAddress
);

KDDEBUGGER_DATA64 DbgBlock::KdBlock;

/// <summary>
/// Initialize debugger block g_KdBlock
/// </summary>
VOID DbgBlock::Initialize()
{
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&context);

    auto dumpHeader = (PDUMP_HEADER)ExAllocatePool2(POOL_FLAG_NON_PAGED, DUMP_BLOCK_SIZE, 'temp');
    if (dumpHeader)
    {
        KeCapturePersistentThreadState(&context, NULL, 0, 0, 0, 0, 0, dumpHeader);
        RtlCopyMemory(&KdBlock, (PUCHAR)dumpHeader + KDDEBUGGER_DATA_OFFSET, sizeof(KdBlock));

        ExFreePool(dumpHeader);
    }
}