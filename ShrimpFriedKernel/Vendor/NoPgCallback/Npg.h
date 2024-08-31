// https://github.com/patrickcjk/notify-routine-poc/tree/master
#pragma once
extern "C" {
#include <Ntifs.h>
}

NTSTATUS SetCreateProcessNotifyRoutine(IN PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine, OUT void** TrampolineBase);
NTSTATUS UnSetCreateProcessNotifyRoutine(IN void** TrampolineBase);