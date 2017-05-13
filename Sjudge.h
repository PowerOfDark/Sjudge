//
// Created by powerofdark on 13.05.17.
//

#ifndef SJUDGE_SJUDGE_H
#define SJUDGE_SJUDGE_H

#include "pin.H"

long long GetVmSize(int pid);

long long GetVmPeak(int pid);

long long GetProcStatusValue(int pid, string key);

void ReportResult(int code, const char* msg);

void Fail(const char* msg);

void Forbidden(const char* msg);

int OutputFd;
char OutputBuffer[1024];
const char* ALLOWED_OPEN_DIRECTORIES[] = {
        "/lib/",
        "/usr/lib/",
        "/etc/ld.so",
        "/proc",
        "/etc/timezone",
        0
};

long long MemoryUsage;
long long MemoryUsagePeak;
long long TimeLimit;
long long HardTimeLimit;
long long MemoryLimit;
long long OutputLimit;
long long BaseMemoryUsage;
long long RealMemoryUsagePeak;
long long RealBaseMemoryUsage;
long long PinBaseMemory;
bool Silent = false;
bool DisableSyscallFilter;
bool CountSystemTime;
long long StaticMemoryUsage;

#define CPU_CYCLE_TIME (2 * 1000000)
#define CPU_CACHE_TIME (2 * 1000000)

long long SyscallCount;
long long SyscallLimit;
int FailedReadCount;
time_t Started;

extern const char* GetReturnValueString(int ret);


struct SupervisorThreadDataItem
{
    int LastSyscall;
};

SupervisorThreadDataItem SupervisorThreadData[16384];

#endif //SJUDGE_SJUDGE_H
