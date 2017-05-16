/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2012 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */


#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <sys/time.h>
#include <signal.h>
#include <sys/resource.h>
#include <climits>
#include <cerrno>
#include <cstdlib>
#include <portability.H>
#include "pin.H"
//#include "prototypes.h"
#include "supervisor.h"
#include "InsCounter.h"
#include "CacheSimulation.h"
#include "Sjudge.h"
#include "Handlers.h"

using namespace std;


void Fail(const char* msg)
{
    char* reason; // eax@1
    reason = strerror(errno);
    fprintf(stderr, "supervisor: %s (errno='%s')\n", msg, reason);
    exit(122);
}

void Forbidden(const char* msg)
{
    ReportResult(RETVAL_RV, msg);
}

static char* GetEnvironmentString(const char* name, const char* name2, const char* dflt)
{
    char* ret;
    char* t = getenv(name);
    if (!t)
        if (!name2 || !(t = getenv(name2)))
            return strdup(dflt);
    ret = strdup(t);
    unsetenv(name);
    return ret;
}

static long long GetEnvironmentInteger(const char* name, const char* name2, long dflt)
{
    long long ret;
    char* t = getenv(name);
    if (!t)
        if (!name2 || !(t = getenv(name2)))
            return dflt;
    ret = strtoll(t, NULL, 0);
    unsetenv(name);
    return ret;
}

static int GetEnvironmentBool(const char* name, const char* name2, int dflt)
{
    int ret;
    char* t = getenv(name);
    if (!t)
        if (!name2 || !(t = getenv(name2)))
            return dflt;
    ret = (t[0] != '\0') && (t[0] != '0');
    unsetenv(name);
    return ret;
}

inline void CheckMemoryLimits()
{
    INT64 vmSize = GetVmSize(getpid());
    INT64 pinMemory = LEVEL_PINCLIENT::PIN_MemoryAllocatedForPin() >> 10;
    if (vmSize > RealMemoryUsagePeak) RealMemoryUsagePeak = vmSize;
    INT64 memoryUsage = vmSize - pinMemory - BaseMemoryUsage;
    if (memoryUsage != MemoryUsage)
    {
        MemoryUsage = memoryUsage;
        if (memoryUsage > MemoryUsagePeak)
        {
            MemoryUsagePeak = memoryUsage;
            if (memoryUsage > MemoryLimit)
            {
                ReportResult(RETVAL_MLE, GetReturnValueString(RETVAL_MLE));
            }
        }
    }
}


#pragma region syscall

VOID OnSycallEntry(THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* useless)
{
    UINT32 syscallNum;
    const char* syscallName;

    syscallNum = PIN_GetSyscallNumber(ctxt, std);

    INT16 flags = GetSyscallFlags(syscallNum);
    if (++SyscallCount > SyscallLimit)
        ReportResult(RETVAL_TLE, "syscalls limit exceeded");
    if (flags & SC_SKIP)
    {
        PIN_SetSyscallNumber(ctxt, std, VoidStar2Addrint((VOID*) -1));
        goto RETURN;
    }
    if (!(flags & SC_ALLOWED))
    {
        char buf[256];
        syscallName = GetSyscallName(syscallNum);
        snprintf(buf, 256, "intercepted Forbidden syscall %d (%s)", syscallNum, syscallName);
        Forbidden(buf);
    }
    if (flags & SC_TRAP)
    {
        bool allowed = (bool) Handlers::OnSyscallEntry(syscallNum, threadIndex, ctxt, std);
        if (!allowed)
        {
            PIN_SetSyscallNumber(ctxt, std, VoidStar2Addrint((VOID*) -1));
        }
    }
RETURN:;
    SupervisorThreadData[threadIndex].LastSyscall = syscallNum;
}


VOID OnSycallExit(THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* useless)
{
    UINT32 syscallNum = (UINT32) SupervisorThreadData[threadIndex].LastSyscall;
    INT16 flags = GetSyscallFlags(syscallNum);

    if (flags & SC_TRAP)
    {
        Handlers::OnSyscallExit(syscallNum, threadIndex, ctxt, std);
    }
    if (flags & SC_MEMORY)
    {
        CheckMemoryLimits();
    }
}

#pragma endregion syscall

long long GetProcStatusValue(int pid, string key)
{
    const int bufsz = 84;
    char buf[bufsz];
    snprintf(buf, bufsz, "/proc/%d/status", pid);
    FILE* stream = fopen(buf, "r");
    if (!stream)
    {
        Fail("cannot open /proc/.../status");
    }

    long long res = 0;
    while (fgets(buf, bufsz, stream) != NULL)
    {
        if (strstr(buf, key.c_str()) != NULL)
        {
            if (sscanf(buf, "%*s %lld", &res) == 1)
            {
                break;
            }
        }
    }
    fclose(stream);
    if (res == 0) Fail("cannot find proc status entry");
    return res;


}

long long GetVmSize(int pid)
{
    return GetProcStatusValue(pid, "VmSize");
}

long long GetVmPeak(int pid)
{
    return GetProcStatusValue(pid, "VmPeak");
}

const char* GetReturnValueString(int ret)
{
    switch (ret)
    {
        case RETVAL_OK:
            return "Exited normally";
        case RETVAL_TLE:
            return "Time limit exceeded";
        case RETVAL_MLE:
            return "Memory limit exceeded";
        case RETVAL_RE:
            return "Runtime error";
        case RETVAL_RV:
            return "Rule violation";
        case RETVAL_OLE:
            return "Output limit exceeded";
        default:
            return "Unknown error";
    }
}


void ReportResult(int code, const char* msg)
{
    UINT64 totalInsCount = 0;
    UINT64 totalCacheMissCount = 0;
    UINT64 totalMemoryTime;
    UINT64 totalTime;
    UINT64 totalCpuTime;


    for (int i = 0; i < InsCounter::ThreadCount; i++)
    {
        totalInsCount += InsCounter::ThreadData[i]._count;
    }

    totalCpuTime = totalInsCount / CPU_CYCLE_TIME;

    for (int i = 0; i < CacheSimulation::ThreadCount; i++)
    {
        totalCacheMissCount += CacheSimulation::ThreadData[i]._count;
    }

    totalMemoryTime = totalCacheMissCount / CPU_CACHE_TIME;
    totalTime = (totalMemoryTime + totalCpuTime);

    if (MemoryUsagePeak >= MemoryLimit)
    {
        code = RETVAL_MLE;
    }
    else
    {
        if (totalTime >= (UINT64)TimeLimit)
        {
            code = RETVAL_TLE;
        }
    }
    fputc(10, stderr);
    fprintf(
            stderr,
            "__RESULT__ %d %lld %u %lld %lld\n%s\n", //code time(total) time(real?) (mem usage) (syscall count) (result)
            code,
            (long long) totalTime,
            0,
            MemoryUsagePeak,
            SyscallCount,
            msg);
    if (!Silent)
    {
        fprintf(stderr, "SUPERVISOR REPORT\n");
        fprintf(stderr, "-----------------\n");
        fprintf(stderr, "  Result code: %s\n", GetReturnValueString(code));
        fprintf(stderr, "  Time:        %lldms\n", (long long) totalTime);
        fprintf(stderr, "  CPU time:    %lldms\n", (long long) totalCpuTime);
        fprintf(stderr, "  Memory time: %lldms\n", (long long) totalMemoryTime);
        fprintf(stderr, "  Memory used: %lldkB\n", MemoryUsagePeak);
        fprintf(stderr, "  Comment:     %s\n", msg);
        fprintf(stderr, "  Syscalls:    %lld\n\n", SyscallCount);
        fprintf(stderr, "  Real peak:   %lldkB\n", GetVmPeak(getpid()));

    }
    PIN_ExitProcess(0);
}


BOOL Periodic(THREADID tid, INT32 sig, CONTEXT* ctxt, BOOL hasHandler, const EXCEPTION_INFO* pExceptInfo, VOID* v)
{

    UINT64 totalInsCount = 0;
    UINT64 totalCacheMissCount = 0;
    UINT64 totalCpuTime = 0;
    UINT64 totalMemoryTime = 0;

    for (int i = 0; i < InsCounter::ThreadCount; i++)
    {
        totalInsCount += (InsCounter::ThreadData[i]._count);
    }
    totalCpuTime = totalInsCount / CPU_CYCLE_TIME;

    for (int i = 0; i < CacheSimulation::ThreadCount; i++)
    {
        totalCacheMissCount += (CacheSimulation::ThreadData[i]._count);
    }
    totalMemoryTime = totalCacheMissCount / CPU_CYCLE_TIME;

    CheckMemoryLimits();
    if ((totalCpuTime + totalMemoryTime) >= (UINT64)TimeLimit)
    {
        ReportResult(RETVAL_TLE, "time limit exceeded");
    }
    if (HardTimeLimit)
    {
        if ((Started + HardTimeLimit) < time(0))
        {
            ReportResult(RETVAL_TLE, "hard time limit exceeded");
        }
    }
    return 0;
}

BOOL OnErrorSignal(THREADID tid, int sig, CONTEXT* ctxt, BOOL hasHandler, const EXCEPTION_INFO* pExceptInfo,
                   VOID* v)
{
    char buf[256];

    snprintf(buf, 256, "process exited due to signal %d", sig);
    ReportResult(sig, buf);
    return 0;//just for the sake of completeness
}

VOID Fini(int code, VOID* v)
{
    FILE* f = fopen("out2", "w");
    fprintf(f, "Fini()\n");
    fclose(f);
    char buf[64];
    CheckMemoryLimits();
    if (code == 0)
    {
        ReportResult(0, "ok");
    }
    snprintf(buf, 64, "runtime error %d", code);
    ReportResult(code + 200, buf);
}


VOID OnImageLoaded(IMG img, VOID* v)
{
    UINT32 mem;
    if (IMG_Valid(img))
    {
        mem = (UINT32) (IMG_HighAddress(img) - IMG_LowAddress(img)) >> 10;
        StaticMemoryUsage += mem;
        BaseMemoryUsage -= mem;
    }
}

VOID OnImageUnloaded(IMG img, VOID* v)
{
    UINT32 mem;
    if (IMG_Valid(img))
    {
        mem = (UINT32) (IMG_HighAddress(img) - IMG_LowAddress(img)) >> 10;
        StaticMemoryUsage -= mem;
        BaseMemoryUsage += mem;
    }
}

int main(int argc, char* argv[])
{
    int result;

    if (LEVEL_PINCLIENT::PIN_Init(argc, argv))
    {
        result = 0;
    }
    else
    {
        OutputFd = 2; //stderr
        InsCounter::Start();
        bool simulateCache = (bool) GetEnvironmentBool("CACHE", "CACHESIM", 0);
        if (simulateCache)
        {
            CacheSimulation::Start();
        }
        LEVEL_PINCLIENT::PIN_AddSyscallEntryFunction(OnSycallEntry, 0);
        LEVEL_PINCLIENT::PIN_AddSyscallExitFunction(OnSycallExit, 0);
        LEVEL_PINCLIENT::PIN_InterceptSignal(SIGALRM, Periodic, 0);
        LEVEL_PINCLIENT::PIN_UnblockSignal(SIGALRM, 1);
        LEVEL_PINCLIENT::PIN_AddFiniFunction(Fini, 0);
        LEVEL_PINCLIENT::IMG_AddInstrumentFunction(OnImageLoaded, 0);
        LEVEL_PINCLIENT::IMG_AddUnloadFunction(OnImageUnloaded, 0);
        PinBaseMemory = (UINT32) LEVEL_PINCLIENT::PIN_MemoryAllocatedForPin() >> 10;
        RealMemoryUsagePeak = RealBaseMemoryUsage = GetVmSize(getpid());
        BaseMemoryUsage = RealBaseMemoryUsage - PinBaseMemory;

        Silent = (bool) GetEnvironmentBool("QUIET", "SILENT", 0);

        if (!Silent)
        {
            fprintf(stderr, "SJudge PinSupervisor version 0.99999\n");
            fprintf(stderr, "Copyright 2004-2011 (C) Szymon Acedanski\n\n");
        }
        MemoryLimit = GetEnvironmentInteger("MEM_LIMIT", "MEM", 256000) & 0xFFFFFFFC;
        TimeLimit = GetEnvironmentInteger("TIME_LIMIT", "TIME", 10000);
        HardTimeLimit = GetEnvironmentInteger("HARD_LIMIT", "HARD", (TimeLimit << 6) / 1000 + 24);
        OutputLimit = GetEnvironmentInteger("OUT_LIMIT", 0, 50000000);
        SyscallLimit = GetEnvironmentInteger("SC_LIMIT", 0, (long) (300000ULL * TimeLimit / 100ULL));
        CountSystemTime = (bool) GetEnvironmentBool("SYSTIME", 0, 1);
        DisableSyscallFilter = (bool) GetEnvironmentBool("ALLOW", 0, 0);
        Started = time(0);
        if (!Silent)
        {
            fprintf(stderr, "Memory limit:   %lld kB\n", MemoryLimit);
            fprintf(stderr, "Time limit:     %lld msecs\n", TimeLimit);
            fprintf(stderr, "Output limit:   %lld kB\n", OutputLimit / 1024);
            fprintf(stderr, "System time:    %scounted\n\n", CountSystemTime ? "" : "not");
            fprintf(stderr, "Syscall filter: %sabled\n", DisableSyscallFilter ? "dis" : "en");
            fprintf(stderr, "Cache simulation: %sabled\n", simulateCache ? "en" : "dis");
            fprintf(stderr, "Memory at startup: %lld kB\n", RealBaseMemoryUsage);
            fprintf(stderr, "PIN  mem at start: %lld kB\n\n", PinBaseMemory);
        }

        int signals[] = {SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGBUS, SIGFPE, SIGUSR1, SIGSEGV, SIGUSR2,
                         SIGPIPE, SIGTERM, SIGXCPU, SIGXFSZ, 0xFFFF};
        int i = 0;
        do
        {
            PIN_InterceptSignal(signals[i], OnErrorSignal, 0);
            PIN_UnblockSignal(signals[i], 1);
        } while (signals[++i] != 0xFFFF);

        rlimit lim;
        lim.rlim_cur = lim.rlim_max = 0;
        if (setrlimit(RLIMIT_CORE, &lim))
            Fail("setrlimit(RLIMIT_CORE) failed");

        lim.rlim_cur = lim.rlim_max = (rlim_t) -1; //infinity
        if (setrlimit(RLIMIT_STACK, &lim))
            Fail("setrlimit(RLIMIT_STACK) failed");

        itimerval timerInterval;
        timeval tv;
        tv.tv_usec = 100000;
        tv.tv_sec = 0;
        timerInterval.it_interval = timerInterval.it_value = tv;
        if (setitimer(0, &timerInterval, 0) < 0)
            Fail("cannot set interval timer");

        LEVEL_PINCLIENT::PIN_StartProgram();
        result = 0;
    }
    return result;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
