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
#include "pin.H"
//#include "prototypes.h"
#include "supervisor.h"
#include "inscount.h"
#include "cachesim.h"

using namespace std;

extern "C" short syscall_flag(int id);
extern "C" const char* syscall_name(int);

long long get_vmsize(int pid);

long long get_vmpeak(int pid);

long long get_procstatus(int pid, string key);

void report_result(int a1, const char* a2);

void fail(const char* a1);

void forbidden(const char* a1);

int super_out_fd = 0;
char super_out_buf[1024];
const char* allowed_open_dirs[] = {
        "/lib/",
        "/usr/lib/",
        "/etc/ld.so",
        "/proc",
        "/etc/timezone",
        0
};
long long used_memory = 0;
long long max_memory = 0;
long long time_limit = 0;
long long hard_time_limit = 0;
long long mem_limit = 0;
long long out_limit = 0;
long long base_memory = 0;
long long real_peak_mem = 0;
long long real_base_memory = 0;
long long pin_base_memory = 0;
bool quiet = false;
bool allow_all = false;
bool count_systime = false;
long long static_memory = 0;

#define CPU_CYCLE_TIME (2 * 1000000)
#define CPU_CACHE_TIME (2 * 1000000)


int supervisor_thread_data[16384];


void fail(const char* msg)
{
    char* reason; // eax@1
    reason = strerror(errno);
    fprintf(stderr, "supervisor: %s (errno='%s')\n", msg, reason);
    exit(122);
}

void forbidden(const char* a1)
{
    report_result(RETVAL_RV, a1);
}

static char* get_env_string(const char* name, const char* name2, const char* dflt)
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

static long long get_env_number(const char* name, const char* name2, long dflt)
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

static int get_env_bool(const char* name, const char* name2, int dflt)
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

inline void checkMemoryLimits()
{
    INT64 vmSize = get_vmsize(getpid());
    INT64 pinMemory = LEVEL_PINCLIENT::PIN_MemoryAllocatedForPin() >> 10;
    real_peak_mem = max(real_peak_mem, vmSize);
    INT64 memoryUsage = vmSize - pinMemory - base_memory;
    if (memoryUsage != used_memory)
    {
        used_memory = memoryUsage;
        if (memoryUsage > max_memory)
        {
            max_memory = memoryUsage;
            if (memoryUsage > mem_limit)
            {
                report_result(124, "memory limit exceeded");
            }
        }
    }
}


#pragma region syscall
int syscalls_counter = 0;
long long sc_limit = 0;
int failed_reads_counter = 0;
time_t time_started = 0;

const char* result_codes[256] = {};

const short _sys_kill = 0x25;
const short _sys_tkill = 0xee;
const short _sys_tgkill = 0x10e;

const short _sys_read = 0x03;
const short _sys_write = 0x04;
const short _sys_open = 0x05;

const short _sys_readv = 0x91;
const short _sys_writev = 0x92;


struct ArgHelper
{
    CONTEXT* _ctxt;
    SYSCALL_STANDARD _std;

    void* operator[](UINT32 n)
    {
        return Addrint2VoidStar(PIN_GetSyscallArgument(_ctxt, _std, n));
    }

    UINT32 operator()(UINT32 n)
    {
        return (UINT32) (UINT64) operator[](n);
    }

    ArgHelper() {}
} getArg;

int quirk_sys_kill_entry(UINT32 pid, UINT32 sig)
{
    if (pid != getpid())
    {
        forbidden("tried to kill some process");
        return 0;
    }

    if (sig == SIGSTOP || sig == SIGTRAP || sig == SIGVTALRM)
    {
        forbidden("used forbidden signal");
        return 0;
    }
    return 1;
}

int quirk_sys_write_entry(UINT32 fd, UINT32 count)
{
    if (fd > 2)
    {
        forbidden("writing to something other than stdout and stderr");
        return 0;
    }

    if (count > (UINT32) out_limit)
    {
        report_result(RETVAL_OLE, "output limit exceeded");
        return 0;
    }
    return 1;
}

int quirk_sys_open_entry(const char* path, UINT32 flags)
{
    fprintf(stderr, "open %05x %s\n", flags, path);
    if (path[0] != '/')
    {
        forbidden("opening files is forbidden");
        return 0;
    }
    char cpath[PATH_MAX + 1];
    if (realpath(path, cpath) == NULL)
    {
        return 0;
    }
    if (flags & O_WRONLY || flags & O_RDWR)
    {
        if (!strcmp("/dev/null", cpath))
            return 1;
        return 0;
    }
    const char** allowed_dirs_iter;
    for (allowed_dirs_iter = allowed_open_dirs; *allowed_dirs_iter; allowed_dirs_iter++)
        if (!strncmp(cpath, *allowed_dirs_iter, strlen(*allowed_dirs_iter)))
            return 1;
    return 0;
}

void quirk_write_exit(UINT32 ret)
{
    if (ret >= 0)
    {
        out_limit -= ret;
    }
}

void quirk_read_exit(UINT32 ret)
{
    if (ret <= 0)
    {
        if (++failed_reads_counter >= 100000)
        {
            report_result(100, "reading past the end of input");
        }
    }
}


int quirk_syscall_entry(unsigned int syscallNum, int a2, CONTEXT* ctxt, SYSCALL_STANDARD std)
{
    getArg._ctxt = ctxt;
    getArg._std = std;

    switch (syscallNum)
    {
        case _sys_kill:
        case _sys_tkill:
        case _sys_tgkill:
        {
            UINT32 tgOffset = (UINT32) (syscallNum == _sys_tgkill);
            UINT32 pid = getArg(0 + tgOffset); //tgkill needs the second argument instead
            UINT32 sig = getArg(1 + tgOffset);
            return quirk_sys_kill_entry(pid, sig);

        }
        case _sys_write:
        {
            UINT32 fd = getArg(0);
            UINT32 count = getArg(2);
            return quirk_sys_write_entry(fd, count);
        }
        case _sys_open:
        {
            const char* path = (const char*) getArg[0];
            UINT32 flags = getArg(1);
            return quirk_sys_open_entry(path, flags);
        }
        case _sys_read:
            return 1;
        default:
        {
            fprintf(stderr, "unknown syscall quirk entry (%x)", syscallNum);
            fail("unknown syscall quirk");
            return 0;
        }
    }
}

short get_syscall_flags(int id)
{
    return syscall_flag(id);
}

VOID syscall_entry(THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* useless)
{
    UINT32 syscallNum; // ebx@1
    const char* syscallName; // eax@9

    syscallNum = PIN_GetSyscallNumber(ctxt, std);

    INT16 flags = get_syscall_flags(syscallNum);
    if (++syscalls_counter > sc_limit)
        report_result(125, "syscalls limit exceeded");
    if (flags & SC_SKIP)
    {
        PIN_SetSyscallNumber(ctxt, std, VoidStar2Addrint((VOID*) -1));
        goto RETURN;
    }
    if (!(flags & SC_ALLOWED))
    {
        char buf[256];
        syscallName = syscall_name(syscallNum);
        snprintf(buf, 256, "intercepted forbidden syscall %d (%s)", syscallNum, syscallName);
        forbidden(buf);
    }
    if (flags & 0x20)
    {
        bool allowed = (bool) quirk_syscall_entry(syscallNum, threadIndex, ctxt, std);
        if (!allowed)
        {
            PIN_SetSyscallNumber(ctxt, std, VoidStar2Addrint((VOID*) -1));
        }
    }
RETURN:;
    supervisor_thread_data[16 * threadIndex] = syscallNum;
}


void quirk_syscall_exit(unsigned int syscallNum, THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std)
{
    UINT32 ret = (UINT32) (UINT64) Addrint2VoidStar(PIN_GetSyscallReturn(ctxt, std));
    switch (syscallNum)
    {
        case _sys_readv:
        case _sys_read:
            quirk_read_exit(ret);
            return;
        case _sys_writev:
        case _sys_write:
            quirk_write_exit(ret);
            return;
        case _sys_kill:
        case _sys_tkill:
        case _sys_tgkill:
        case _sys_open:
            return;
        default:
        {
            fprintf(stderr, "unknown syscall quirk exit (%x)", syscallNum);
            fail("unknown syscall quirk");
            return;
        }

    }
}


VOID syscall_exit(THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* useless)
{
    UINT32 syscallNum = (UINT32) supervisor_thread_data[16 * threadIndex];
    INT16 flags = get_syscall_flags(syscallNum);

    if (flags & 0x20)
    {
        quirk_syscall_exit(syscallNum, threadIndex, ctxt, std);
    }
    if (flags & 2)
    {
        checkMemoryLimits();
    }
}

#pragma endregion syscall

long long get_procstatus(int pid, string key)
{
    const int bufsz = 84;
    char buf[bufsz];
    snprintf(buf, bufsz, "/proc/%d/status", pid);
    FILE* stream = fopen(buf, "r");
    if (!stream)
    {
        fail("cannot open /proc/.../status");
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
    if (res == 0) fail("cannot find proc status entry");
    return res;


}

long long get_vmsize(int a1)
{
    return get_procstatus(a1, "VmSize");
}


long long get_vmpeak(int a1)
{
    return get_procstatus(a1, "VmPeak");
}


void report_result(int a1, const char* a2)
{
    int v2; // ebx@1
    const char* v3; // ebp@1
    THREAD_DATA* v4; // eax@2
    unsigned int v5; // esi@2
    unsigned int v6; // edi@2
    unsigned long long inscount_total = 0; // kr08_8@3
    unsigned long long inscount_last = 0;
    int* v8; // eax@5

    unsigned long long cachesim_total = 0; // kr10_8@6
    unsigned long long cachesim_last = 0;
    unsigned long long v12; // rax@7
    int v13; // edi@7
    unsigned int v14; // esi@7
    int v15; // eax@7
    const char* v16; // eax@20
    int v17; // eax@21
    int v18; // eax@21
    int fd_4; // [sp+4h] [bp-58h]@13
    unsigned long long v20; // [sp+3Ch] [bp-20h]@4

    v2 = a1;
    v3 = a2;
    if (inscount::num_threads <= 0)
    {
        v5 = 0;
        v6 = 0;
    }
    else
    {
        for (int i = 0; i < inscount::num_threads; i++)
        {
            inscount_total += (inscount_last = inscount::thread_data[i]._count);
        }
    }
    v20 = inscount_last / CPU_CYCLE_TIME;
    if (cachesim::num_threads <= 0)
    {
    }
    else
    {
        for (int i = 0; i < cachesim::num_threads; i++)
        {
            cachesim_total += (cachesim_last = cachesim::thread_data[i]._count);
        }
    }
    v12 = cachesim_last / CPU_CACHE_TIME;
    v13 = (int) v12;
    v14 = UINT32(v12 + v20);
    v15 = (int) max_memory;
    if (max_memory >= mem_limit)
    {
        v3 = "memory limit exceeded";
        v2 = 124;
        if (quiet)
        {
            goto LABEL_13;
        }
    }
    else
    {
        if (v14 >= time_limit)
        {
            v3 = "time limit exceeded";
        }
        if (v14 >= time_limit)
        {
            v2 = 125;
        }

        if (quiet)
        {
LABEL_13:
            snprintf(
                    super_out_buf,
                    1024,
                    "__RESULT__ %d %u %u %d %d\n%s\n", //code time(tool) time(real) (mem usage) (syscall count) (result)
                    v2,
                    v14,
                    0,
                    v15,
                    syscalls_counter,
                    v3);
            write(super_out_fd, &super_out_buf, strlen((const char*) &super_out_buf));
            if (quiet)
            {
                goto LABEL_14;
            }
            fwrite("SUPERVISOR REPORT\n", 1u, 0x12u, stderr);
            fwrite("-----------------\n", 1u, 0x12u, stderr);
            if (v2 <= 200 && (v2 <= 0 || v2 >= __libc_current_sigrtmin()))
            {
                if (v2 == 120)
                {
                    v16 = "Output limit exceeded";
                }
                else
                {
                    if (v2 > 120)
                    {
                        if (v2 == 121)
                        {
                            v16 = "Rule violation";
                            goto LABEL_21;
                        }
                        if (v2 == 124)
                        {
                            v16 = "Memory limit exceeded";
                            goto LABEL_21;
                        }
                        v16 = "Time limit exceeded";
                        if (v2 == 125)
                        {
                            goto LABEL_21;
                        }
                    }
                    else
                    {
                        v16 = "Exited normally";
                        if (!v2)
                        {
                            goto LABEL_21;
                        }
                        v16 = "Runtime error";
                        if (v2 == 100)
                        {
                            goto LABEL_21;
                        }
                    }
                    v16 = "???";
                }
            }
            else
            {
                v16 = "runtime error";
            }
LABEL_21:
            fprintf(stderr, "  Result code: %s\n", v16);
            fprintf(stderr, "  Time:        %ums\n", v14);
            fprintf(stderr, "  CPU time:    %ums [total %llu]\n", v20, inscount_last);
            fprintf(stderr, "  Memory time: %ums\n", v13);
            fprintf(stderr, "  Memory used: %ldkB\n", max_memory);
            fprintf(stderr, "  Comment:     %s\n", v3);
            fprintf(stderr, "  Syscalls:    %d\n\n", syscalls_counter);
            v17 = getpid();
            v18 = (int) get_vmpeak(v17);
            fprintf(stderr, "  Real peak:   %dkB\n", v18);
            //fprintf(stderr, "  Count. peak: %ldkB\n");
LABEL_14:
            LEVEL_PINCLIENT::PIN_ExitProcess(0);
        }
    }
    fputc(10, stderr);
    v15 = max_memory;
    goto LABEL_13;
}

BOOL periodic(THREADID tid, INT32 sig, CONTEXT* ctxt, BOOL hasHandler, const EXCEPTION_INFO* pExceptInfo, VOID* v)
{

    UINT64 inscount_total = 0; // rcx@2
    UINT64 cachesim_total = 0;
    UINT64 cpuTime_total = 0;
    UINT64 memTime_total = 0;

    for (int i = 0; i < inscount::num_threads; i++)
    {
        inscount_total += (inscount::thread_data[i]._count);
    }
    cpuTime_total = inscount_total / CPU_CYCLE_TIME;

    for (int i = 0; i < cachesim::num_threads; i++)
    {
        cachesim_total += (cachesim::thread_data[i]._count);
    }
    memTime_total = cachesim_total / CPU_CYCLE_TIME;

    checkMemoryLimits();
    if ((cpuTime_total + memTime_total) >= time_limit)
    {
        report_result(125, "time limit exceeded");
    }
    if (hard_time_limit)
    {
        if ((time_started + hard_time_limit) < time(0))
        {
            report_result(125, "hard time limit exceeded");
        }
    }
    return 0;
}

BOOL error_signal_handler(THREADID tid, int sig, CONTEXT* ctxt, BOOL hasHandler, const EXCEPTION_INFO* pExceptInfo,
                          VOID* v)
{
    char buf[256]; // [sp+20h] [bp-10Ch]@1

    snprintf(buf, 256, "process exited due to signal %d", sig);
    report_result(sig, buf);
    return 0;//just for the sake of completeness
}

VOID Fini(int code, VOID* v)
{
    char buf[64];
    checkMemoryLimits();
    if (code == 0)
    {
        report_result(0, "ok");
    }
    snprintf(buf, 64, "runtime error %d", code);
    report_result(code + 200, buf);
}


VOID image_load(IMG img, VOID* v)
{
    UINT32 mem;
    if (IMG_Valid(img))
    {
        mem = (UINT32) (IMG_HighAddress(img) - IMG_LowAddress(img)) >> 10;
        static_memory += mem;
        base_memory -= mem;
    }
}

VOID image_unload(IMG img, VOID* v)
{
    UINT32 mem;
    if (IMG_Valid(img))
    {
        mem = (UINT32) (IMG_HighAddress(img) - IMG_LowAddress(img)) >> 10;
        static_memory -= mem;
        base_memory += mem;
    }
}

int main(int argc, char* argv[])
{
    result_codes[RETVAL_OK] = "Exited normally";
    result_codes[RETVAL_TLE] = "Time limit exceeded";
    result_codes[RETVAL_MLE] = "Memory limit exceeded";
    result_codes[RETVAL_RE] = "Runtime error";
    result_codes[RETVAL_RV] = "Rule violation";
    result_codes[RETVAL_OLE] = "Output limit exceeded";

    int result; // eax@13

    if (LEVEL_PINCLIENT::PIN_Init(argc, argv))
    {
        result = 0;//Usage(v3);
    }
    else
    {
        super_out_fd = 2; //stderr
        inscount::init();
        bool simulateCache = (bool) get_env_bool("CACHE", "CACHESIM", 0);
        if (simulateCache)
        {
            cachesim::init();
        }
        LEVEL_PINCLIENT::PIN_AddSyscallEntryFunction(syscall_entry, 0);
        LEVEL_PINCLIENT::PIN_AddSyscallExitFunction(syscall_exit, 0);
        LEVEL_PINCLIENT::PIN_InterceptSignal(14, periodic, 0);
        LEVEL_PINCLIENT::PIN_UnblockSignal(14, 1);
        LEVEL_PINCLIENT::PIN_AddFiniFunction(Fini, 0);
        LEVEL_PINCLIENT::IMG_AddInstrumentFunction(image_load, 0);
        LEVEL_PINCLIENT::IMG_AddUnloadFunction(image_unload, 0);
        pin_base_memory = (UINT32) LEVEL_PINCLIENT::PIN_MemoryAllocatedForPin() >> 10;
        real_peak_mem = real_base_memory = get_vmsize(getpid());
        base_memory = real_base_memory - pin_base_memory;

        quiet = (bool) get_env_bool("QUIET", "SILENT", 0);

        if (!quiet)
        {
            fwrite("SJudge PinSupervisor version 0.99999\n", 1u, 0x25u, stderr);
            fwrite("Copyright 2004-2011 (C) Szymon Acedanski\n\n", 1u, 0x2Au, stderr);
        }
        mem_limit = get_env_number("MEM_LIMIT", "MEM", 256000) & 0xFFFFFFFC;
        time_limit = get_env_number("TIME_LIMIT", "TIME", 10000);
        hard_time_limit = get_env_number("HARD_LIMIT", "HARD", (time_limit << 6) / 1000 + 24);
        out_limit = get_env_number("OUT_LIMIT", 0, 50000000);
        sc_limit = get_env_number("SC_LIMIT", 0, (long) (300000ULL * time_limit / 100ULL));
        count_systime = (bool) get_env_bool("SYSTIME", 0, 1);
        allow_all = (bool) get_env_bool("ALLOW", 0, 0);
        time_started = time(0);
        if (!quiet)
        {
            fprintf(stderr, "Memory limit:   %lld kB\n", mem_limit);
            fprintf(stderr, "Time limit:     %lld msecs\n", time_limit);
            fprintf(stderr, "Output limit:   %lld kB\n", out_limit / 1024);
            fprintf(stderr, "System time:    %scounted\n\n", count_systime ? "" : "not");
            fprintf(stderr, "Syscall filter: %sabled\n", allow_all ? "dis" : "en");
            fprintf(stderr, "Cache simulation: %sabled\n", simulateCache ? "en" : "dis");
            fprintf(stderr, "Memory at startup: %lld kB\n", real_base_memory);
            fprintf(stderr, "PIN  mem at start: %lld kB\n\n", pin_base_memory);
        }

        int signals[] = {1, 2, 3, 4, 6, 7, 0xB, 0xD, 0xF, 0xA, 0xC, 5, 0x18, 0x19, 0xFF};
        int i = 0;
        do
        {
            PIN_InterceptSignal(signals[i], error_signal_handler, 0);
            PIN_UnblockSignal(signals[i], 1);
        } while (signals[++i] != 0xFF);

        rlimit lim;
        lim.rlim_cur = lim.rlim_max = 0;
        if (setrlimit(RLIMIT_CORE, &lim))
            fail("setrlimit(RLIMIT_CORE) failed");

        lim.rlim_cur = lim.rlim_max = (rlim_t) -1; //infinity
        if (setrlimit(RLIMIT_STACK, &lim))
            fail("setrlimit(RLIMIT_STACK) failed");

        itimerval timerInterval;
        timeval tv;
        tv.tv_usec = 100000;
        tv.tv_sec = 0;
        timerInterval.it_interval = timerInterval.it_value = tv;
        if (setitimer(0, &timerInterval, 0) < 0)
            fail("cannot set interval timer");

        LEVEL_PINCLIENT::PIN_StartProgram();
        result = 0;
    }
    return result;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
