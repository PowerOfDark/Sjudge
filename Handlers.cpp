//
// Created by powerofdark on 13.05.17.
//
#include <climits>
#include <fcntl.h>
#include <cstring>
#include <cstdlib>
#include "Handlers.h"
#include "supervisor.h"

#pragma region Entry

int Handlers::OnSyscallEntry(unsigned int syscallNum, int a2, CONTEXT* ctxt, SYSCALL_STANDARD std)
{
    struct
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
    } getArg;
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
            return Handlers::OnSysKillEntry(pid, sig);

        }
        case _sys_write:
        {
            UINT32 fd = getArg(0);
            UINT32 count = getArg(2);
            return Handlers::OnSysWriteEntry(fd, count);
        }
        case _sys_open:
        {
            const char* path = (const char*) getArg[0];
            UINT32 flags = getArg(1);
            return Handlers::OnSysOpenEntry(path, flags);
        }
        case _sys_read:
            return 1;
        default:
        {
            fprintf(stderr, "unknown syscall entry handler(%x)", syscallNum);
            Fail("unhandled syscall");
            return 0;
        }
    }
}


int Handlers::OnSysKillEntry(UINT32 pid, UINT32 sig)
{
    if (pid != getpid())
    {
        Forbidden("tried to kill some process");
        return 0;
    }

    if (sig == SIGSTOP || sig == SIGTRAP || sig == SIGVTALRM)
    {
        Forbidden("used Forbidden signal");
        return 0;
    }
    return 1;
}

int Handlers::OnSysOpenEntry(const char* path, UINT32 flags)
{
    if (!Silent) fprintf(stderr, "open %05x %s\n", flags, path);
    if (path[0] != '/')
    {
        Forbidden("opening files is forbidden");
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
    const char** allowedDirsIter;
    for (allowedDirsIter = ALLOWED_OPEN_DIRECTORIES; *allowedDirsIter; allowedDirsIter++)
        if (!strncmp(cpath, *allowedDirsIter, strlen(*allowedDirsIter)))
            return 1;
    return 0;
}

int Handlers::OnSysWriteEntry(UINT32 fd, UINT32 count)
{
    if (fd > 2)
    {
        Forbidden("writing to something other than stdout and stderr");
        return 0;
    }

    if (count > (UINT32) OutputLimit)
    {
        ReportResult(RETVAL_OLE, "output limit exceeded");
        return 0;
    }
    return 1;
}


#pragma endregion Entry

void Handlers::OnSyscallExit(unsigned int syscallNum, THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std)
{
    UINT32 ret = (UINT32) (UINT64) Addrint2VoidStar(PIN_GetSyscallReturn(ctxt, std));
    switch (syscallNum)
    {
        case _sys_readv:
        case _sys_read:
            Handlers::OnSysReadExit(ret);
            return;
        case _sys_writev:
        case _sys_write:
            Handlers::OnSysWriteExit(ret);
            return;
        case _sys_kill:
        case _sys_tkill:
        case _sys_tgkill:
        case _sys_open:
            return;
        default:
        {
            fprintf(stderr, "unknown syscall exit handler(%x)", syscallNum);
            Fail("unhandled syscall");
            return;
        }

    }
}

void Handlers::OnSysWriteExit(UINT32 ret)
{
    if (ret >= 0)
    {
        OutputLimit -= ret;
    }
}

void Handlers::OnSysReadExit(UINT32 ret)
{
    if (ret <= 0)
    {
        if (++FailedReadCount >= 100000)
        {
            ReportResult(100, "reading past the end of input");
        }
    }
}