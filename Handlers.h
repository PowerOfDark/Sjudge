//
// Created by powerofdark on 13.05.17.
//

#ifndef SJUDGE_HANDLERS_H
#define SJUDGE_HANDLERS_H

#include <unistd.h>
#include <bits/signum.h>
#include "signal.h"
#include "pin.H"

#ifndef SJUDGE_SJUDGE_H

extern void Fail(const char* msg);

extern void Forbidden(const char* msg);

extern void ReportResult(int code, const char* msg);

extern long long OutputLimit;
extern int FailedReadCount;
extern bool Silent;
#endif

namespace Handlers
{
    int OnSyscallEntry(unsigned int syscallNum, int a2, CONTEXT* ctxt, SYSCALL_STANDARD std);

    int OnSysKillEntry(UINT32 pid, UINT32 sig);

    int OnSysOpenEntry(const char* path, UINT32 flags);

    int OnSysWriteEntry(UINT32 fd, UINT32 count);

    void OnSysReadExit(UINT32 ret);

    void OnSysWriteExit(UINT32 ret);

    void OnSyscallExit(unsigned int syscallNum, THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std);

};


#endif //SJUDGE_HANDLERS_H
