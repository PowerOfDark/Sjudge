#ifndef _SUPERVISOR_SUPERVISOR_H
#define _SUPERVISOR_SUPERVISOR_H

#include <stdio.h>

#define SC_ALLOWED      0x1
#define SC_MEMORY       0x2 /* changes amount of used memory */
#define SC_SKIP         0x4
#define SC_EXTENSION    0x8 /* esyscalls */
#define SC_NOEXTENSION  0x10 /* disable when estensions forced */
#define SC_TRAP         0x20

#define SS_OUT       0
#define SS_IN        1
#define SS_SKIPPING  2
#define SS_EMULATING 3
#define SS_CHANGED   4

#define RETVAL_OK            0
#define RETVAL_TLE        125
#define RETVAL_MLE        124
#define RETVAL_SIG_BASE     0
#define RETVAL_RE_BASE    200
#define RETVAL_RE         100
#define RETVAL_RV         121
#define RETVAL_OLE        120

#define MAX_SYSNR  2048

#define IOSHM_SIZE  65536
#define IOSHM_ISIZE 32768

//#define dbgprintf fprintf
#define dbgprintf(...) do { } while(0)

/* scnames.c */
//const char* syscall_name(int sysnr);

/* policy.c */
extern short syscall_flags[MAX_SYSNR];
extern short syscall_flags_java[MAX_SYSNR];
extern short syscall_flags_java_inited[MAX_SYSNR];
extern const char* ALLOWED_OPEN_DIRECTORIES[];

#define PADSIZE 56  // 64byte linesize : 64 - 8
struct THREAD_DATA
{
    UINT64 _count;
    UINT8 _pad[PADSIZE];
};

extern "C" short GetSyscallFlags(int id);
extern "C" const char* GetSyscallName(int);

#define _sys_kill 0x25
#define _sys_tkill 0xEE
#define _sys_tgkill 0x10E
#define _sys_read 0x03
#define _sys_write 0x04
#define _sys_open 0x05
#define _sys_readv 0x91
#define _sys_writev 0x92


#endif
