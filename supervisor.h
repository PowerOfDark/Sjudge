#ifndef _SUPERVISOR_SUPERVISOR_H
#define _SUPERVISOR_SUPERVISOR_H

#include <stdio.h>

#define SC_ALLOWED        1
#define SC_MEMORY         2 /* changes amount of used memory */
#define SC_SKIP           4
#define SC_EXTENSION      8 /* esyscalls */
#define SC_NOEXTENSION   16 /* disable when estensions forced */

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
extern const char* allowed_open_dirs[];

#define PADSIZE 56  // 64byte linesize : 64 - 8
struct THREAD_DATA
{
    UINT64 _count;
    UINT8 _pad[PADSIZE];
};

#endif
