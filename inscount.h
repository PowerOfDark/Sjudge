//
// Created by powerofdark on 09.05.17.
//
#include "pin.H"
#include "supervisor.h"
#ifndef SJUDGE_INSCOUNT_H
#define SJUDGE_INSCOUNT_H

class inscount
{
public:

    static LEVEL_BASE::PIN_LOCK thread_lock;
    static int num_threads;
    static const int MAX_THREADS = 1000;
    static THREAD_DATA thread_data[MAX_THREADS];
    static void init();
    static VOID thread_start(THREADID threadIndex, CONTEXT *ctxt, int flags, VOID *v);
    static VOID instrument_inscount(TRACE trace, VOID *v);
    static VOID PIN_FAST_ANALYSIS_CALL docount(UINT32 c, THREADID tid);

    inscount();
};


#endif //SJUDGE_INSCOUNT_H
