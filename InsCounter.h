//
// Created by powerofdark on 09.05.17.
//
#include "pin.H"
#include "supervisor.h"

#ifndef SJUDGE_INSCOUNT_H
#define SJUDGE_INSCOUNT_H

class InsCounter
{
public:

    static LEVEL_BASE::PIN_LOCK ThreadLock;
    static int ThreadCount;
    static const int MAX_THREADS = 1000;
    static THREAD_DATA ThreadData[MAX_THREADS];

    static void Start();

    static VOID OnThreadStart(THREADID threadIndex, CONTEXT* ctxt, int flags, VOID* v);

    static VOID InstrumentIns(TRACE trace, VOID* v);

    static VOID PIN_FAST_ANALYSIS_CALL OnBblExecuted(UINT32 c, THREADID tid);

};


#endif //SJUDGE_INSCOUNT_H
