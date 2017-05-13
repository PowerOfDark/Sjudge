//
// Created by powerofdark on 09.05.17.
//
#include "pin.H"
#include "supervisor.h"

#ifndef SJUDGE_CACHESIM_H
#define SJUDGE_CACHESIM_H

class CacheSimulation
{
public:

    static const int CACHE_MISS_PENALTY = 16LL;
    static LEVEL_BASE::PIN_LOCK ThreadLock;
    static int ThreadCount;
    static BUFFER_ID MemoryBufferId;
    static const int MAX_THREADS = 1000;
    static THREAD_DATA ThreadData[MAX_THREADS];
    static unsigned int Cache[65536 + 1];

    static void Start();

    static VOID*
    TRACE_OnBufferFull(BUFFER_ID id, THREADID tid, const CONTEXT* ctxt, VOID* buf, UINT64 numElements, VOID* v);

    static VOID OnThreadStart(THREADID threadIndex, CONTEXT* ctxt, int flags, VOID* v);

    static VOID InstrumentMemory(TRACE trace, VOID* v);
    //static VOID PIN_FAST_ANALYSIS_CALL OnBblExecuted(UINT32 c, THREADID tid);

};

#endif //SJUDGE_CACHESIM_H
