//
// Created by powerofdark on 09.05.17.
//
#include "pin.H"
#include "supervisor.h"
#ifndef SJUDGE_CACHESIM_H
#define SJUDGE_CACHESIM_H

class cachesim
{
public:

    static const int CACHE_MISS_PENALTY = 16LL;
    static LEVEL_BASE::PIN_LOCK thread_lock;
    static int num_threads;
    static BUFFER_ID mem_buf_id;
    static const int MAX_THREADS = 1000;
    static THREAD_DATA thread_data[MAX_THREADS];
    static unsigned int cache[65536 + 1];
    static void init();
    static VOID* trace_buffer_full(BUFFER_ID id, THREADID tid, const CONTEXT* ctxt, VOID* buf, UINT64 numElements, VOID* v);
    static VOID thread_start(THREADID threadIndex, CONTEXT* ctxt, int flags, VOID*  v);
    static VOID instrument_memory(TRACE trace, VOID* v);
    //static VOID PIN_FAST_ANALYSIS_CALL docount(UINT32 c, THREADID tid);

};
#endif //SJUDGE_CACHESIM_H
