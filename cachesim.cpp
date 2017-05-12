//
// Created by powerofdark on 09.05.17.
//

#include "cachesim.h"


int cachesim::num_threads = 0;
THREAD_DATA cachesim::thread_data[MAX_THREADS];
BUFFER_ID cachesim::mem_buf_id = 0;
unsigned int cachesim::cache[65536 + 1];
LEVEL_BASE::PIN_LOCK cachesim::thread_lock;

void cachesim::init()
{
    cachesim::mem_buf_id = PIN_DefineTraceBuffer(8, 16000, cachesim::trace_buffer_full, 0);
    if (!cachesim::mem_buf_id)
    {
        fprintf(stderr, "PIN_DefineTraceBuffer failed\n");
        PIN_ExitProcess(0xFA);
    }
    PIN_AddThreadStartFunction(cachesim::thread_start, 0);
    TRACE_AddInstrumentFunction(cachesim::instrument_memory, 0);
}

VOID*
cachesim::trace_buffer_full(BUFFER_ID id, THREADID tid, const CONTEXT* ctxt, VOID* buf, UINT64 numElements, VOID* v)
{
    // we're doing 32 bit only anyway
    UINT32* it = (UINT32*) buf;
    UINT64 left = numElements;
    UINT64 penalty = 0;
    UINT32 val, valhigh;
    UINT32 cut, cuthigh;
    while (left > 0)
    {
        val = *it;
        cut = val >> 6;
        if (cut != cachesim::cache[(UINT16) cut])
        {
            cachesim::cache[(UINT16) cut] = cut;
            penalty += cachesim::CACHE_MISS_PENALTY;
        }
        valhigh = *(it + 1);
        // this shouldn't happen with 32-bit pointers
        if (valhigh > 0x40)
        {
            UINT32 middlepoint = (val + valhigh) >> 6;
            for (UINT32 i = cut + 1; middlepoint >= i; ++i)
            {
                if (i != cachesim::cache[(UINT16) i])
                {
                    cachesim::cache[(UINT16) i] = i;
                    penalty += cachesim::CACHE_MISS_PENALTY;
                }
            }
        }
        it += 2;
        --left;
    }
    cachesim::thread_data[tid]._count += penalty;
    return buf;
}


VOID cachesim::thread_start(THREADID threadIndex, CONTEXT* ctxt, int flags, VOID* v)
{
    GetLock(&cachesim::thread_lock, threadIndex + 1);
    ++cachesim::num_threads;
    ReleaseLock(&cachesim::thread_lock);
    if (cachesim::num_threads > cachesim::MAX_THREADS)
    {
        fprintf(stderr, "fatal: maximum number of threads exceeded\n");
        PIN_ExitProcess(0xFA);
    }
}

VOID cachesim::instrument_memory(TRACE trace, VOID* v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {
            if (INS_IsMemoryRead(ins))
            {
                INS_InsertFillBuffer(ins, IPOINT_BEFORE, cachesim::mem_buf_id, IARG_MEMORYREAD_EA, 0, IARG_END);
            }
            else if (INS_IsMemoryWrite(ins))
            {
                INS_InsertFillBuffer(ins, IPOINT_BEFORE, cachesim::mem_buf_id, IARG_MEMORYWRITE_EA, 0, IARG_END);
            }
        }
    }
}

