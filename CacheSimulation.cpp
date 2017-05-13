//
// Created by powerofdark on 09.05.17.
//

#include "CacheSimulation.h"


int CacheSimulation::ThreadCount = 0;
THREAD_DATA CacheSimulation::ThreadData[MAX_THREADS];
BUFFER_ID CacheSimulation::MemoryBufferId = 0;
unsigned int CacheSimulation::Cache[65536 + 1];
LEVEL_BASE::PIN_LOCK CacheSimulation::ThreadLock;

void CacheSimulation::Start()
{
    CacheSimulation::MemoryBufferId = PIN_DefineTraceBuffer(8, 16000, CacheSimulation::TRACE_OnBufferFull, 0);
    if (!CacheSimulation::MemoryBufferId)
    {
        fprintf(stderr, "PIN_DefineTraceBuffer failed\n");
        PIN_ExitProcess(0xFA);
    }
    PIN_AddThreadStartFunction(CacheSimulation::OnThreadStart, 0);
    TRACE_AddInstrumentFunction(CacheSimulation::InstrumentMemory, 0);
}

VOID*
CacheSimulation::TRACE_OnBufferFull(BUFFER_ID id, THREADID tid, const CONTEXT* ctxt, VOID* buf, UINT64 numElements,
                                    VOID* v)
{
    // we're doing 32 bit only anyway
    UINT32* it = (UINT32*) buf;
    UINT64 left = numElements;
    UINT64 penalty = 0;
    UINT32 val, valHigh;
    UINT32 cut, cutHigh;
    while (left > 0)
    {
        val = *it;
        cut = val >> 6;
        if (cut != CacheSimulation::Cache[(UINT16) cut])
        {
            CacheSimulation::Cache[(UINT16) cut] = cut;
            penalty += CacheSimulation::CACHE_MISS_PENALTY;
        }
        valHigh = *(it + 1);
        // this shouldn't happen with 32-bit pointers
        if (valHigh > 0x40)
        {
            UINT32 middlepoint = (val + valHigh) >> 6;
            for (UINT32 i = cut + 1; middlepoint >= i; ++i)
            {
                if (i != CacheSimulation::Cache[(UINT16) i])
                {
                    CacheSimulation::Cache[(UINT16) i] = i;
                    penalty += CacheSimulation::CACHE_MISS_PENALTY;
                }
            }
        }
        it += 2;
        --left;
    }
    CacheSimulation::ThreadData[tid]._count += penalty;
    return buf;
}


VOID CacheSimulation::OnThreadStart(THREADID threadIndex, CONTEXT* ctxt, int flags, VOID* v)
{
    GetLock(&CacheSimulation::ThreadLock, threadIndex + 1);
    ++CacheSimulation::ThreadCount;
    ReleaseLock(&CacheSimulation::ThreadLock);
    if (CacheSimulation::ThreadCount > CacheSimulation::MAX_THREADS)
    {
        fprintf(stderr, "fatal: maximum number of threads exceeded\n");
        PIN_ExitProcess(0xFA);
    }
}

VOID CacheSimulation::InstrumentMemory(TRACE trace, VOID* v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {
            if (INS_IsMemoryRead(ins))
            {
                INS_InsertFillBuffer(ins, IPOINT_BEFORE, CacheSimulation::MemoryBufferId, IARG_MEMORYREAD_EA, 0,
                                     IARG_END);
            }
            else if (INS_IsMemoryWrite(ins))
            {
                INS_InsertFillBuffer(ins, IPOINT_BEFORE, CacheSimulation::MemoryBufferId, IARG_MEMORYWRITE_EA, 0,
                                     IARG_END);
            }
        }
    }
}

