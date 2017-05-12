//
// Created by powerofdark on 09.05.17.
//
#include <inscount.h>


int inscount::num_threads = 0;
PIN_LOCK inscount::thread_lock = {};
THREAD_DATA inscount::thread_data[MAX_THREADS];

void inscount::init()
{
    LEVEL_PINCLIENT::PIN_AddThreadStartFunction(inscount::thread_start, 0);
    LEVEL_PINCLIENT::TRACE_AddInstrumentFunction(inscount::instrument_inscount, 0);
}

void inscount::thread_start(THREADID threadIndex, CONTEXT* ctxt, int flags, VOID* v)
{
    LEVEL_BASE::GetLock(&inscount::thread_lock, threadIndex + 1);
    ++inscount::num_threads;
    ReleaseLock(&inscount::thread_lock);
    if (inscount::num_threads > inscount::MAX_THREADS)
    {
        fwrite("fatal: maximum number of threads exceeded", 1, 0x29, stderr);
        LEVEL_PINCLIENT::PIN_ExitProcess(0xFA);
    }

}

void inscount::docount(UINT32 c, THREADID tid)
{
    inscount::thread_data[tid]._count += c;
}

VOID inscount::instrument_inscount(TRACE trace, VOID* v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // Insert a call to docount for every bbl, passing the number of instructions.
        // IPOINT_ANYWHERE allows Pin to schedule the call anywhere in the bbl to obtain best performance.

        BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR) docount, IARG_FAST_ANALYSIS_CALL, IARG_UINT32,
                       BBL_NumIns(bbl), IARG_THREAD_ID, IARG_END);
    }
}
