//
// Created by powerofdark on 09.05.17.
//
#include <InsCounter.h>


int InsCounter::ThreadCount = 0;
PIN_LOCK InsCounter::ThreadLock = {};
THREAD_DATA InsCounter::ThreadData[MAX_THREADS];

void InsCounter::Start()
{
    LEVEL_PINCLIENT::PIN_AddThreadStartFunction(InsCounter::OnThreadStart, 0);
    LEVEL_PINCLIENT::TRACE_AddInstrumentFunction(InsCounter::InstrumentIns, 0);
}

void InsCounter::OnThreadStart(THREADID threadIndex, CONTEXT* ctxt, int flags, VOID* v)
{
    LEVEL_BASE::GetLock(&InsCounter::ThreadLock, threadIndex + 1);
    ++InsCounter::ThreadCount;
    ReleaseLock(&InsCounter::ThreadLock);
    if (InsCounter::ThreadCount > InsCounter::MAX_THREADS)
    {
        fprintf(stderr, "fatal: maximum number of threads exceeded\n");
        LEVEL_PINCLIENT::PIN_ExitProcess(0xFA);
    }

}

void InsCounter::OnBblExecuted(UINT32 c, THREADID tid)
{
    InsCounter::ThreadData[tid]._count += c;
}

VOID InsCounter::InstrumentIns(TRACE trace, VOID* v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // Insert a call to OnBblExecuted for every bbl, passing the number of instructions.
        // IPOINT_ANYWHERE allows Pin to schedule the call anywhere in the bbl to obtain best performance.

        BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR) OnBblExecuted, IARG_FAST_ANALYSIS_CALL, IARG_UINT32,
                       BBL_NumIns(bbl), IARG_THREAD_ID, IARG_END);
    }
}
