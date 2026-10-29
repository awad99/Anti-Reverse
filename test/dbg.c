#include <windows.h>
#include <stdio.h>
// Minimal debugger: launch argv[1] under a debug port (sets PEB->BeingDebugged
// in the child), pump debug events, report the child's exit code.
int main(int argc, char** argv){
    STARTUPINFOA si={sizeof si}; PROCESS_INFORMATION pi;
    if(!CreateProcessA(argv[1],NULL,NULL,NULL,FALSE,DEBUG_ONLY_THIS_PROCESS,NULL,NULL,&si,&pi)){
        printf("CreateProcess failed %lu\n",(unsigned long)GetLastError()); return 1; }
    DEBUG_EVENT de; DWORD code=0xDEAD;
    for(;;){
        if(!WaitForDebugEvent(&de,15000)){ printf("(no more debug events)\n"); break; }
        if(de.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){ code=de.u.ExitProcess.dwExitCode;
            ContinueDebugEvent(de.dwProcessId,de.dwThreadId,DBG_CONTINUE); break; }
        ContinueDebugEvent(de.dwProcessId,de.dwThreadId,
            de.dwDebugEventCode==EXCEPTION_DEBUG_EVENT?DBG_EXCEPTION_NOT_HANDLED:DBG_CONTINUE);
    }
    printf("[debugger] child exit code = 0x%lX\n",(unsigned long)code);
    return 0;
}
