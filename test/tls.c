#include <windows.h>
#include <stdio.h>
/* A test program that owns a TLS callback, to exercise the packer's TLS-hook
   path (codeenc/pack prepend their stub ahead of this callback). */
static void NTAPI my_tls(PVOID h, DWORD reason, PVOID r) {
    (void)h; (void)r;
    if (reason == DLL_PROCESS_ATTACH) fputs("TLS_RAN\n", stdout);
}
PIMAGE_TLS_CALLBACK _ptls __attribute__((section(".CRT$XLB"), used)) = my_tls;
__thread int _force_tls = 11;
int main(void) { printf("HELLO_TLS_%d\n", _force_tls); return 3; }
