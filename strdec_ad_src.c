// strdec_ad_src.c — anti-debug variant of the string/code decryptor core
// (strcrypt / codeenc). Same xorshift32 keystream as strdec_src.c, but it first
// reads the PEB directly (no API) and folds a debugger check into each range's
// seed. In a clean process the fold is a no-op and decryption is identical to
// the plain core; under a user-mode debugger the seed is perturbed, so every
// range decrypts to garbage and the program cannot run. Folding the check into
// the seed (instead of a branch) means NOP-ing a jump does not recover the code.
//
// Honest limit: a speed bump, not a wall — a debugger that hides the PEB, or one
// that attaches after the stub has run, still gets through; so does a memory dump
// taken after startup. Pair it with the pack pass for defense in depth.
//
// Table entry matches str_core.h exactly: {u64 va; u32 len; u32 seed} (16 bytes);
// va is the absolute VA (32-bit on x86, zero-extended into the u64).
//   void decrypt(const Range* t, uint32_t n);
//
// Build (relocation-free machine code, Windows ABI — use a MinGW gcc so the
// argument registers and non-volatile saves match the loader's expectations):
//   x86_64-w64-mingw32-gcc -O2 -c -fno-stack-protector -fno-asynchronous-unwind-tables \
//       -fcf-protection=none -fno-builtin -fomit-frame-pointer strdec_ad_src.c -o d.o
//   i686-w64-mingw32-gcc  -O2 -c ... strdec_ad_src.c -o d32.o
//   objdump -dr d.o     # verify: one `decrypt` symbol, zero relocations
//   objcopy -O binary --only-section=.text d.o d.bin   # -> embed bytes

#include <stdint.h>
typedef struct { uint64_t va; uint32_t len; uint32_t seed; } Range;  // 16 bytes

void decrypt(const Range* t, uint32_t n) {
    // ---- anti-debug: read the PEB directly (no API), fold into a mask ----
    // x64: PEB at GS:[0x60], NtGlobalFlag +0xBC;  x86: FS:[0x30], +0x68.
    // BeingDebugged is at +0x02 on both. mask = 0 when clean, all-ones if a
    // debugger is present (BeingDebugged set, or the FLG_HEAP_* bits of
    // NtGlobalFlag set).
    uintptr_t peb;
#if defined(__x86_64__)
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));
    uint32_t ntgf = *(volatile uint32_t*)(peb + 0xBC);
#else
    __asm__ volatile ("movl %%fs:0x30, %0" : "=r"(peb));
    uint32_t ntgf = *(volatile uint32_t*)(peb + 0x68);
#endif
    uint32_t being = *(volatile uint8_t*)(peb + 0x02);
    uint32_t mask  = 0u - (uint32_t)((being | (ntgf & 0x70u)) != 0u);

    for (uint32_t i = 0; i < n; ++i) {
        uint8_t* p = (uint8_t*)(uintptr_t)t[i].va;
        uint32_t st = t[i].seed ^ (mask & 0x9e3779b9u);   // perturbed iff debugged
        uint32_t len = t[i].len;
        for (uint32_t j = 0; j < len; ++j) {
            st ^= st << 13; st ^= st >> 17; st ^= st << 5;   // xorshift32
            p[j] ^= (uint8_t)st;
        }
    }
}
