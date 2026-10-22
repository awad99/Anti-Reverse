// stub_src.c — the packer's runtime anti-debug + decrypt + decompress routine,
// written in C so it can be compiled and its *relocation-free* machine code
// extracted and embedded into the stub `pack` adds to a target (see pack.cpp).
//
// It must be fully self-contained: no globals, no library calls, no external
// symbols — only arithmetic on the table and key it is handed, plus one GS-
// relative read of the PEB. All table addresses are absolute VAs (the packer
// pins ASLR), so the function just casts.
//
// Pipeline: (1) ANTI-DEBUG — read the PEB directly (no API) and fold the result
// into the key; (2) per entry, DECRYPT the blob at .src in place with the PAKP
// cipher; (3) DECOMPRESS (LZSS) into .dst (bounded by olen).
//
// Anti-debug: in a clean process PEB->BeingDebugged and the FLG_HEAP_* bits of
// PEB->NtGlobalFlag are 0, so the key is used unchanged. Under a user-mode
// debugger one or both are set, the key is perturbed, and every section decrypts
// to garbage so the program cannot run. Folding the check into the key means
// NOP-ing a branch does not recover the code. Honest limit: a speed bump, not a
// wall — a debugger that hides the PEB, or that attaches after the stub has run,
// still gets through; so does a memory dump taken after startup.
//
// PAKP cipher: a ChaCha-derived ARX keystream cipher. 256-bit key (patched into
// .pakp by the packer), per-section 64-bit nonce, 64-bit block counter, 20
// rounds, custom constants, custom state layout (key in words 0..7). XOR
// keystream, so decrypt == encrypt. The key ships in the file, so this is
// obfuscation-grade (uniform high entropy, no recognizable compressed structure
// for a static tool) — not secrecy against someone who extracts the key.
//
// LZSS format: a flag byte then up to 8 items. flag bit == 1 -> one literal
// byte; flag bit == 0 -> a 2-byte little-endian token m: offset = (m>>4)+1,
// length = (m&0xF)+3, copied from already-output bytes (d-off).
//
// Build to inspect / extract (no CRT, no unwind tables, no CET, no libcalls, no
// loop->memcpy/memset synthesis, no SLP so cipher constants stay immediates):
//   gcc -O2 -c -fno-stack-protector -fno-asynchronous-unwind-tables \
//       -fcf-protection=none -fno-builtin -fomit-frame-pointer \
//       -fno-tree-loop-distribute-patterns -fno-tree-vectorize \
//       -fno-tree-slp-vectorize stub_src.c -o stub.o
//   objdump -dr stub.o        # verify: one symbol `unpack`, zero relocations
//   objcopy -O binary --only-section=.text stub.o stub.bin   # -> embed bytes

#include <stdint.h>

typedef struct { uint64_t dst; uint64_t src; uint32_t clen; uint32_t olen; uint64_t nonce; } Ent;

static inline uint32_t rotl32(uint32_t v, int c) { return (v << c) | (v >> (32 - c)); }

// One PAKP quarter-round (same ARX mixing primitive as ChaCha).
#define QR(a, b, c, d) \
    a += b; d ^= a; d = rotl32(d, 16); \
    c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d, 8);  \
    c += d; b ^= c; b = rotl32(b, 7)

// Decrypt `len` bytes at `buf` in place with the PAKP cipher (XOR keystream).
static inline void pakp_xor(uint8_t* buf, uint32_t len,
                            const uint32_t* key, uint64_t nonce) {
    uint32_t st[16];
    st[0] = key[0]; st[1] = key[1]; st[2] = key[2]; st[3] = key[3];
    st[4] = key[4]; st[5] = key[5]; st[6] = key[6]; st[7] = key[7];
    st[8]  = 0x706b6170u;   // "pakp"
    st[9]  = 0x6f727473u;   // "stro"
    st[10] = 0x762e676eu;   // "ng.v"
    st[11] = 0x65786531u;   // "1exe"
    st[12] = 0;                                  // counter low
    st[13] = 0;                                  // counter high
    st[14] = (uint32_t)nonce;                    // nonce low
    st[15] = (uint32_t)(nonce >> 32);            // nonce high

    uint32_t pos = 0;
    while (pos < len) {
        uint32_t x[16];
        for (int i = 0; i < 16; ++i) x[i] = st[i];
        for (int r = 0; r < 10; ++r) {           // 10 double rounds = 20 rounds
            QR(x[0], x[4], x[8],  x[12]);
            QR(x[1], x[5], x[9],  x[13]);
            QR(x[2], x[6], x[10], x[14]);
            QR(x[3], x[7], x[11], x[15]);
            QR(x[0], x[5], x[10], x[15]);
            QR(x[1], x[6], x[11], x[12]);
            QR(x[2], x[7], x[8],  x[13]);
            QR(x[3], x[4], x[9],  x[14]);
        }
        for (int i = 0; i < 16; ++i) x[i] += st[i];

        const uint8_t* ks = (const uint8_t*)x;   // little-endian serialization
        for (int j = 0; j < 64 && pos < len; ++j) buf[pos++] ^= ks[j];

        if (++st[12] == 0) ++st[13];             // 64-bit block counter
    }
}

void unpack(const Ent* t, uint32_t n, const uint32_t* key) {
    // ---- anti-debug: read the PEB directly (no API), fold into the key -----
    uint64_t peb;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));
    uint32_t being = *(volatile uint8_t*)(peb + 0x02);   // PEB->BeingDebugged
    uint32_t ntgf  = *(volatile uint32_t*)(peb + 0xBC);  // PEB->NtGlobalFlag
    // mask = 0 when clean, 0xFFFFFFFF when a debugger is present.
    uint32_t mask = 0u - (uint32_t)((being | (ntgf & 0x70u)) != 0u);
    uint32_t k[8];
    for (int i = 0; i < 8; ++i)
        k[i] = key[i] ^ (mask & (0x9e3779b9u + (uint32_t)i * 0x61c88647u));

    for (uint32_t i = 0; i < n; ++i) {
        uint8_t* s0 = (uint8_t*)t[i].src;
        pakp_xor(s0, t[i].clen, k, t[i].nonce);   // decrypt in place (perturbed if debugged)

        const uint8_t* s  = s0;
        const uint8_t* se = s0 + t[i].clen;
        uint8_t*       d  = (uint8_t*)t[i].dst;
        uint8_t*       de = d + t[i].olen;        // output bound (hardening)
        while (s < se && d < de) {
            uint8_t fl = *s++;
            for (int b = 0; b < 8 && s < se && d < de; ++b) {
                if (fl & 1) {
                    *d++ = *s++;
                } else {
                    uint32_t m   = (uint32_t)s[0] | ((uint32_t)s[1] << 8);
                    s += 2;
                    uint32_t off = (m >> 4) + 1;
                    uint32_t len = (m & 0xF) + 3;
                    const uint8_t* c = d - off;
                    while (len-- && d < de) *d++ = *c++;
                }
                fl >>= 1;
            }
        }
    }
}
