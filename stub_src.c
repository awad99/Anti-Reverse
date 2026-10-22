// stub_src.c — the packer's runtime decrypt+decompress routine, written in C so
// it can be compiled and its *relocation-free* machine code extracted and
// embedded into the stub `pack` adds to a target (see extract in pack.cpp).
//
// It must be fully self-contained: no globals, no library calls, no external
// symbols — only arithmetic on the table and key it is handed. All addresses in
// the table are absolute VAs (the packer pins ASLR), so the function just casts.
//
// Pipeline, per table entry: the blob at .src (clen bytes, inside the writable
// .pakp section) is first DECRYPTED in place with the PAKP stream cipher, then
// DECOMPRESSED (LZSS) into .dst (olen bytes, a reserved RWX section).
//
// PAKP cipher: a ChaCha-derived ARX keystream cipher. 256-bit key (shared by the
// whole file, patched into .pakp by the packer), a per-section 64-bit nonce, a
// 64-bit block counter, 20 rounds, custom constants, and a custom state layout
// (key in words 0..7, constants in 8..11) so it is not a stock ChaCha block.
// XOR keystream, so decrypt == encrypt. NOTE: the key ships inside the file, so
// this is obfuscation-grade (uniform high entropy, no recognizable compressed
// structure for a static tool) — not cryptographic secrecy against someone who
// extracts the key from the stub. Static analysis only; a dump after startup
// recovers everything. See pack.cpp's scope notes.
//
// LZSS format: a flag byte then up to 8 items. flag bit == 1 -> one literal
// byte; flag bit == 0 -> a 2-byte little-endian token m: offset = (m>>4)+1,
// length = (m&0xF)+3, copied from already-output bytes (d-off).
//
// Build to inspect / extract (no CRT, no unwind tables, no CET, no libcalls, and
// no loop->memcpy/memset synthesis):
//   gcc -O2 -c -fno-stack-protector -fno-asynchronous-unwind-tables \
//       -fcf-protection=none -fno-builtin -fomit-frame-pointer \
//       -fno-tree-loop-distribute-patterns stub_src.c -o stub.o
//   objdump -dr stub.o        # verify: exactly one symbol `unpack`, zero relocs
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
    // Custom 128-bit constant ("pakp" "stro" "ng.v" "1exe"), little-endian.
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
    for (uint32_t i = 0; i < n; ++i) {
        uint8_t* s0 = (uint8_t*)t[i].src;
        pakp_xor(s0, t[i].clen, key, t[i].nonce);   // decrypt in place

        const uint8_t* s  = s0;
        const uint8_t* se = s0 + t[i].clen;
        uint8_t*       d  = (uint8_t*)t[i].dst;
        while (s < se) {
            uint8_t fl = *s++;
            for (int b = 0; b < 8 && s < se; ++b) {
                if (fl & 1) {
                    *d++ = *s++;
                } else {
                    uint32_t m   = (uint32_t)s[0] | ((uint32_t)s[1] << 8);
                    s += 2;
                    uint32_t off = (m >> 4) + 1;
                    uint32_t len = (m & 0xF) + 3;
                    const uint8_t* c = d - off;
                    while (len--) *d++ = *c++;
                }
                fl >>= 1;
            }
        }
    }
}
