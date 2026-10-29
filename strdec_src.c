// strdec_src.c — the string/code decryptor core for strcrypt/codeenc, written in
// C so it compiles relocation-free for both x64 and x86 (see str_core.h). The
// packer encrypts each range with xorshift32 (advance-then-use low byte); this
// reverses it in place. Range addresses are absolute VAs (ASLR pinned), stored
// as u64 and cast via uintptr_t so they truncate correctly on x86.
//   void decrypt(const Range* t, uint32_t n);
#include <stdint.h>
typedef struct { uint64_t va; uint32_t len; uint32_t seed; } Range;  // 16 bytes
void decrypt(const Range* t, uint32_t n) {
    for (uint32_t i = 0; i < n; ++i) {
        uint8_t* p = (uint8_t*)(uintptr_t)t[i].va;
        uint32_t st = t[i].seed, len = t[i].len;
        for (uint32_t j = 0; j < len; ++j) {
            st ^= st << 13; st ^= st >> 17; st ^= st << 5;   // xorshift32
            p[j] ^= (uint8_t)st;
        }
    }
}
