#ifndef STR_CORE_H
#define STR_CORE_H
// str_core.h — shared decryptor core for the string (strcrypt) and code
// (codeenc) passes, for both x64 and x86. Encryption is xorshift32 keystream
// (advance-then-use low byte) XORed over each range; `decrypt` reverses it. The
// range table is 16 bytes/entry: {u64 va; u32 len; u32 seed} (va is the absolute
// VA, 32-bit on x86, zero-extended into the u64). Built from strdec_src.c with
// `gcc [-m32] -c ...`; reuses pak_core.h's stub-framing helpers.
//   void decrypt(const Range* t, uint32_t n);
#include "pak_core.h"

// x86-64 decrypt core (relocation-free; see strdec_src.c).
static const unsigned char kDec[] = {
    0x85,0xd2,0x74,0x6d,0x89,0xd2,0x48,0xc1,0xe2,0x04,0x4c,0x8d,
    0x14,0x11,0x66,0x90,0x44,0x8b,0x49,0x08,0x45,0x85,0xc9,0x74,
    0x4f,0x48,0x8b,0x11,0x8b,0x41,0x0c,0x49,0x01,0xd1,0x0f,0x1f,
    0x84,0x00,0x00,0x00,0x00,0x00,0x66,0x66,0x2e,0x0f,0x1f,0x84,
    0x00,0x00,0x00,0x00,0x00,0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,
    0x00,0x00,0x00,0x00,0x41,0x89,0xc0,0x41,0xc1,0xe0,0x0d,0x44,
    0x31,0xc0,0x41,0x89,0xc0,0x41,0xc1,0xe8,0x11,0x41,0x31,0xc0,
    0x44,0x89,0xc0,0xc1,0xe0,0x05,0x44,0x31,0xc0,0x30,0x02,0x48,
    0x83,0xc2,0x01,0x49,0x39,0xd1,0x75,0xd8,0x48,0x83,0xc1,0x10,
    0x49,0x39,0xca,0x75,0x9f,0xc3,
};
static const size_t kDecLen = sizeof(kDec);

// x86 (i386) decrypt core.
static const unsigned char kDec32[] = {
    0x83,0xec,0x0c,0x89,0x7c,0x24,0x08,0x8b,0x7c,0x24,0x14,0x85,
    0xff,0x74,0x5d,0x89,0x74,0x24,0x04,0x8b,0x74,0x24,0x10,0xc1,
    0xe7,0x04,0x89,0x1c,0x24,0x01,0xf7,0x90,0x8b,0x5e,0x08,0x85,
    0xdb,0x74,0x37,0x8b,0x16,0x8b,0x46,0x0c,0x01,0xd3,0x66,0x90,
    0x2e,0x8d,0xb4,0x26,0x00,0x00,0x00,0x00,0x2e,0x8d,0xb4,0x26,
    0x00,0x00,0x00,0x00,0x89,0xc1,0xc1,0xe1,0x0d,0x31,0xc8,0x89,
    0xc1,0xc1,0xe9,0x11,0x31,0xc1,0x89,0xc8,0xc1,0xe0,0x05,0x31,
    0xc8,0x30,0x02,0x83,0xc2,0x01,0x39,0xd3,0x75,0xe2,0x83,0xc6,
    0x10,0x39,0xf7,0x75,0xbb,0x8b,0x1c,0x24,0x8b,0x74,0x24,0x04,
    0x8b,0x7c,0x24,0x08,0x83,0xc4,0x0c,0xc3,
};
static const size_t kDec32Len = sizeof(kDec32);

// ---- x64 framings: decrypt(table, count) with rcx=table, edx=count ---------
static std::vector<uint8_t> MakeStrEntryStub(size_t& offTable, size_t& offCount, size_t& offOep) {
    std::vector<uint8_t> s;
    s.insert(s.end(), {0x48,0xb9});            offTable = pakpStubHole(s, 8);  // movabs rcx, TABLE
    s.insert(s.end(), {0xba});                 offCount = pakpStubHole(s, 4);  // mov    edx, COUNT
    s.insert(s.end(), {0x48,0x83,0xec,0x28});                                  // sub    rsp, 0x28
    s.insert(s.end(), {0xe8});    size_t disp = pakpStubHole(s, 4);            // call   decrypt
    s.insert(s.end(), {0x48,0x83,0xc4,0x28});                                  // add    rsp, 0x28
    s.insert(s.end(), {0x48,0xb8});            offOep   = pakpStubHole(s, 8);  // movabs rax, OEP
    s.insert(s.end(), {0xff,0xe0});                                            // jmp    rax
    pakpPatchCall(s, disp);
    s.insert(s.end(), kDec, kDec + kDecLen);
    return s;
}
static std::vector<uint8_t> MakeStrTlsStub(size_t& offTable, size_t& offCount) {
    std::vector<uint8_t> s;
    s.insert(s.end(), {0x83,0xfa,0x01});                                       // cmp edx, 1 (ATTACH)
    s.insert(s.end(), {0x74,0x01});                                            // je  +1 (skip ret)
    s.insert(s.end(), {0xc3});                                                 // ret (other reasons)
    s.insert(s.end(), {0x48,0xb9});            offTable = pakpStubHole(s, 8);  // movabs rcx, TABLE
    s.insert(s.end(), {0xba});                 offCount = pakpStubHole(s, 4);  // mov    edx, COUNT
    s.insert(s.end(), {0x48,0x83,0xec,0x28});                                  // sub    rsp, 0x28
    s.insert(s.end(), {0xe8});    size_t disp = pakpStubHole(s, 4);            // call   decrypt
    s.insert(s.end(), {0x48,0x83,0xc4,0x28});                                  // add    rsp, 0x28
    s.insert(s.end(), {0xc3});                                                 // ret
    pakpPatchCall(s, disp);
    s.insert(s.end(), kDec, kDec + kDecLen);
    return s;
}

// ---- x86 framings: cdecl decrypt(table, count) -> push count, push table ---
static std::vector<uint8_t> MakeStrEntryStub32(size_t& offTable, size_t& offCount, size_t& offOep) {
    std::vector<uint8_t> s;
    s.insert(s.end(), {0x68});    offCount = pakpStubHole(s, 4);               // push COUNT
    s.insert(s.end(), {0x68});    offTable = pakpStubHole(s, 4);               // push TABLE
    s.insert(s.end(), {0xe8});    size_t disp = pakpStubHole(s, 4);            // call decrypt
    s.insert(s.end(), {0x83,0xc4,0x08});                                       // add esp, 8
    s.insert(s.end(), {0xb8});    offOep   = pakpStubHole(s, 4);               // mov eax, OEP
    s.insert(s.end(), {0xff,0xe0});                                            // jmp eax
    pakpPatchCall(s, disp);
    s.insert(s.end(), kDec32, kDec32 + kDec32Len);
    return s;
}
static std::vector<uint8_t> MakeStrTlsStub32(size_t& offTable, size_t& offCount) {
    std::vector<uint8_t> s;
    s.insert(s.end(), {0x83,0x7c,0x24,0x08,0x01});                             // cmp dword [esp+8], 1
    s.insert(s.end(), {0x75}); size_t jnePos = s.size(); s.insert(s.end(), 1, 0); // jne skip (rel8)
    s.insert(s.end(), {0x68});    offCount = pakpStubHole(s, 4);               // push COUNT
    s.insert(s.end(), {0x68});    offTable = pakpStubHole(s, 4);               // push TABLE
    s.insert(s.end(), {0xe8});    size_t disp = pakpStubHole(s, 4);            // call decrypt
    s.insert(s.end(), {0x83,0xc4,0x08});                                       // add esp, 8
    size_t skip = s.size();
    s[jnePos] = (uint8_t)(skip - (jnePos + 1));                                // jne -> the ret
    s.insert(s.end(), {0xc2,0x0c,0x00});                                       // ret 12 (stdcall)
    pakpPatchCall(s, disp);
    s.insert(s.end(), kDec32, kDec32 + kDec32Len);
    return s;
}

#endif // STR_CORE_H
