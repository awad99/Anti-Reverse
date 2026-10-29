// codeenc — x64 PE code-section encryptor (part of the Anti-Reverse toolset).
//
// Encrypts the bytes of the target's code section (.text) in place and appends a
// decryptor stub (a new ".pakc" section) that runs before the original code,
// XOR-decrypts the section back in memory, then lets execution continue. On disk
// the code section is ciphertext, so IDA / objdump static disassembly shows
// garbage (`db 4Ah, 8Bh, ...`) where the clean function bodies used to be.
//
//   Usage:  codeenc <input.exe> <output.exe>
//
// Two ways the stub gets to run first, chosen automatically:
//   * If the target has TLS callbacks (most MinGW/MSVC exes do), we prepend our
//     decryptor to the TLS callback array. TLS callbacks run before the entry
//     point, and ours runs before the rest, so by the time any real code runs the
//     section is already plaintext. The TLS stub runs only on DLL_PROCESS_ATTACH
//     and the shared decryptor touches only volatile registers, so the registers
//     the loader expects across the callback are preserved.
//   * Otherwise we repoint AddressOfEntryPoint at the stub, which ends with a
//     `jmp` to the original entry.
//
// The code section is marked writable (IMAGE_SCN_MEM_WRITE) so the loader maps it
// RWX and the stub can decrypt in place with a plain XOR loop — no API calls from
// the stub. ASLR is pinned (DYNAMIC_BASE cleared) so fixed VAs resolve. It also
// composes with strcrypt: each pass leaves the other's stub alone (.pak vs .pakc).
//
// Scope / limits (honest):
//   * x64 native PE only (PE32+, AMD64). Refuses 32-bit, DLLs, .NET and files it
//     has already code-encrypted.
//   * Defeats STATIC analysis only. A debugger, or a memory dump taken after the
//     stub runs, recovers the original code — full decompiler-proofing needs code
//     virtualization, which this does not do. Protect software you own, and
//     always test the output.
//
// The PE plumbing (parse/validate, RVA mapping, exclusion list) is shared with
// strcrypt/pack via pe_core.h; the decryptor machine code and stub framings are
// shared with the GUI via str_core.h. The keystream is xorshift32 (advance-then-
// use low byte); the per-range seed now comes from a CSPRNG, so the ciphertext is
// polymorphic and the seeds are not recoverable from the (plaintext) PE header.
//
// Build (MSYS2 UCRT64):
//   g++ -O2 -std=c++17 -o codeenc.exe codeenc.cpp

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <random>
#include "pe_core.h"
#define STR_ANTIDEBUG     // select the anti-debug decryptor core from str_core.h
#include "str_core.h"      // MakeStrEntryStub / MakeStrTlsStub + the shared decryptor

static inline uint32_t xorshift32(uint32_t x) {
    x ^= x << 13; x ^= x >> 17; x ^= x << 5; return x;
}

struct Range { uint32_t rva; uint32_t len; uint32_t seed; uint32_t fileOff; };

static void fail(const char* msg) { std::fprintf(stderr, "codeenc: %s\n", msg); std::exit(1); }

int main(int argc, char** argv) {
    if (argc != 3) { std::fprintf(stderr, "usage: codeenc <input.exe> <output.exe>\n"); return 2; }

    // ---- load -----------------------------------------------------------
    FILE* f = std::fopen(argv[1], "rb");
    if (!f) fail("cannot open input");
    std::fseek(f, 0, SEEK_END); long sz = std::ftell(f); std::fseek(f, 0, SEEK_SET);
    if (sz <= 0) fail("empty input");
    std::vector<uint8_t> img(static_cast<size_t>(sz));
    if (std::fread(img.data(), 1, img.size(), f) != img.size()) fail("read error");
    std::fclose(f);

    // ---- parse + validate (x64 only); refuse already-encrypted files ----
    pe::View<true> v(img);
    { std::string e = pe::open<true>(v, ".pakc"); if (!e.empty()) fail(e.c_str()); }
    IMAGE_OPTIONAL_HEADER64& opt = *v.opt;
    using TLS = pe::Traits<true>::TLS;

    // ---- gather TLS callbacks (we hook ahead of them, not refuse) -------
    std::vector<uint64_t> tlsCallbacks;
    uint32_t tlsDirFileOff = 0;        // file offset of IMAGE_TLS_DIRECTORY64, 0 if none
    {
        auto& tlsDir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tlsDir.VirtualAddress && tlsDir.Size) {
            uint32_t o = v.rvaToOff(tlsDir.VirtualAddress);
            if (o && v.in(o, sizeof(TLS))) {
                auto tls = reinterpret_cast<TLS*>(v.at(o));
                if (tls->AddressOfCallBacks >= v.imageBase) {
                    uint32_t arrOff = v.rvaToOff((uint32_t)(tls->AddressOfCallBacks - v.imageBase));
                    for (uint32_t k = 0; arrOff && v.in(arrOff + k * 8, 8) && k < 4096; ++k) {
                        uint64_t cb; std::memcpy(&cb, v.at(arrOff + k * 8), 8);
                        if (!cb) break;
                        tlsCallbacks.push_back(cb);
                    }
                    if (!tlsCallbacks.empty()) tlsDirFileOff = o;
                }
            }
        }
    }
    const bool hookTls = tlsDirFileOff != 0;

    // ---- the bytes the loader needs intact ------------------------------
    std::vector<pe::Span> ex;
    pe::buildExclusions<true>(v, ex);

    // ---- pick the code section -----------------------------------------
    // Prefer a section literally named ".text"; otherwise the first executable
    // code section that is not one of our own stub sections (.pak / .pakc).
    int codeIdx = -1;
    for (WORD i = 0; i < v.nSec; ++i) {
        if (std::memcmp(v.sec[i].Name, ".pak", 4) == 0) continue;   // skip .pak / .pakc stubs
        bool exec = (v.sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool code = (v.sec[i].Characteristics & IMAGE_SCN_CNT_CODE)    != 0;
        if (!(exec || code)) continue;
        if (std::memcmp(v.sec[i].Name, ".text\0\0\0", 8) == 0) { codeIdx = i; break; }
        if (codeIdx < 0) codeIdx = i;
    }
    if (codeIdx < 0) fail("no code/.text section found");
    IMAGE_SECTION_HEADER& cs = v.sec[codeIdx];
    char codeName[9] = {0}; std::memcpy(codeName, cs.Name, 8);  // keep a copy: cs dangles after img.resize()

    uint32_t codeVA  = cs.VirtualAddress;
    uint32_t codeOff = cs.PointerToRawData;
    uint32_t vsz     = cs.Misc.VirtualSize ? cs.Misc.VirtualSize : cs.SizeOfRawData;
    uint32_t codeLen = std::min<uint32_t>(cs.SizeOfRawData, vsz);
    if (!codeOff || !codeLen) fail("code section has no raw data");
    if ((size_t)codeOff + codeLen > img.size()) codeLen = (uint32_t)(img.size() - codeOff);

    // ---- carve the code section into runs that avoid excluded bytes -----
    std::random_device rng;
    auto freshSeed = [&]() { uint32_t s = 0; while (!s) s = rng(); return s; };
    std::vector<Range> ranges;
    uint32_t endRVA = codeVA + codeLen;
    for (uint32_t p = codeVA; p < endRVA;) {
        bool inside = false; uint32_t curEnd = p, nextBeg = endRVA;
        for (auto& s : ex) {
            if (p >= s.beg && p < s.end) { inside = true; if (s.end > curEnd) curEnd = s.end; }
            else if (s.beg > p && s.beg < nextBeg) nextBeg = s.beg;
        }
        if (inside) { p = std::min(curEnd, endRVA); continue; }
        uint32_t runEnd = std::min(nextBeg, endRVA);
        if (runEnd > p) ranges.push_back({ p, runEnd - p, freshSeed(), codeOff + (p - codeVA) });
        p = runEnd;
    }
    if (ranges.empty()) fail("nothing encryptable in the code section");

    // ---- encrypt in place (advance-then-use keystream, matches the stub) -
    for (auto& r : ranges) {
        uint32_t st = r.seed;
        for (uint32_t j = 0; j < r.len; ++j) { st = xorshift32(st); img[r.fileOff + j] ^= (uint8_t)st; }
    }
    cs.Characteristics |= IMAGE_SCN_MEM_WRITE;   // let the loader map .text RWX

    // ---- assemble the .pakc section content -----------------------------
    // Layout: [ stub ][ range table ]  (+ [ new TLS callback array ] if hooking TLS).
    size_t offTable, offCount, offOep = 0;
    std::vector<uint8_t> stub = hookTls ? MakeStrTlsStub(offTable, offCount)
                                        : MakeStrEntryStub(offTable, offCount, offOep);

    const size_t stubLen   = stub.size();
    const size_t tableSize = ranges.size() * 16;
    const size_t cbArrSize = hookTls ? (tlsCallbacks.size() + 2) * 8 : 0; // mine + olds + null
    const size_t contentSize = stubLen + tableSize + cbArrSize;

    if (!v.hasRoomForSectionHeader())
        fail("no room in header for a new section (unsupported layout)");

    uint32_t newVA  = (uint32_t)pe::View<true>::alignUp(v.maxSectionEnd(), v.secAlign);
    uint32_t rawPtr = (uint32_t)pe::View<true>::alignUp(img.size(),       v.fileAlign);
    uint32_t rawSz  = (uint32_t)pe::View<true>::alignUp(contentSize,      v.fileAlign);

    uint64_t tableVA = v.imageBase + newVA + stubLen;
    uint64_t oepVA   = v.imageBase + opt.AddressOfEntryPoint;   // current entry (chains)

    std::vector<uint8_t> content(contentSize, 0);
    std::memcpy(content.data(), stub.data(), stubLen);
    std::memcpy(content.data() + offTable, &tableVA, 8);
    uint32_t cnt = (uint32_t)ranges.size();
    std::memcpy(content.data() + offCount, &cnt, 4);
    if (!hookTls) std::memcpy(content.data() + offOep, &oepVA, 8);  // entry form only
    for (size_t i = 0; i < ranges.size(); ++i) {
        uint64_t absVA = v.imageBase + ranges[i].rva;
        uint8_t* e = content.data() + stubLen + i * 16;
        std::memcpy(e + 0, &absVA, 8);
        std::memcpy(e + 8, &ranges[i].len,  4);
        std::memcpy(e + 12, &ranges[i].seed, 4);
    }
    uint64_t newCbArrVA = 0;
    if (hookTls) {
        uint8_t* a = content.data() + stubLen + tableSize;
        uint64_t mine = v.imageBase + newVA;                 // our callback = stub start
        std::memcpy(a, &mine, 8);
        for (size_t i = 0; i < tlsCallbacks.size(); ++i)
            std::memcpy(a + (i + 1) * 8, &tlsCallbacks[i], 8);
        // trailing 8 bytes already zero = null terminator
        newCbArrVA = v.imageBase + newVA + stubLen + tableSize;
    }

    IMAGE_SECTION_HEADER nh = {};
    std::memcpy(nh.Name, ".pakc\0\0", 8);
    nh.Misc.VirtualSize = (DWORD)contentSize;
    nh.VirtualAddress   = newVA;
    nh.SizeOfRawData    = rawSz;
    nh.PointerToRawData = rawPtr;
    nh.Characteristics  = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    std::memcpy(v.at(v.sectionHeaderSlotOff()), &nh, sizeof(nh));

    v.nt->FileHeader.NumberOfSections = v.nSec + 1;
    opt.SizeOfImage = (DWORD)pe::View<true>::alignUp(newVA + contentSize, v.secAlign);
    opt.DllCharacteristics &= ~(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA |
                                IMAGE_DLLCHARACTERISTICS_GUARD_CF);
    if (!hookTls)
        opt.AddressOfEntryPoint = newVA;   // entry-point form: run the stub first

    // Append section data.
    img.resize(rawPtr + rawSz, 0);
    std::memcpy(img.data() + rawPtr, content.data(), contentSize);

    // TLS form: repoint the callback array at our prepended copy (do this after
    // the resize, so we write into the final buffer).
    if (hookTls) {
        size_t cbField = tlsDirFileOff + offsetof(TLS, AddressOfCallBacks);
        std::memcpy(img.data() + cbField, &newCbArrVA, 8);
    }

    FILE* o = std::fopen(argv[2], "wb");
    if (!o) fail("cannot open output");
    if (std::fwrite(img.data(), 1, img.size(), o) != img.size()) fail("write error");
    std::fclose(o);

    uint64_t bytesEnc = 0; for (auto& r : ranges) bytesEnc += r.len;
    std::printf("codeenc: encrypted section '%.8s' (%llu bytes in %zu run(s)); added .pakc stub (%zu B).\n",
                codeName, (unsigned long long)bytesEnc, ranges.size(), contentSize);
    std::printf("codeenc: decryptor hooked via %s%s.\n",
                hookTls ? "TLS callback" : "entry point",
                hookTls ? " (ahead of the target's own callbacks)" : "");
    std::printf("codeenc: wrote %s\n", argv[2]);
    return 0;
}
