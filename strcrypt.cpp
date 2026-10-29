// strcrypt — x64 PE string-encryption packer (part of the Anti-Reverse toolset).
//
// Takes an already-compiled 64-bit native Windows .exe and encrypts the string
// bytes in its .rdata / .data sections, then appends a small decryptor stub that
// runs before the original entry point, decrypts the strings in memory, and
// jumps to the original code. The on-disk file shows ciphertext where the
// strings were, so `strings` / a hex editor reveal nothing.
//
//   Usage:  strcrypt <input.exe> <output.exe>
//
// Scope / limits (honest):
//   * x64 native PE only (PE32+, machine AMD64). Refuses 32-bit, DLLs, .NET,
//     and files already packed by this tool.
//   * It encrypts detected ASCII / UTF-16LE string runs, skipping every byte the
//     Windows loader needs before the stub runs (headers, import table, all data
//     directories). It does NOT touch code, pointers, or resources.
//   * ASLR is pinned (DYNAMIC_BASE cleared) so the stub can use fixed addresses;
//     an EXE loads at its preferred base, so this is safe for EXEs.
//   * Exotic targets (delay-imports that live outside their data directory, TLS
//     callbacks that read .rdata strings, self-checking binaries) can break —
//     always test the output. This is a protector for software you own.
//
// The PE plumbing (parse/validate, RVA mapping, the loader-critical exclusion
// list) is shared with codeenc/pack via pe_core.h; the decryptor machine code
// and stub framing are shared with the GUI via str_core.h. The keystream is
// xorshift32 (advance-then-use low byte); the per-range seed now comes from a
// CSPRNG, so the ciphertext is polymorphic and the seeds are not recoverable
// from the (plaintext) PE header.
//
// Build (MSYS2 UCRT64):
//   g++ -O2 -std=c++17 -o strcrypt.exe strcrypt.cpp

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
#include "str_core.h"      // MakeStrEntryStub + the shared xorshift decryptor

// Keystream must match the stub exactly: advance xorshift32, then use low byte.
static inline uint32_t xorshift32(uint32_t x) {
    x ^= x << 13; x ^= x >> 17; x ^= x << 5; return x;
}

struct Range { uint32_t rva; uint32_t len; uint32_t seed; uint32_t fileOff; };

static void fail(const char* msg) { std::fprintf(stderr, "strcrypt: %s\n", msg); std::exit(1); }

int main(int argc, char** argv) {
    if (argc != 3) { std::fprintf(stderr, "usage: strcrypt <input.exe> <output.exe>\n"); return 2; }

    // ---- load the file --------------------------------------------------
    FILE* f = std::fopen(argv[1], "rb");
    if (!f) fail("cannot open input");
    std::fseek(f, 0, SEEK_END); long sz = std::ftell(f); std::fseek(f, 0, SEEK_SET);
    if (sz <= 0) fail("empty input");
    std::vector<uint8_t> img(static_cast<size_t>(sz));
    if (std::fread(img.data(), 1, img.size(), f) != img.size()) fail("read error");
    std::fclose(f);

    // ---- parse + validate (x64 only); refuse files we already packed ----
    pe::View<true> v(img);
    { std::string e = pe::open<true>(v, ".pak"); if (!e.empty()) fail(e.c_str()); }
    IMAGE_OPTIONAL_HEADER64& opt = *v.opt;

    // ---- the bytes the loader needs intact ------------------------------
    std::vector<pe::Span> ex;
    pe::buildExclusions<true>(v, ex);

    // ---- find + encrypt string runs in .rdata / .data -------------------
    const uint32_t MINLEN = 4;
    std::vector<Range> ranges;

    // Per-range seed from a CSPRNG (never 0, which xorshift cannot leave).
    std::random_device rng;
    auto freshSeed = [&]() { uint32_t s = 0; while (!s) s = rng(); return s; };
    auto consider = [&](uint32_t rva, uint32_t fileOff, uint32_t len) {
        if (len < MINLEN) return;
        if (pe::overlaps(ex, rva, rva + len)) return;
        ranges.push_back({ rva, len, freshSeed(), fileOff });
    };

    std::vector<bool> anyInSection(v.nSec, false);
    for (WORD i = 0; i < v.nSec; ++i) {
        bool isData = std::memcmp(v.sec[i].Name, ".rdata", 6) == 0 ||
                      std::memcmp(v.sec[i].Name, ".data",  5) == 0;
        if (!isData) continue;
        uint32_t base = v.sec[i].PointerToRawData;
        uint32_t raw  = v.sec[i].SizeOfRawData;
        uint32_t vsz  = v.sec[i].Misc.VirtualSize;
        uint32_t scan = std::min(raw, vsz ? vsz : raw);
        if (!base || !v.in(base, scan)) continue;
        uint32_t vbase = v.sec[i].VirtualAddress;
        size_t before = ranges.size();

        // ASCII runs
        for (uint32_t p = 0; p < scan;) {
            uint8_t c = img[base + p];
            if (c >= 0x20 && c <= 0x7e) {
                uint32_t q = p;
                while (q < scan) { uint8_t d = img[base + q]; if (d < 0x20 || d > 0x7e) break; ++q; }
                consider(vbase + p, base + p, q - p);
                p = q;
            } else ++p;
        }
        // UTF-16LE runs (printable ASCII char followed by 0x00)
        for (uint32_t p = 0; p + 1 < scan;) {
            if (img[base + p] >= 0x20 && img[base + p] <= 0x7e && img[base + p + 1] == 0x00) {
                uint32_t q = p;
                while (q + 1 < scan && img[base + q] >= 0x20 && img[base + q] <= 0x7e &&
                       img[base + q + 1] == 0x00) q += 2;
                consider(vbase + p, base + p, q - p);   // length in bytes
                p = q;
            } else ++p;
        }
        anyInSection[i] = ranges.size() > before;
    }

    if (ranges.empty()) fail("no encryptable strings found (nothing to do)");

    // Encrypt in place (advance-then-use keystream, matching the stub).
    for (auto& r : ranges) {
        uint32_t st = r.seed;
        for (uint32_t j = 0; j < r.len; ++j) { st = xorshift32(st); img[r.fileOff + j] ^= (uint8_t)st; }
    }
    // Make touched sections writable so the stub can decrypt in memory.
    for (WORD i = 0; i < v.nSec; ++i)
        if (anyInSection[i]) v.sec[i].Characteristics |= IMAGE_SCN_MEM_WRITE;

    // ---- lay out the new .pak section (shared entry stub + range table) -
    size_t offTable, offCount, offOep;
    std::vector<uint8_t> stub = MakeStrEntryStub(offTable, offCount, offOep);
    const size_t  stubLen     = stub.size();
    const size_t  tableSize   = ranges.size() * 16;      // {u64 absVA, u32 len, u32 seed}
    const size_t  contentSize = stubLen + tableSize;

    if (!v.hasRoomForSectionHeader())
        fail("no room in header for a new section (unsupported layout)");

    uint32_t newVA  = (uint32_t)pe::View<true>::alignUp(v.maxSectionEnd(), v.secAlign);
    uint32_t rawPtr = (uint32_t)pe::View<true>::alignUp(img.size(),       v.fileAlign);
    uint32_t rawSz  = (uint32_t)pe::View<true>::alignUp(contentSize,      v.fileAlign);

    uint64_t tableVA = v.imageBase + newVA + stubLen;
    uint64_t oepVA   = v.imageBase + opt.AddressOfEntryPoint;

    // Assemble the section content: patched stub + table.
    std::vector<uint8_t> content(contentSize, 0);
    std::memcpy(content.data(), stub.data(), stubLen);
    std::memcpy(content.data() + offTable, &tableVA, 8);
    uint32_t cnt = (uint32_t)ranges.size();
    std::memcpy(content.data() + offCount, &cnt, 4);
    std::memcpy(content.data() + offOep,   &oepVA, 8);
    for (size_t i = 0; i < ranges.size(); ++i) {
        uint64_t absVA = v.imageBase + ranges[i].rva;
        uint8_t* e = content.data() + stubLen + i * 16;
        std::memcpy(e + 0, &absVA, 8);
        std::memcpy(e + 8, &ranges[i].len, 4);
        std::memcpy(e + 12, &ranges[i].seed, 4);
    }

    // Write the new section header (into existing header padding).
    IMAGE_SECTION_HEADER nh = {};
    std::memcpy(nh.Name, ".pak\0\0\0", 8);
    nh.Misc.VirtualSize = (DWORD)contentSize;
    nh.VirtualAddress   = newVA;
    nh.SizeOfRawData    = rawSz;
    nh.PointerToRawData = rawPtr;
    nh.Characteristics  = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    std::memcpy(v.at(v.sectionHeaderSlotOff()), &nh, sizeof(nh));

    // Patch the headers.
    v.nt->FileHeader.NumberOfSections = v.nSec + 1;
    opt.AddressOfEntryPoint = newVA;                                   // run the stub first
    opt.SizeOfImage = (DWORD)pe::View<true>::alignUp(newVA + contentSize, v.secAlign);
    opt.DllCharacteristics &= ~(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA |
                                IMAGE_DLLCHARACTERISTICS_GUARD_CF);

    // ---- append the section data + write output -------------------------
    img.resize(rawPtr + rawSz, 0);
    std::memcpy(img.data() + rawPtr, content.data(), contentSize);

    FILE* o = std::fopen(argv[2], "wb");
    if (!o) fail("cannot open output");
    if (std::fwrite(img.data(), 1, img.size(), o) != img.size()) fail("write error");
    std::fclose(o);

    uint64_t bytesEnc = 0; for (auto& r : ranges) bytesEnc += r.len;
    std::printf("strcrypt: encrypted %zu string(s), %llu bytes; added .pak stub (%zu B).\n",
                ranges.size(), (unsigned long long)bytesEnc, contentSize);
    std::printf("strcrypt: wrote %s\n", argv[2]);
    return 0;
}
