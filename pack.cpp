// pack — x64 PE compressing+encrypting packer (part of the exe-protector toolset).
//
// Compresses the target's non-loader-critical sections (typically .text and
// .data) with a custom LZSS, then encrypts each compressed blob with the PAKP
// stream cipher (custom ChaCha-derived ARX; fresh random 256-bit key per pack,
// so output is polymorphic). It removes their raw bytes from the file (so the
// file shrinks and those sections are just absent/zeroed on disk), and appends a
// new ".pakp" section holding a self-contained anti-debug+decrypt+decompress stub
// + a table + the encrypted blobs + the key. At load the stub checks for a
// debugger, decrypts, and rebuilds each section in memory, then runs the original
// program. Statically a tool sees uniform high-entropy data (no recognizable
// compressed structure), not code; the file is also smaller.
//
// Anti-debug: the stub reads the PEB directly (no API) and folds BeingDebugged /
// NtGlobalFlag into the key, so under a user-mode debugger the sections decrypt
// to garbage and the program cannot run — and NOP-ing a branch does not recover
// it. A speed bump, not a wall (a PEB-hiding or late-attaching debugger gets by).
//
// The key ships inside .pakp, so the encryption is obfuscation-grade — it raises
// the static-analysis bar and makes the blobs pattern-free, but is not secrecy
// against someone who extracts the key from the stub.
//
//   Usage:  pack <input.exe> <output.exe>
//
// The decrypt+decompress routine is relocation-free machine code extracted from
// stub_src.c (compiled with SLP vectorization off so the cipher constants stay
// immediates, verified with `objdump -dr` to have no relocations). The packed
// sections are marked RWX so the loader maps them writable and the stub writes
// decompressed bytes straight into their reserved virtual space — no API calls.
// The .pakp section is RWX too, so the stub can decrypt the blobs in place.
// Hooked via a TLS callback when the target has one (so it runs before the real
// callbacks and the entry), else via the entry point. ASLR is pinned
// (DYNAMIC_BASE cleared) so the absolute VAs in the table resolve.
//
// Loader-critical data (headers, imports/IAT, relocations, TLS directory,
// exception/debug/load-config directories, resources) is never compressed, so
// the Windows loader still has everything it needs before the stub runs. It
// composes with strcrypt/codeenc (distinct section names; stubs chain).
//
// Scope / limits (honest): native PE EXEs — both x64 (PE32+, AMD64, x86-64 stub)
// and x86 (PE32, i386, x86 stub); dispatched on the machine field. Refuses DLLs,
// .NET and files it has already packed. Defeats STATIC analysis only — a debugger
// or a memory dump after startup recovers everything. For protecting software you
// own; always test the output.
//
// Build (MSYS2 UCRT64):  g++ -O2 -std=c++17 -o pack.exe pack.cpp

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <random>
#include <type_traits>
#include "pe_core.h"      // shared PE parse/validate, RVA mapping, exclusion list
#include "pak_core.h"

static void fail(const char* m) { std::fprintf(stderr, "pack: %s\n", m); std::exit(1); }

// The packer core, parameterized on architecture. X64 => PE32+/AMD64 with an
// x86-64 stub; !X64 => PE32/i386 with the x86 stub. The two differ only in the
// header struct types, the pointer width PW (stub patch slots, the TLS callback
// array, import thunks, the TLS AddressOfCallBacks field) and the ordinal flag;
// the Ent table stays 32 bytes on both (32-bit VAs zero-extend into its u64s).
template<bool X64>
static int packImpl(std::vector<uint8_t>& img, const char* outPath, long sz) {
    using NT  = typename pe::Traits<X64>::NT;
    using OPT = typename pe::Traits<X64>::OPT;
    using TLS = typename pe::Traits<X64>::TLS;
    constexpr int PW = pe::Traits<X64>::PW;

    // ---- parse + validate; refuse DLL/.NET and files we already packed ----
    // (main() has already dispatched on the machine field, so don't re-require it)
    pe::View<X64> v(img);
    { std::string e = pe::open<X64>(v, ".pakp", /*requireMachine=*/false); if (!e.empty()) fail(e.c_str()); }
    OPT& opt = *v.opt;
    const uint64_t imageBase = v.imageBase;
    const uint32_t fileAlign = v.fileAlign;
    const uint32_t secAlign  = v.secAlign;
    auto alignUp = [](uint64_t x, uint64_t a) { return (x + a - 1) / a * a; };
    IMAGE_SECTION_HEADER* sec = v.sec;
    const WORD nSec = v.nSec;
    DWORD peOff = v.peOff;
    auto at = [&](size_t off) -> uint8_t* { return img.data() + off; };
    auto in = [&](size_t off, size_t len) { return off + len <= img.size(); };

    // ---- TLS callbacks (hook ahead of them) ----------------------------
    std::vector<uint64_t> tlsCallbacks;
    uint32_t tlsDirRva = 0;
    {
        auto& d = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (d.VirtualAddress && d.Size) {
            uint32_t o = v.rvaToOff(d.VirtualAddress);
            if (o && in(o, sizeof(TLS))) {
                auto tls = reinterpret_cast<TLS*>(at(o));
                if ((uint64_t)tls->AddressOfCallBacks >= imageBase) {
                    uint32_t arrOff = v.rvaToOff((uint32_t)((uint64_t)tls->AddressOfCallBacks - imageBase));
                    for (uint32_t k = 0; arrOff && in(arrOff + k * PW, PW) && k < 4096; ++k) {
                        uint64_t cb = 0; std::memcpy(&cb, at(arrOff + k * PW), PW);
                        if (!cb) break;
                        tlsCallbacks.push_back(cb);
                    }
                    if (!tlsCallbacks.empty()) tlsDirRva = d.VirtualAddress;
                }
            }
        }
    }
    const bool hookTls = tlsDirRva != 0;

    // ---- loader-critical exclusions (never compress these) -------------
    std::vector<pe::Span> ex;
    pe::buildExclusions<X64>(v, ex);

    // ---- choose compressible sections + compress -----------------------
    struct Plan { int idx; std::vector<uint8_t> blob; uint32_t origLen; };
    std::vector<Plan> plans;
    for (WORD i = 0; i < nSec; ++i) {
        if (std::memcmp(sec[i].Name, ".pak", 4) == 0) continue;     // our own stub sections
        uint32_t raw = sec[i].SizeOfRawData, ptr = sec[i].PointerToRawData;
        if (!raw || !ptr) continue;                                  // nothing on disk (e.g. .bss)
        uint32_t va  = sec[i].VirtualAddress;
        uint32_t span = std::max<uint32_t>(sec[i].Misc.VirtualSize, raw);
        if (pe::overlaps(ex, va, va + span)) continue;               // loader needs it intact
        uint32_t clamp = raw;
        if ((size_t)ptr + clamp > img.size()) clamp = (uint32_t)(img.size() - ptr);
        if (!clamp) continue;
        Plan p; p.idx = i; p.origLen = clamp;
        p.blob = pakp_lz_compress(at(ptr), clamp);
        if (p.blob.size() >= clamp) continue;                        // skip if it would not shrink
        plans.push_back(std::move(p));
    }
    if (plans.empty()) fail("no compressible sections found (nothing to do)");

    std::vector<bool> isComp(nSec, false);
    for (auto& p : plans) isComp[p.idx] = true;

    // ---- encrypt each compressed blob in place (PAKP cipher) -----------
    uint32_t key[8];
    { std::random_device rd; for (int i = 0; i < 8; ++i) key[i] = rd(); }
    for (size_t i = 0; i < plans.size(); ++i)
        pakp_xor(plans[i].blob.data(), (uint32_t)plans[i].blob.size(), key, (uint64_t)i);

    // ---- assemble the .pakp content: stub + table + blobs [+ cb array] [+ key] --
    uint32_t newVA = (uint32_t)alignUp(v.maxSectionEnd(), secAlign);

    size_t offT, offC, offO = 0, offK = 0;
    std::vector<uint8_t> stub;
    if constexpr (X64)
        stub = hookTls ? MakePakpTlsStub(offT, offC, offK) : MakePakpEntryStub(offT, offC, offO, offK);
    else
        stub = hookTls ? MakePakpTlsStub32(offT, offC, offK) : MakePakpEntryStub32(offT, offC, offO, offK);

    const size_t stubLen   = stub.size();
    const size_t tableSize = plans.size() * 32;      // Ent is 32 bytes (adds nonce)
    size_t blobsSize = 0; for (auto& p : plans) blobsSize += p.blob.size();
    const size_t cbArrSize = hookTls ? (tlsCallbacks.size() + 2) * PW : 0;
    const size_t kKeyLen   = 32;                     // 256-bit PAKP key
    const size_t keyOff    = stubLen + tableSize + blobsSize + cbArrSize;
    const size_t contentSize = keyOff + kKeyLen;

    uint64_t tableVA = imageBase + newVA + stubLen;
    uint64_t oepVA   = imageBase + opt.AddressOfEntryPoint;
    uint64_t keyVA   = imageBase + newVA + keyOff;

    std::vector<uint8_t> content(contentSize, 0);
    std::memcpy(content.data(), stub.data(), stubLen);
    std::memcpy(content.data() + offT, &tableVA, PW);
    uint32_t cnt = (uint32_t)plans.size();
    std::memcpy(content.data() + offC, &cnt, 4);
    if (!hookTls) std::memcpy(content.data() + offO, &oepVA, PW);
    std::memcpy(content.data() + offK, &keyVA, PW);
    std::memcpy(content.data() + keyOff, key, kKeyLen);

    // table entries (32-byte Ent; VAs stored as u64, truncated by the stub on x86) + blobs
    size_t blobCursor = stubLen + tableSize;
    for (size_t i = 0; i < plans.size(); ++i) {
        uint64_t dstVA = imageBase + sec[plans[i].idx].VirtualAddress;
        uint64_t srcVA = imageBase + newVA + blobCursor;
        uint32_t clen  = (uint32_t)plans[i].blob.size();
        uint32_t olen  = plans[i].origLen;
        uint64_t nonce = (uint64_t)i;                // matches the encrypt pass
        uint8_t* e = content.data() + stubLen + i * 32;
        std::memcpy(e + 0,  &dstVA, 8);
        std::memcpy(e + 8,  &srcVA, 8);
        std::memcpy(e + 16, &clen, 4);
        std::memcpy(e + 20, &olen, 4);
        std::memcpy(e + 24, &nonce, 8);
        std::memcpy(content.data() + blobCursor, plans[i].blob.data(), clen);
        blobCursor += clen;
    }
    uint64_t newCbArrVA = 0;
    if (hookTls) {
        uint8_t* a = content.data() + stubLen + tableSize + blobsSize;
        uint64_t mine = imageBase + newVA;
        std::memcpy(a, &mine, PW);                   // our callback first (pointer-wide)
        for (size_t i = 0; i < tlsCallbacks.size(); ++i)
            std::memcpy(a + (i + 1) * PW, &tlsCallbacks[i], PW);
        newCbArrVA = imageBase + newVA + stubLen + tableSize + blobsSize;
    }

    // ---- rebuild the file: headers + kept raw + .pakp ------------------
    if (!v.hasRoomForSectionHeader())
        fail("no room in header for a new section (unsupported layout)");
    uint32_t secTabEnd = v.sectionHeaderSlotOff();

    std::vector<uint32_t> newPtr(nSec, 0), newRaw(nSec, 0);
    std::vector<uint8_t> out(at(0), at(opt.SizeOfHeaders));   // copy header region verbatim
    for (WORD i = 0; i < nSec; ++i) {
        if (isComp[i]) continue;                             // compressed: no raw data on disk
        uint32_t raw = sec[i].SizeOfRawData, ptr = sec[i].PointerToRawData;
        if (!raw || !ptr) continue;                          // .bss etc.
        uint32_t clamp = raw;
        if ((size_t)ptr + clamp > img.size()) clamp = (uint32_t)(img.size() - ptr);
        uint32_t dstOff = (uint32_t)alignUp(out.size(), fileAlign);
        out.resize(dstOff, 0);
        out.insert(out.end(), at(ptr), at(ptr) + clamp);
        newPtr[i] = dstOff; newRaw[i] = raw;
    }
    uint32_t pakpPtr = (uint32_t)alignUp(out.size(), fileAlign);
    uint32_t pakpRaw = (uint32_t)alignUp(contentSize, fileAlign);
    out.resize(pakpPtr, 0);
    out.insert(out.end(), content.begin(), content.end());
    out.resize(pakpPtr + pakpRaw, 0);

    // ---- patch headers in the rebuilt image (no more resizing) ---------
    auto nt2  = reinterpret_cast<NT*>(out.data() + peOff);
    auto sec2 = IMAGE_FIRST_SECTION(nt2);
    for (WORD i = 0; i < nSec; ++i) {
        if (isComp[i]) {
            sec2[i].PointerToRawData = 0;
            sec2[i].SizeOfRawData    = 0;                    // loader zero-fills the VA span
            sec2[i].Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
        } else {
            sec2[i].PointerToRawData = newPtr[i];
            sec2[i].SizeOfRawData    = newRaw[i];
        }
    }
    IMAGE_SECTION_HEADER nh = {};
    std::memcpy(nh.Name, ".pakp\0\0", 8);
    nh.Misc.VirtualSize = (DWORD)contentSize;
    nh.VirtualAddress   = newVA;
    nh.SizeOfRawData    = pakpRaw;
    nh.PointerToRawData = pakpPtr;
    // WRITE: the stub decrypts the compressed blobs in place within .pakp.
    nh.Characteristics  = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE |
                          IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    std::memcpy(out.data() + secTabEnd, &nh, sizeof(nh));

    nt2->FileHeader.NumberOfSections = nSec + 1;
    nt2->OptionalHeader.SizeOfImage  = (DWORD)alignUp(newVA + contentSize, secAlign);
    nt2->OptionalHeader.DllCharacteristics &= ~(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                                IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA |
                                                IMAGE_DLLCHARACTERISTICS_GUARD_CF);
    if (!hookTls) nt2->OptionalHeader.AddressOfEntryPoint = newVA;

    if (hookTls) {
        // repoint TLS AddressOfCallBacks at our prepended array (new file layout)
        auto rvaToNewOff = [&](uint32_t rva) -> uint32_t {
            if (rva < nt2->OptionalHeader.SizeOfHeaders) return rva;
            for (WORD i = 0; i < nSec; ++i) {
                uint32_t va = sec2[i].VirtualAddress;
                uint32_t span = std::max(sec2[i].Misc.VirtualSize, sec2[i].SizeOfRawData);
                if (sec2[i].PointerToRawData && rva >= va && rva < va + span)
                    return sec2[i].PointerToRawData + (rva - va);
            }
            return 0;
        };
        uint32_t to = rvaToNewOff(tlsDirRva);
        if (!to) fail("could not relocate TLS directory (unsupported layout)");
        size_t cbField = to + offsetof(TLS, AddressOfCallBacks);
        std::memcpy(out.data() + cbField, &newCbArrVA, PW);
    }

    FILE* o = std::fopen(outPath, "wb");
    if (!o) fail("cannot open output");
    if (std::fwrite(out.data(), 1, out.size(), o) != out.size()) fail("write error");
    std::fclose(o);

    uint64_t origBytes = 0, compBytes = 0;
    for (auto& p : plans) { origBytes += p.origLen; compBytes += p.blob.size(); }
    std::printf("pack: %s; compressed %zu section(s): %llu -> %llu bytes (%.1f%%).\n",
                X64 ? "x64" : "x86", plans.size(),
                (unsigned long long)origBytes, (unsigned long long)compBytes,
                origBytes ? 100.0 * compBytes / origBytes : 0.0);
    std::printf("pack: file %ld -> %zu bytes; hooked via %s.\n",
                sz, out.size(), hookTls ? "TLS callback" : "entry point");
    std::printf("pack: wrote %s\n", outPath);
    return 0;
}

int main(int argc, char** argv) {
    if (argc != 3) { std::fprintf(stderr, "usage: pack <input.exe> <output.exe>\n"); return 2; }

    FILE* f = std::fopen(argv[1], "rb");
    if (!f) fail("cannot open input");
    std::fseek(f, 0, SEEK_END); long sz = std::ftell(f); std::fseek(f, 0, SEEK_SET);
    if (sz <= 0) fail("empty input");
    std::vector<uint8_t> img(static_cast<size_t>(sz));
    if (std::fread(img.data(), 1, img.size(), f) != img.size()) fail("read error");
    std::fclose(f);

    if (img.size() < sizeof(IMAGE_DOS_HEADER)) fail("too small");
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(img.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) fail("not a PE (no MZ)");
    DWORD peOff = dos->e_lfanew;
    if ((size_t)peOff + 6 > img.size()) fail("not a PE (truncated)");
    if (*reinterpret_cast<DWORD*>(img.data() + peOff) != IMAGE_NT_SIGNATURE) fail("not a PE (no PE00)");
    WORD machine = *reinterpret_cast<WORD*>(img.data() + peOff + 4);

    if (machine == IMAGE_FILE_MACHINE_AMD64) return packImpl<true>(img, argv[2], sz);
    if (machine == IMAGE_FILE_MACHINE_I386)  return packImpl<false>(img, argv[2], sz);
    fail("only x64 (AMD64) and x86 (i386) executables are supported");
    return 1;
}
