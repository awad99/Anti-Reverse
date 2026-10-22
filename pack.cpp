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
// Scope / limits (honest): x64 native PE only (PE32+, AMD64). Refuses 32-bit,
// DLLs, .NET and files it has already packed. Defeats STATIC analysis only — a
// debugger or a memory dump after startup recovers everything. For protecting
// software you own; always test the output.
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
#include "pak_core.h"

struct Span { uint32_t beg; uint32_t end; };
static bool overlaps(const std::vector<Span>& ex, uint32_t beg, uint32_t end) {
    for (const auto& s : ex) if (beg < s.end && s.beg < end) return true;
    return false;
}
static void fail(const char* m) { std::fprintf(stderr, "pack: %s\n", m); std::exit(1); }

int main(int argc, char** argv) {
    if (argc != 3) { std::fprintf(stderr, "usage: pack <input.exe> <output.exe>\n"); return 2; }

    FILE* f = std::fopen(argv[1], "rb");
    if (!f) fail("cannot open input");
    std::fseek(f, 0, SEEK_END); long sz = std::ftell(f); std::fseek(f, 0, SEEK_SET);
    if (sz <= 0) fail("empty input");
    std::vector<uint8_t> img(static_cast<size_t>(sz));
    if (std::fread(img.data(), 1, img.size(), f) != img.size()) fail("read error");
    std::fclose(f);

    auto at = [&](size_t off) -> uint8_t* { return img.data() + off; };
    auto in = [&](size_t off, size_t len) { return off + len <= img.size(); };

    if (!in(0, sizeof(IMAGE_DOS_HEADER))) fail("too small");
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(at(0));
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) fail("not a PE (no MZ)");
    DWORD peOff = dos->e_lfanew;
    if (!in(peOff, sizeof(IMAGE_NT_HEADERS64))) fail("not a PE (truncated)");
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(at(peOff));
    if (nt->Signature != IMAGE_NT_SIGNATURE) fail("not a PE (no PE00)");
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) fail("only x64 (AMD64) is supported");
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) fail("only PE32+ (64-bit) is supported");
    if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) fail("DLLs are not supported (EXE only)");

    IMAGE_OPTIONAL_HEADER64& opt = nt->OptionalHeader;
    if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR &&
        opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress)
        fail(".NET assemblies are not supported");

    const uint64_t imageBase = opt.ImageBase;
    const uint32_t fileAlign = opt.FileAlignment;
    const uint32_t secAlign  = opt.SectionAlignment;
    auto alignUp = [](uint64_t v, uint64_t a) { return (v + a - 1) / a * a; };

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    const WORD nSec = nt->FileHeader.NumberOfSections;
    for (WORD i = 0; i < nSec; ++i)
        if (std::memcmp(sec[i].Name, ".pakp", 5) == 0) fail("already packed");

    auto rvaToOff = [&](uint32_t rva) -> uint32_t {
        if (rva < opt.SizeOfHeaders) return rva;
        for (WORD i = 0; i < nSec; ++i) {
            uint32_t va = sec[i].VirtualAddress;
            uint32_t span = std::max(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
            if (rva >= va && rva < va + span) return sec[i].PointerToRawData + (rva - va);
        }
        return 0;
    };

    // ---- TLS callbacks (hook ahead of them) ----------------------------
    std::vector<uint64_t> tlsCallbacks;
    uint32_t tlsDirRva = 0;
    {
        auto& d = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (d.VirtualAddress && d.Size) {
            uint32_t o = rvaToOff(d.VirtualAddress);
            if (o && in(o, sizeof(IMAGE_TLS_DIRECTORY64))) {
                auto tls = reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(at(o));
                if (tls->AddressOfCallBacks >= imageBase) {
                    uint32_t arrOff = rvaToOff((uint32_t)(tls->AddressOfCallBacks - imageBase));
                    for (uint32_t k = 0; arrOff && in(arrOff + k * 8, 8) && k < 4096; ++k) {
                        uint64_t cb; std::memcpy(&cb, at(arrOff + k * 8), 8);
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
    std::vector<Span> ex;
    ex.push_back({ 0, opt.SizeOfHeaders });
    for (DWORD i = 0; i < opt.NumberOfRvaAndSizes && i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
        auto& d = opt.DataDirectory[i];
        if (d.VirtualAddress && d.Size) ex.push_back({ d.VirtualAddress, d.VirtualAddress + d.Size });
    }
    {
        auto& impDir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        uint32_t off = impDir.VirtualAddress ? rvaToOff(impDir.VirtualAddress) : 0;
        int guard = 0;
        while (off && in(off, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && ++guard < 4096) {
            auto imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(at(off));
            if (imp->Name == 0 && imp->FirstThunk == 0) break;
            if (imp->Name) {
                uint32_t nameOff = rvaToOff(imp->Name), n = 0;
                while (nameOff && in(nameOff + n, 1) && img[nameOff + n]) ++n;
                ex.push_back({ imp->Name, imp->Name + n + 1 });
            }
            for (int which = 0; which < 2; ++which) {
                uint32_t arrRva = which ? imp->FirstThunk : imp->OriginalFirstThunk;
                if (!arrRva) continue;
                uint32_t arrOff = rvaToOff(arrRva), k = 0;
                while (arrOff && in(arrOff + k * 8, 8)) {
                    uint64_t t; std::memcpy(&t, at(arrOff + k * 8), 8);
                    if (!t) break;
                    if (!(t & IMAGE_ORDINAL_FLAG64)) {
                        uint32_t ibnRva = (uint32_t)(t & 0x7fffffff);
                        uint32_t ibnOff = rvaToOff(ibnRva), n = 0;
                        while (ibnOff && in(ibnOff + 2 + n, 1) && img[ibnOff + 2 + n]) ++n;
                        ex.push_back({ ibnRva, ibnRva + 2 + n + 1 });
                    }
                    ++k;
                }
                ex.push_back({ arrRva, arrRva + (k + 1) * 8 });
            }
            off += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
    }

    // ---- choose compressible sections + compress -----------------------
    struct Plan { int idx; std::vector<uint8_t> blob; uint32_t origLen; };
    std::vector<Plan> plans;
    for (WORD i = 0; i < nSec; ++i) {
        if (std::memcmp(sec[i].Name, ".pak", 4) == 0) continue;     // our own stub sections
        uint32_t raw = sec[i].SizeOfRawData, ptr = sec[i].PointerToRawData;
        if (!raw || !ptr) continue;                                  // nothing on disk (e.g. .bss)
        uint32_t va  = sec[i].VirtualAddress;
        uint32_t span = std::max<uint32_t>(sec[i].Misc.VirtualSize, raw);
        if (overlaps(ex, va, va + span)) continue;                   // loader needs it intact
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
    // Fresh random 256-bit key per pack -> polymorphic output; the key ships
    // in .pakp (obfuscation-grade, not secrecy). Nonce = the blob's table index,
    // so every (key,nonce) pair is unique within the file.
    uint32_t key[8];
    { std::random_device rd; for (int i = 0; i < 8; ++i) key[i] = rd(); }
    for (size_t i = 0; i < plans.size(); ++i)
        pakp_xor(plans[i].blob.data(), (uint32_t)plans[i].blob.size(), key, (uint64_t)i);

    // ---- assemble the .pakp content: stub + table + blobs [+ cb array] [+ key] --
    uint32_t maxEnd = 0;
    for (WORD i = 0; i < nSec; ++i)
        maxEnd = std::max<uint32_t>(maxEnd, sec[i].VirtualAddress +
                 std::max(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData));
    uint32_t newVA = (uint32_t)alignUp(maxEnd, secAlign);

    size_t offT, offC, offO = 0, offK = 0;
    std::vector<uint8_t> stub = hookTls ? MakePakpTlsStub(offT, offC, offK)
                                        : MakePakpEntryStub(offT, offC, offO, offK);
    const size_t stubLen   = stub.size();
    const size_t tableSize = plans.size() * 32;      // Ent is 32 bytes (adds nonce)
    size_t blobsSize = 0; for (auto& p : plans) blobsSize += p.blob.size();
    const size_t cbArrSize = hookTls ? (tlsCallbacks.size() + 2) * 8 : 0;
    const size_t kKeyLen   = 32;                     // 256-bit PAKP key
    const size_t keyOff    = stubLen + tableSize + blobsSize + cbArrSize;
    const size_t contentSize = keyOff + kKeyLen;

    uint64_t tableVA = imageBase + newVA + stubLen;
    uint64_t oepVA   = imageBase + opt.AddressOfEntryPoint;
    uint64_t keyVA   = imageBase + newVA + keyOff;

    std::vector<uint8_t> content(contentSize, 0);
    std::memcpy(content.data(), stub.data(), stubLen);
    std::memcpy(content.data() + offT, &tableVA, 8);
    uint32_t cnt = (uint32_t)plans.size();
    std::memcpy(content.data() + offC, &cnt, 4);
    if (!hookTls) std::memcpy(content.data() + offO, &oepVA, 8);
    std::memcpy(content.data() + offK, &keyVA, 8);
    std::memcpy(content.data() + keyOff, key, kKeyLen);

    // table entries + blobs
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
        std::memcpy(a, &mine, 8);
        for (size_t i = 0; i < tlsCallbacks.size(); ++i)
            std::memcpy(a + (i + 1) * 8, &tlsCallbacks[i], 8);
        newCbArrVA = imageBase + newVA + stubLen + tableSize + blobsSize;
    }

    // ---- rebuild the file: headers + kept raw + .pakp ------------------
    uint32_t secTabOff = peOff + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader;
    uint32_t secTabEnd = secTabOff + (uint32_t)nSec * sizeof(IMAGE_SECTION_HEADER);
    if (secTabEnd + sizeof(IMAGE_SECTION_HEADER) > opt.SizeOfHeaders)
        fail("no room in header for a new section (unsupported layout)");

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
    auto nt2  = reinterpret_cast<IMAGE_NT_HEADERS64*>(out.data() + peOff);
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
        size_t cbField = to + offsetof(IMAGE_TLS_DIRECTORY64, AddressOfCallBacks);
        std::memcpy(out.data() + cbField, &newCbArrVA, 8);
    }

    FILE* o = std::fopen(argv[2], "wb");
    if (!o) fail("cannot open output");
    if (std::fwrite(out.data(), 1, out.size(), o) != out.size()) fail("write error");
    std::fclose(o);

    uint64_t origBytes = 0, compBytes = 0;
    for (auto& p : plans) { origBytes += p.origLen; compBytes += p.blob.size(); }
    std::printf("pack: compressed %zu section(s): %llu -> %llu bytes (%.1f%%).\n",
                plans.size(), (unsigned long long)origBytes, (unsigned long long)compBytes,
                origBytes ? 100.0 * compBytes / origBytes : 0.0);
    std::printf("pack: file %ld -> %zu bytes; hooked via %s.\n",
                sz, out.size(), hookTls ? "TLS callback" : "entry point");
    std::printf("pack: wrote %s\n", argv[2]);
    return 0;
}
