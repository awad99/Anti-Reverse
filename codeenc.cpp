// codeenc — x64 PE code-section encryptor (part of the exe-protector toolset).
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
//     section is already plaintext. This stub ends with `ret` and preserves the
//     non-volatile registers the loader expects (rsi/rdi).
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

// ---- the decryptor core -------------------------------------------------
// Reads 16-byte entries {u64 absVA, u32 len, u32 seed}, XORs each range with an
// xorshift32 keystream (advance-then-use). Two framings share this core:
//
//   kStub      (entry-point form)  : <core> ; movabs rax,OEP ; jmp rax
//   kStubTls   (TLS-callback form) : push rsi;push rdi;<core>;pop rdi;pop rsi;ret
//
// The core's internal relative branches are identical in both, so the TLS form is
// just the entry form with a 2-byte prologue and its 12-byte tail swapped for
// `pop rdi; pop rsi; ret` — nothing between the branches moves.
static const unsigned char kStub[] = {
    0x48,0xbe,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11, // movabs rsi, TABLE   [off 2]
    0xb9,0x22,0x22,0x22,0x22,                          // mov    ecx, COUNT   [off 11]
    0x85,0xc9,0x74,0x43,                               // test ecx,ecx / jz done
    0x48,0x8b,0x3e,0x8b,0x56,0x08,0x8b,0x46,0x0c,      // load absVA,len,seed
    0x48,0x83,0xc6,0x10,                               // add rsi,16
    0x85,0xd2,0x74,0x2e,                               // test edx,edx / jz next
    0x41,0x89,0xc1,0x41,0xc1,0xe1,0x0d,0x44,0x31,0xc8, // xorshift <<13
    0x41,0x89,0xc1,0x41,0xc1,0xe9,0x11,0x44,0x31,0xc8, // xorshift >>17
    0x41,0x89,0xc1,0x41,0xc1,0xe1,0x05,0x44,0x31,0xc8, // xorshift <<5
    0x44,0x8a,0x0f,0x41,0x30,0xc1,0x44,0x88,0x0f,      // *rdi ^= al
    0x48,0xff,0xc7,0xff,0xca,0xeb,0xce,                // inc rdi / dec edx / loop
    0xff,0xc9,0xeb,0xb9,                               // dec ecx / loop      [done = next byte]
    0x48,0xb8,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33, // movabs rax, OEP     [off 88]
    0xff,0xe0,                                         // jmp rax
};
static const size_t kStubLen  = sizeof(kStub);
static const size_t kOffTable = 2;
static const size_t kOffCount = 11;
static const size_t kOffOep   = 88;
static const size_t kCoreLen  = 86;   // kStub up to (not incl.) the movabs rax tail = "done" label

static inline uint32_t xorshift32(uint32_t x) {
    x ^= x << 13; x ^= x >> 17; x ^= x << 5; return x;
}

// Build the TLS-callback framing of the stub. Returns the bytes; sets the table
// and count placeholder offsets within them.
//
// A TLS callback is invoked as callback(PVOID Dll, DWORD Reason, PVOID Reserved)
// — Reason in edx — at process/thread attach AND detach. We must decrypt exactly
// once, so we run only on DLL_PROCESS_ATTACH (1) and `ret` on every other reason;
// otherwise the detach call would XOR .text a second time and re-encrypt it,
// crashing the process on the way out.
static std::vector<uint8_t> MakeTlsStub(size_t& offTable, size_t& offCount) {
    std::vector<uint8_t> s;
    s.push_back(0x83); s.push_back(0xfa); s.push_back(0x01); // cmp edx, 1 (DLL_PROCESS_ATTACH)
    s.push_back(0x74); s.push_back(0x01);                    // je +1  (skip the ret below)
    s.push_back(0xc3);                                       // ret    (other reasons: do nothing)
    s.push_back(0x56);                         // push rsi
    s.push_back(0x57);                         // push rdi
    s.insert(s.end(), kStub, kStub + kCoreLen); // shared core (ends at "done")
    s.push_back(0x5f);                         // pop rdi
    s.push_back(0x5e);                         // pop rsi
    s.push_back(0xc3);                         // ret
    offTable = 8 + kOffTable;                  // 6-byte guard + push rsi/rdi + core off 2 = 10
    offCount = 8 + kOffCount;                  // ... + core off 11 = 19
    return s;
}

struct Range { uint32_t rva; uint32_t len; uint32_t seed; uint32_t fileOff; };
struct Span  { uint32_t beg; uint32_t end; };   // [beg,end) in RVA space

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

    auto at = [&](size_t off) -> uint8_t* { return img.data() + off; };
    auto in = [&](size_t off, size_t len) { return off + len <= img.size(); };

    // ---- parse + validate headers --------------------------------------
    if (!in(0, sizeof(IMAGE_DOS_HEADER))) fail("too small");
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(at(0));
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) fail("not a PE (no MZ)");
    DWORD peOff = dos->e_lfanew;
    if (!in(peOff, sizeof(IMAGE_NT_HEADERS64))) fail("not a PE (truncated)");
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(at(peOff));
    if (nt->Signature != IMAGE_NT_SIGNATURE) fail("not a PE (no PE00)");
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        fail("only x64 (AMD64) executables are supported");
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        fail("only PE32+ (64-bit) is supported");
    if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL)
        fail("DLLs are not supported (EXE only)");

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
        if (std::memcmp(sec[i].Name, ".pakc", 5) == 0) fail("already code-encrypted");

    auto rvaToOff = [&](uint32_t rva) -> uint32_t {
        if (rva < opt.SizeOfHeaders) return rva;
        for (WORD i = 0; i < nSec; ++i) {
            uint32_t va = sec[i].VirtualAddress;
            uint32_t span = std::max(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
            if (rva >= va && rva < va + span) return sec[i].PointerToRawData + (rva - va);
        }
        return 0;
    };

    // ---- gather TLS callbacks (we hook ahead of them, not refuse) -------
    std::vector<uint64_t> tlsCallbacks;
    uint32_t tlsDirFileOff = 0;        // file offset of IMAGE_TLS_DIRECTORY64, 0 if none
    {
        auto& tlsDir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tlsDir.VirtualAddress && tlsDir.Size) {
            uint32_t o = rvaToOff(tlsDir.VirtualAddress);
            if (o && in(o, sizeof(IMAGE_TLS_DIRECTORY64))) {
                auto tls = reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(at(o));
                if (tls->AddressOfCallBacks >= imageBase) {
                    uint32_t arrRva = (uint32_t)(tls->AddressOfCallBacks - imageBase);
                    uint32_t arrOff = rvaToOff(arrRva);
                    for (uint32_t k = 0; arrOff && in(arrOff + k * 8, 8) && k < 4096; ++k) {
                        uint64_t cb; std::memcpy(&cb, at(arrOff + k * 8), 8);
                        if (!cb) break;
                        tlsCallbacks.push_back(cb);
                    }
                    if (!tlsCallbacks.empty()) tlsDirFileOff = o;
                }
            }
        }
    }
    const bool hookTls = tlsDirFileOff != 0;

    // ---- build the loader-critical exclusion list ----------------------
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

    // ---- pick the code section -----------------------------------------
    // Prefer a section literally named ".text"; otherwise the first executable
    // code section that is not one of our own stub sections (.pak / .pakc).
    int codeIdx = -1;
    for (WORD i = 0; i < nSec; ++i) {
        if (std::memcmp(sec[i].Name, ".pak", 4) == 0) continue;   // skip .pak / .pakc stubs
        bool exec = (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool code = (sec[i].Characteristics & IMAGE_SCN_CNT_CODE)    != 0;
        if (!(exec || code)) continue;
        if (std::memcmp(sec[i].Name, ".text\0\0\0", 8) == 0) { codeIdx = i; break; }
        if (codeIdx < 0) codeIdx = i;
    }
    if (codeIdx < 0) fail("no code/.text section found");
    IMAGE_SECTION_HEADER& cs = sec[codeIdx];
    char codeName[9] = {0}; std::memcpy(codeName, cs.Name, 8);  // keep a copy: cs dangles after img.resize()

    uint32_t codeVA  = cs.VirtualAddress;
    uint32_t codeOff = cs.PointerToRawData;
    uint32_t vsz     = cs.Misc.VirtualSize ? cs.Misc.VirtualSize : cs.SizeOfRawData;
    uint32_t codeLen = std::min<uint32_t>(cs.SizeOfRawData, vsz);
    if (!codeOff || !codeLen) fail("code section has no raw data");
    if ((size_t)codeOff + codeLen > img.size()) codeLen = (uint32_t)(img.size() - codeOff);

    // ---- carve the code section into runs that avoid excluded bytes -----
    uint32_t globalSeed = (uint32_t)(opt.AddressOfEntryPoint * 2654435761u + 0x5eed1234u);
    auto seedFor = [&](uint32_t rva) {
        uint32_t s = rva * 2246822519u + globalSeed + 0x9e3779b9u;
        return s ? s : 0xA5A5A5A5u;
    };
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
        if (runEnd > p) ranges.push_back({ p, runEnd - p, seedFor(p), codeOff + (p - codeVA) });
        p = runEnd;
    }
    if (ranges.empty()) fail("nothing encryptable in the code section");

    // ---- encrypt in place (advance-then-use keystream, matches the stub) -
    for (auto& r : ranges) {
        uint32_t st = r.seed;
        for (uint32_t j = 0; j < r.len; ++j) { st = xorshift32(st); img[r.fileOff + j] ^= (uint8_t)st; }
    }
    // Make the code section writable so the stub can decrypt it in memory.
    cs.Characteristics |= IMAGE_SCN_MEM_WRITE;

    // ---- assemble the .pakc section content -----------------------------
    // Layout: [ stub ][ range table ]  (+ [ new TLS callback array ] if hooking TLS).
    size_t offT, offC;
    std::vector<uint8_t> stub = hookTls ? MakeTlsStub(offT, offC)
                                        : std::vector<uint8_t>(kStub, kStub + kStubLen);
    if (!hookTls) { offT = kOffTable; offC = kOffCount; }

    const size_t stubLen   = stub.size();
    const size_t tableSize = ranges.size() * 16;
    const size_t cbArrSize = hookTls ? (tlsCallbacks.size() + 2) * 8 : 0; // mine + olds + null
    const size_t contentSize = stubLen + tableSize + cbArrSize;

    uint32_t secTabOff = peOff + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader;
    uint32_t secTabEnd = secTabOff + (uint32_t)nSec * sizeof(IMAGE_SECTION_HEADER);
    if (secTabEnd + sizeof(IMAGE_SECTION_HEADER) > opt.SizeOfHeaders)
        fail("no room in header for a new section (unsupported layout)");

    uint32_t maxEnd = 0;
    for (WORD i = 0; i < nSec; ++i)
        maxEnd = std::max<uint32_t>(maxEnd, sec[i].VirtualAddress +
                 std::max(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData));
    uint32_t newVA  = (uint32_t)alignUp(maxEnd, secAlign);
    uint32_t rawPtr = (uint32_t)alignUp(img.size(), fileAlign);
    uint32_t rawSz  = (uint32_t)alignUp(contentSize, fileAlign);

    uint64_t tableVA = imageBase + newVA + stubLen;
    uint64_t oepVA   = imageBase + opt.AddressOfEntryPoint;   // current entry (chains)

    std::vector<uint8_t> content(contentSize, 0);
    std::memcpy(content.data(), stub.data(), stubLen);
    std::memcpy(content.data() + offT, &tableVA, 8);
    uint32_t cnt = (uint32_t)ranges.size();
    std::memcpy(content.data() + offC, &cnt, 4);
    if (!hookTls) std::memcpy(content.data() + kOffOep, &oepVA, 8);  // entry form only
    for (size_t i = 0; i < ranges.size(); ++i) {
        uint64_t absVA = imageBase + ranges[i].rva;
        uint8_t* e = content.data() + stubLen + i * 16;
        std::memcpy(e + 0, &absVA, 8);
        std::memcpy(e + 8, &ranges[i].len,  4);
        std::memcpy(e + 12, &ranges[i].seed, 4);
    }
    uint64_t newCbArrVA = 0;
    if (hookTls) {
        uint8_t* a = content.data() + stubLen + tableSize;
        uint64_t mine = imageBase + newVA;                   // our callback = stub start
        std::memcpy(a, &mine, 8);
        for (size_t i = 0; i < tlsCallbacks.size(); ++i)
            std::memcpy(a + (i + 1) * 8, &tlsCallbacks[i], 8);
        // trailing 8 bytes already zero = null terminator
        newCbArrVA = imageBase + newVA + stubLen + tableSize;
    }

    IMAGE_SECTION_HEADER nh = {};
    std::memcpy(nh.Name, ".pakc\0\0", 8);
    nh.Misc.VirtualSize = (DWORD)contentSize;
    nh.VirtualAddress   = newVA;
    nh.SizeOfRawData    = rawSz;
    nh.PointerToRawData = rawPtr;
    nh.Characteristics  = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    std::memcpy(at(secTabEnd), &nh, sizeof(nh));

    nt->FileHeader.NumberOfSections = nSec + 1;
    opt.SizeOfImage = (DWORD)alignUp(newVA + contentSize, secAlign);
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
        size_t cbField = tlsDirFileOff + offsetof(IMAGE_TLS_DIRECTORY64, AddressOfCallBacks);
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
