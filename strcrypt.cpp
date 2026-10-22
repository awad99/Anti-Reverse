// strcrypt — x64 PE string-encryption packer (part of the exe-protector toolset).
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

// ---- the decryptor stub -------------------------------------------------
// Machine code assembled from stub.s (verified with objdump). Placeholders:
//   offset 2  : u64  absolute VA of the range table
//   offset 11 : u32  number of ranges
//   offset 88 : u64  absolute VA of the original entry point
// It reads 16-byte entries {u64 absVA, u32 len, u32 seed}, XORs each range with
// an xorshift32 keystream (advance-then-use), then jumps to the original entry.
static const unsigned char kStub[] = {
    0x48,0xbe,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11, // movabs rsi, TABLE
    0xb9,0x22,0x22,0x22,0x22,                          // mov    ecx, COUNT
    0x85,0xc9,0x74,0x43,                               // test ecx,ecx / jz done
    0x48,0x8b,0x3e,0x8b,0x56,0x08,0x8b,0x46,0x0c,      // load absVA,len,seed
    0x48,0x83,0xc6,0x10,                               // add rsi,16
    0x85,0xd2,0x74,0x2e,                               // test edx,edx / jz next
    0x41,0x89,0xc1,0x41,0xc1,0xe1,0x0d,0x44,0x31,0xc8, // xorshift <<13
    0x41,0x89,0xc1,0x41,0xc1,0xe9,0x11,0x44,0x31,0xc8, // xorshift >>17
    0x41,0x89,0xc1,0x41,0xc1,0xe1,0x05,0x44,0x31,0xc8, // xorshift <<5
    0x44,0x8a,0x0f,0x41,0x30,0xc1,0x44,0x88,0x0f,      // *rdi ^= al
    0x48,0xff,0xc7,0xff,0xca,0xeb,0xce,                // inc rdi / dec edx / loop
    0xff,0xc9,0xeb,0xb9,                               // dec ecx / loop
    0x48,0xb8,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33, // movabs rax, OEP
    0xff,0xe0,                                         // jmp rax
};
static const size_t kStubLen   = sizeof(kStub);
static const size_t kOffTable  = 2;
static const size_t kOffCount  = 11;
static const size_t kOffOep     = 88;

// Keystream must match the stub exactly: advance xorshift32, then use low byte.
static inline uint32_t xorshift32(uint32_t x) {
    x ^= x << 13; x ^= x >> 17; x ^= x << 5; return x;
}

struct Range { uint32_t rva; uint32_t len; uint32_t seed; uint32_t fileOff; };
struct Span  { uint32_t beg; uint32_t end; };   // [beg,end) in RVA space

static bool overlaps(const std::vector<Span>& ex, uint32_t beg, uint32_t end) {
    for (const auto& s : ex) if (beg < s.end && s.beg < end) return true;
    return false;
}

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
        if (std::memcmp(sec[i].Name, ".pak", 4) == 0) fail("already packed");

    // RVA -> file offset (headers map 1:1 below SizeOfHeaders).
    auto rvaToOff = [&](uint32_t rva) -> uint32_t {
        if (rva < opt.SizeOfHeaders) return rva;
        for (WORD i = 0; i < nSec; ++i) {
            uint32_t va = sec[i].VirtualAddress;
            uint32_t span = std::max(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
            if (rva >= va && rva < va + span) return sec[i].PointerToRawData + (rva - va);
        }
        return 0;
    };

    // ---- build the exclusion list (bytes the loader needs intact) -------
    std::vector<Span> ex;
    ex.push_back({ 0, opt.SizeOfHeaders });
    for (DWORD i = 0; i < opt.NumberOfRvaAndSizes && i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
        auto& d = opt.DataDirectory[i];
        if (d.VirtualAddress && d.Size) ex.push_back({ d.VirtualAddress, d.VirtualAddress + d.Size });
    }
    // Walk the import table: INT/IAT arrays, DLL name strings, import-by-name.
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
                        uint32_t ibnOff = rvaToOff(ibnRva), n = 0;   // hint(2) + name
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

    // ---- find + encrypt string runs in .rdata / .data -------------------
    const uint32_t MINLEN = 4;
    uint32_t globalSeed = (uint32_t)(opt.AddressOfEntryPoint * 2654435761u + 0x12345678u);
    std::vector<Range> ranges;

    auto seedFor = [&](uint32_t rva) {
        uint32_t s = rva * 2246822519u + globalSeed + 0x9e3779b9u;
        return s ? s : 0xA5A5A5A5u;
    };
    auto consider = [&](uint32_t rva, uint32_t fileOff, uint32_t len) {
        if (len < MINLEN) return;
        if (overlaps(ex, rva, rva + len)) return;
        ranges.push_back({ rva, len, seedFor(rva), fileOff });
    };

    bool anyInSection[96] = { false };
    for (WORD i = 0; i < nSec; ++i) {
        bool isData = std::memcmp(sec[i].Name, ".rdata", 6) == 0 ||
                      std::memcmp(sec[i].Name, ".data",  5) == 0;
        if (!isData) continue;
        uint32_t base = sec[i].PointerToRawData;
        uint32_t raw  = sec[i].SizeOfRawData;
        uint32_t vsz  = sec[i].Misc.VirtualSize;
        uint32_t scan = std::min(raw, vsz ? vsz : raw);
        if (!base || !in(base, scan)) continue;
        uint32_t vbase = sec[i].VirtualAddress;
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
    for (WORD i = 0; i < nSec; ++i)
        if (anyInSection[i]) sec[i].Characteristics |= IMAGE_SCN_MEM_WRITE;

    // ---- lay out the new .pak section (stub + range table) --------------
    const size_t  tableSize   = ranges.size() * 16;
    const size_t  contentSize = kStubLen + tableSize;

    // room for one more section header?
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

    uint64_t tableVA = imageBase + newVA + kStubLen;
    uint64_t oepVA   = imageBase + opt.AddressOfEntryPoint;

    // Assemble the section content: patched stub + table.
    std::vector<uint8_t> content(contentSize, 0);
    std::memcpy(content.data(), kStub, kStubLen);
    std::memcpy(content.data() + kOffTable, &tableVA, 8);
    uint32_t cnt = (uint32_t)ranges.size();
    std::memcpy(content.data() + kOffCount, &cnt, 4);
    std::memcpy(content.data() + kOffOep,   &oepVA, 8);
    for (size_t i = 0; i < ranges.size(); ++i) {
        uint64_t absVA = imageBase + ranges[i].rva;
        uint8_t* e = content.data() + kStubLen + i * 16;
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
    std::memcpy(at(secTabEnd), &nh, sizeof(nh));

    // Patch the headers.
    nt->FileHeader.NumberOfSections = nSec + 1;
    opt.AddressOfEntryPoint = newVA;                                   // run the stub first
    opt.SizeOfImage = (DWORD)alignUp(newVA + contentSize, secAlign);
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
