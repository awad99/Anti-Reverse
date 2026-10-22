// exe-protector — educational software-protection demonstrator (stage 1: inspector)
//
// Stage 1 goal: a native Win32 GUI that lets you pick any .exe and inspect its
// PE layout (headers, sections, imports). This is the read-only foundation a
// packer/protector needs before it can transform a binary. Later stages will
// add protection passes (section encryption + stub loader, self-integrity and
// anti-debug checks) for protecting software you own, the same category of tool
// as UPX / VMProtect.
//
// All user-visible string literals are encrypted at compile time via OBF(...)
// (see obfuscate.h), so the shipped binary carries ciphertext, not readable
// text — `strings exe-protector.exe` reveals nothing about what it does.
//
// Build (MSYS2 UCRT64). -static makes the .exe self-contained (no libstdc++-6
// / libgcc / libwinpthread DLLs needed to run it); -s strips the symbol table
// so function names do not leak either; obfuscate.h needs C++17:
//   g++ -O2 -std=c++17 -municode -mwindows -static -s -o exe-protector.exe \
//       main.cpp resource.o -lcomdlg32 -lgdi32 -lcomctl32

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <commctrl.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <initializer_list>
#include <utility>
#include "obfuscate.h"

// ---- control IDs ---------------------------------------------------------
enum {
    IDC_PATH = 1001,
    IDC_BROWSE,
    IDC_ENCRYPT,   // encrypt strings
    IDC_ENCCODE,   // encrypt code section
    IDC_PROTECT,   // both passes in one click
    IDC_INFO,
};

static HFONT g_uiFont   = nullptr;  // Segoe UI for labels / buttons
static HFONT g_monoFont = nullptr;  // Consolas for the report pane
static HWND  g_hPath    = nullptr;
static HWND  g_hInfo    = nullptr;
static std::wstring g_currentPath;   // the .exe currently loaded in the inspector

// ---- small formatting helpers -------------------------------------------
static std::wstring Hex(unsigned long long v, int width = 0) {
    std::wostringstream os;
    os << L"0x" << std::uppercase << std::hex;
    if (width) os << std::setw(width) << std::setfill(L'0');
    os << v;
    return os.str();
}

// Append "NAME" for each bit set in `value`, from a {bit, name} list. The names
// arrive already decrypted (OBF temporaries converted to wstring at the call
// site), so no plaintext flag name is ever stored in the binary.
static std::wstring DecodeFlags(
        unsigned long value,
        std::initializer_list<std::pair<unsigned long, const wchar_t*>> tbl) {
    // Each name is an OBF temporary that stays alive for the whole statement
    // that builds the list, so reading its pointer here is safe; we copy the
    // ones we keep into `out` before the temporaries are destroyed.
    std::wstring out;
    for (const auto& e : tbl) {
        if (value & e.first) {
            if (!out.empty()) out += L" | ";
            out += e.second;
        }
    }
    return out.empty() ? OBF(L"(none)").str() : out;
}

static std::wstring MachineName(WORD m) {
    switch (m) {
        case IMAGE_FILE_MACHINE_I386:  return OBF(L"x86 (i386)").str();
        case IMAGE_FILE_MACHINE_AMD64: return OBF(L"x64 (AMD64)").str();
        case IMAGE_FILE_MACHINE_ARM:   return OBF(L"ARM").str();
        case IMAGE_FILE_MACHINE_ARM64: return OBF(L"ARM64").str();
        case IMAGE_FILE_MACHINE_IA64:  return OBF(L"IA64").str();
        default:                       return OBF(L"unknown").str();
    }
}

static std::wstring SubsystemName(WORD s) {
    switch (s) {
        case IMAGE_SUBSYSTEM_WINDOWS_GUI: return OBF(L"Windows GUI").str();
        case IMAGE_SUBSYSTEM_WINDOWS_CUI: return OBF(L"Windows console (CUI)").str();
        case IMAGE_SUBSYSTEM_NATIVE:      return OBF(L"Native").str();
        case IMAGE_SUBSYSTEM_EFI_APPLICATION: return OBF(L"EFI application").str();
        default:                          return OBF(L"other").str();
    }
}

// ---- file loading --------------------------------------------------------
static bool LoadFileBytes(const std::wstring& path, std::vector<BYTE>& out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (1LL << 31)) {
        CloseHandle(h);
        return false;
    }
    out.resize(static_cast<size_t>(sz.QuadPart));
    DWORD read = 0;
    BOOL ok = ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &read, nullptr);
    CloseHandle(h);
    return ok && read == out.size();
}

// Map an RVA to a raw file offset using the section table. Returns 0 on miss.
static DWORD RvaToOffset(DWORD rva, const IMAGE_SECTION_HEADER* sec, WORD n) {
    for (WORD i = 0; i < n; ++i) {
        DWORD va  = sec[i].VirtualAddress;
        DWORD vsz = sec[i].Misc.VirtualSize;
        DWORD rsz = sec[i].SizeOfRawData;
        DWORD span = (vsz > rsz) ? vsz : rsz;
        if (rva >= va && rva < va + span)
            return sec[i].PointerToRawData + (rva - va);
    }
    return 0;
}

// Shannon entropy (bits/byte, 0..8) over a byte range. High values (~7.5+)
// mean the bytes look random — a strong hint the section is compressed or
// encrypted, i.e. already packed.
static double ShannonEntropy(const BYTE* p, size_t n) {
    if (!n) return 0.0;
    size_t freq[256] = {0};
    for (size_t i = 0; i < n; ++i) freq[p[i]]++;
    double h = 0.0;
    for (int i = 0; i < 256; ++i) if (freq[i]) {
        double pr = (double)freq[i] / (double)n;
        h -= pr * std::log2(pr);
    }
    return h;
}

// Classic hex+ASCII dump of up to `n` bytes, 16 per row.
static void AppendHexDump(std::wostringstream& r, const BYTE* p, size_t n) {
    for (size_t row = 0; row < n; row += 16) {
        r << L"  " << Hex(row, 8) << L"  ";
        for (size_t c = 0; c < 16; ++c) {
            if (row + c < n) {
                static const wchar_t* H = L"0123456789ABCDEF";
                BYTE b = p[row + c];
                r << H[b >> 4] << H[b & 0xF] << L' ';
            } else r << L"   ";
            if (c == 7) r << L' ';
        }
        r << L' ';
        for (size_t c = 0; c < 16 && row + c < n; ++c) {
            BYTE b = p[row + c];
            r << (wchar_t)((b >= 0x20 && b < 0x7F) ? b : '.');
        }
        r << L"\r\n";
    }
}

// ---- the inspector -------------------------------------------------------
static std::wstring AnalyzePE(const std::wstring& path) {
    std::wostringstream r;
    std::vector<BYTE> buf;
    if (!LoadFileBytes(path, buf)) return OBF(L"Could not read the file.").str();

    const size_t size = buf.size();
    const BYTE*  base = buf.data();
    auto in = [&](size_t off, size_t len) { return off + len <= size; };

    r << OBF(L"File : ") << path << L"\r\n";
    r << OBF(L"Size : ") << size << OBF(L" bytes (") << Hex(size) << L")\r\n\r\n";

    if (!in(0, sizeof(IMAGE_DOS_HEADER)))
        return r.str() + OBF(L"Too small to be a PE file.").c_str();
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return r.str() + OBF(L"Not a PE file (missing 'MZ' signature).").c_str();

    r << OBF(L"== DOS header ==\r\n");
    r << OBF(L"  e_lfanew : ") << Hex(dos->e_lfanew) << OBF(L"  (offset of PE header)\r\n\r\n");

    DWORD peOff = dos->e_lfanew;
    if (!in(peOff, 4) || *reinterpret_cast<const DWORD*>(base + peOff) != IMAGE_NT_SIGNATURE)
        return r.str() + OBF(L"Not a PE file (missing 'PE\\0\\0' signature).").c_str();

    DWORD fhOff = peOff + 4;
    if (!in(fhOff, sizeof(IMAGE_FILE_HEADER)))
        return r.str() + OBF(L"Truncated: file header is cut off.").c_str();
    auto fh = reinterpret_cast<const IMAGE_FILE_HEADER*>(base + fhOff);

    r << OBF(L"== File header ==\r\n");
    r << OBF(L"  Machine        : ") << Hex(fh->Machine) << L"  " << MachineName(fh->Machine) << L"\r\n";
    r << OBF(L"  Sections       : ") << fh->NumberOfSections << L"\r\n";
    r << OBF(L"  TimeDateStamp  : ") << Hex(fh->TimeDateStamp) << L"\r\n";
    r << OBF(L"  OptHeader size : ") << fh->SizeOfOptionalHeader << OBF(L" bytes\r\n");
    r << OBF(L"  Characteristics: ") << DecodeFlags(fh->Characteristics, {
        { IMAGE_FILE_EXECUTABLE_IMAGE,    OBF(L"EXECUTABLE") },
        { IMAGE_FILE_DLL,                 OBF(L"DLL") },
        { IMAGE_FILE_LARGE_ADDRESS_AWARE, OBF(L"LARGE_ADDRESS_AWARE") },
        { IMAGE_FILE_32BIT_MACHINE,       OBF(L"32BIT_MACHINE") },
        { IMAGE_FILE_RELOCS_STRIPPED,     OBF(L"RELOCS_STRIPPED") },
        { IMAGE_FILE_DEBUG_STRIPPED,      OBF(L"DEBUG_STRIPPED") },
    }) << L"\r\n\r\n";

    DWORD ohOff = fhOff + sizeof(IMAGE_FILE_HEADER);
    if (!in(ohOff, sizeof(WORD)))
        return r.str() + OBF(L"Truncated: optional header is cut off.").c_str();
    WORD magic = *reinterpret_cast<const WORD*>(base + ohOff);

    DWORD entry = 0, subsystem = 0, dllChar = 0;
    unsigned long long imageBase = 0, sizeOfImage = 0;
    const IMAGE_DATA_DIRECTORY* dirs = nullptr;
    DWORD numDirs = 0;

    r << OBF(L"== Optional header ==\r\n");
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (!in(ohOff, sizeof(IMAGE_OPTIONAL_HEADER32)))
            return r.str() + OBF(L"Truncated: 32-bit optional header is cut off.").c_str();
        auto oh = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(base + ohOff);
        entry = oh->AddressOfEntryPoint; imageBase = oh->ImageBase;
        sizeOfImage = oh->SizeOfImage; subsystem = oh->Subsystem;
        dllChar = oh->DllCharacteristics;
        dirs = oh->DataDirectory; numDirs = oh->NumberOfRvaAndSizes;
        r << OBF(L"  Format         : PE32 (32-bit)\r\n");
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (!in(ohOff, sizeof(IMAGE_OPTIONAL_HEADER64)))
            return r.str() + OBF(L"Truncated: 64-bit optional header is cut off.").c_str();
        auto oh = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(base + ohOff);
        entry = oh->AddressOfEntryPoint; imageBase = oh->ImageBase;
        sizeOfImage = oh->SizeOfImage; subsystem = oh->Subsystem;
        dllChar = oh->DllCharacteristics;
        dirs = oh->DataDirectory; numDirs = oh->NumberOfRvaAndSizes;
        r << OBF(L"  Format         : PE32+ (64-bit)\r\n");
    } else {
        return r.str() + OBF(L"Unknown optional header magic ").c_str() + Hex(magic) + L".";
    }
    r << OBF(L"  Entry point RVA: ") << Hex(entry) << L"\r\n";
    r << OBF(L"  Image base     : ") << Hex(imageBase) << L"\r\n";
    r << OBF(L"  Size of image  : ") << Hex(sizeOfImage) << L"\r\n";
    r << OBF(L"  Subsystem      : ") << subsystem << L"  (" << SubsystemName((WORD)subsystem) << L")\r\n";
    r << OBF(L"  DLL characteri.: ") << DecodeFlags(dllChar, {
        { IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,    OBF(L"DYNAMIC_BASE (ASLR)") },
        { IMAGE_DLLCHARACTERISTICS_NX_COMPAT,       OBF(L"NX_COMPAT (DEP)") },
        { IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, OBF(L"HIGH_ENTROPY_VA") },
        { IMAGE_DLLCHARACTERISTICS_GUARD_CF,        OBF(L"GUARD_CF (CFG)") },
        { IMAGE_DLLCHARACTERISTICS_NO_SEH,          OBF(L"NO_SEH") },
        { IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, OBF(L"FORCE_INTEGRITY") },
    }) << L"\r\n\r\n";

    // Section table follows the optional header.
    DWORD secOff = ohOff + fh->SizeOfOptionalHeader;
    WORD  nSec   = fh->NumberOfSections;
    if (!in(secOff, (size_t)nSec * sizeof(IMAGE_SECTION_HEADER)))
        return r.str() + OBF(L"Truncated: section table is cut off.").c_str();
    auto sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(base + secOff);

    r << OBF(L"== Sections (") << nSec << OBF(L") ==\r\n");
    r << OBF(L"  Name       VirtAddr    VirtSize    RawSize     Entropy  Flags\r\n");
    for (WORD i = 0; i < nSec; ++i) {
        wchar_t name[9] = {0};
        for (int k = 0; k < 8; ++k)
            name[k] = sec[i].Name[k] ? (wchar_t)sec[i].Name[k] : L' ';

        double ent = 0.0;
        DWORD ro = sec[i].PointerToRawData, rn = sec[i].SizeOfRawData;
        if (rn && ro < size) {
            if ((size_t)ro + rn > size) rn = (DWORD)(size - ro);
            ent = ShannonEntropy(base + ro, rn);
        }
        std::wostringstream es;
        es << std::fixed << std::setprecision(2) << ent << (ent > 7.0 ? L"*" : L" ");

        r << L"  " << name << L"  "
          << std::left << std::setw(10) << Hex(sec[i].VirtualAddress) << L"  "
          << std::setw(10) << Hex(sec[i].Misc.VirtualSize)           << L"  "
          << std::setw(10) << Hex(sec[i].SizeOfRawData)              << L"  "
          << std::setw(7)  << es.str()                               << L"  "
          << DecodeFlags(sec[i].Characteristics, {
                 { IMAGE_SCN_CNT_CODE,               OBF(L"CODE") },
                 { IMAGE_SCN_CNT_INITIALIZED_DATA,   OBF(L"IDATA") },
                 { IMAGE_SCN_CNT_UNINITIALIZED_DATA, OBF(L"UDATA") },
                 { IMAGE_SCN_MEM_EXECUTE,            OBF(L"EXEC") },
                 { IMAGE_SCN_MEM_READ,               OBF(L"READ") },
                 { IMAGE_SCN_MEM_WRITE,              OBF(L"WRITE") },
             }) << std::right << L"\r\n";
    }
    r << OBF(L"  (* entropy > 7.0 — section looks compressed or encrypted)\r\n\r\n");

    // Imported DLLs (data directory 1).
    r << OBF(L"== Imported DLLs ==\r\n");
    if (numDirs > IMAGE_DIRECTORY_ENTRY_IMPORT &&
        dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
        DWORD impOff = RvaToOffset(dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, sec, nSec);
        int count = 0;
        while (impOff && in(impOff, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
            auto imp = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + impOff);
            if (imp->Name == 0 && imp->FirstThunk == 0) break;
            DWORD nameOff = RvaToOffset(imp->Name, sec, nSec);
            if (nameOff && nameOff < size) {
                const char* dll = reinterpret_cast<const char*>(base + nameOff);
                size_t maxLen = size - nameOff, len = 0;
                while (len < maxLen && dll[len]) ++len;
                std::string s(dll, len);
                r << L"  " << std::wstring(s.begin(), s.end()) << L"\r\n";
            }
            impOff += sizeof(IMAGE_IMPORT_DESCRIPTOR);
            if (++count > 256) { r << OBF(L"  ...(truncated)\r\n"); break; }
        }
        if (count == 0) r << OBF(L"  (none resolved)\r\n");
    } else {
        r << OBF(L"  (no import directory)\r\n");
    }

    // Raw header bytes — handy for eyeballing the MZ stub and PE structures.
    size_t dumpN = size < 240 ? size : 240;
    r << OBF(L"\r\n== Header hex (first ") << dumpN << OBF(L" bytes) ==\r\n");
    AppendHexDump(r, base, dumpN);

    return r.str();
}

// ===========================================================================
//  String-encryption pass — the "Encrypt strings" button.
//
//  This is the strcrypt packer built into the GUI. It takes the loaded x64 .exe,
//  XOR-encrypts the ASCII / UTF-16 string runs in its .rdata / .data sections,
//  and appends a tiny decryptor stub (a new ".pak" section) that runs before the
//  original entry point, restores the strings in memory, then jumps to the real
//  code. On disk the protected file shows ciphertext where the strings were, so
//  `strings` / a hex editor reveal nothing. For protecting software you own; the
//  standalone CLI equivalent (and the annotated stub source) lives in strcrypt.cpp.
// ===========================================================================

// Decryptor stub machine code. Placeholders patched at pack time:
//   offset 2  : u64  absolute VA of the range table
//   offset 11 : u32  number of ranges
//   offset 88 : u64  absolute VA of the original entry point
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
static const size_t kStubLen  = sizeof(kStub);
static const size_t kOffTable = 2;
static const size_t kOffCount = 11;
static const size_t kOffOep   = 88;
static const size_t kCoreLen  = 86;   // kStub up to (not incl.) the movabs rax/jmp tail ("done")

// The code-encryption pass runs the SAME decrypt core as a TLS callback instead
// of at the entry point, so it fires before the target's own TLS callbacks and
// its real entry (most compiled exes have TLS callbacks). A TLS callback is
// callback(PVOID,DWORD Reason,PVOID) — Reason in edx — and fires at attach AND
// detach, so we decrypt only on DLL_PROCESS_ATTACH (1) and `ret` otherwise, or
// the detach call would XOR the code a second time and re-encrypt it on exit.
// The decrypt core is byte-identical to kStub's; only the framing differs, so
// the core's internal relative branches stay valid.
static std::vector<BYTE> MakeTlsStub(size_t& offTable, size_t& offCount) {
    std::vector<BYTE> s = {
        0x83,0xfa,0x01,   // cmp edx, 1 (DLL_PROCESS_ATTACH)
        0x74,0x01,        // je +1  (into push rsi)
        0xc3,             // ret    (other reasons: do nothing)
        0x56,             // push rsi
        0x57,             // push rdi
    };
    s.insert(s.end(), kStub, kStub + kCoreLen);  // shared decrypt core (ends at "done")
    s.push_back(0x5f);    // pop rdi
    s.push_back(0x5e);    // pop rsi
    s.push_back(0xc3);    // ret
    offTable = 8 + kOffTable;   // 6-byte guard + push rsi/rdi + core table offset
    offCount = 8 + kOffCount;
    return s;
}

// Keystream must match the stub exactly: advance xorshift32, then use low byte.
static inline uint32_t xorshift32(uint32_t x) {
    x ^= x << 13; x ^= x >> 17; x ^= x << 5; return x;
}

struct PackRange { uint32_t rva; uint32_t len; uint32_t seed; uint32_t fileOff; };
struct PackSpan  { uint32_t beg; uint32_t end; };   // [beg,end) in RVA space
struct PackResult { bool ok; std::wstring message; };

static bool PackOverlaps(const std::vector<PackSpan>& ex, uint32_t beg, uint32_t end) {
    for (const auto& s : ex) if (beg < s.end && s.beg < end) return true;
    return false;
}

static bool WriteFileBytes(const std::wstring& path, const std::vector<BYTE>& data) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD wrote = 0;
    BOOL ok = WriteFile(h, data.data(), (DWORD)data.size(), &wrote, nullptr);
    CloseHandle(h);
    return ok && wrote == data.size();
}

// Encrypt the string runs of `inPath` and write a protected copy to `outPath`.
// Returns {ok, human-readable message}; never throws, never exits.
static PackResult PackStrings(const std::wstring& inPath, const std::wstring& outPath) {
    auto err = [](std::wstring m) { return PackResult{ false, std::move(m) }; };

    std::vector<BYTE> img;
    if (!LoadFileBytes(inPath, img)) return err(OBF(L"Could not read the input file.").str());

    auto at = [&](size_t off) -> BYTE* { return img.data() + off; };
    auto in = [&](size_t off, size_t len) { return off + len <= img.size(); };

    // ---- parse + validate headers --------------------------------------
    if (!in(0, sizeof(IMAGE_DOS_HEADER))) return err(OBF(L"File is too small to be a PE.").str());
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(at(0));
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return err(OBF(L"Not a PE file (missing 'MZ').").str());
    DWORD peOff = dos->e_lfanew;
    if (!in(peOff, sizeof(IMAGE_NT_HEADERS64))) return err(OBF(L"Not a PE file (truncated).").str());
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(at(peOff));
    if (nt->Signature != IMAGE_NT_SIGNATURE) return err(OBF(L"Not a PE file (missing 'PE\\0\\0').").str());
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return err(OBF(L"Only x64 (AMD64) executables are supported.").str());
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return err(OBF(L"Only PE32+ (64-bit) is supported.").str());
    if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL)
        return err(OBF(L"DLLs are not supported (EXE only).").str());

    IMAGE_OPTIONAL_HEADER64& opt = nt->OptionalHeader;
    if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR &&
        opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress)
        return err(OBF(L".NET assemblies are not supported.").str());

    const uint64_t imageBase = opt.ImageBase;
    const uint32_t fileAlign = opt.FileAlignment;
    const uint32_t secAlign  = opt.SectionAlignment;
    auto alignUp = [](uint64_t v, uint64_t a) { return (v + a - 1) / a * a; };

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    const WORD nSec = nt->FileHeader.NumberOfSections;
    for (WORD i = 0; i < nSec; ++i)
        if (std::memcmp(sec[i].Name, ".pak", 4) == 0)
            return err(OBF(L"This file is already packed by exe-protector.").str());

    // RVA -> file offset (headers map 1:1 below SizeOfHeaders).
    auto rvaToOff = [&](uint32_t rva) -> uint32_t {
        if (rva < opt.SizeOfHeaders) return rva;
        for (WORD i = 0; i < nSec; ++i) {
            uint32_t va = sec[i].VirtualAddress;
            uint32_t span = (std::max)(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
            if (rva >= va && rva < va + span) return sec[i].PointerToRawData + (rva - va);
        }
        return 0;
    };

    // ---- build the exclusion list (bytes the loader needs intact) -------
    std::vector<PackSpan> ex;
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
    std::vector<PackRange> ranges;

    auto seedFor = [&](uint32_t rva) {
        uint32_t s = rva * 2246822519u + globalSeed + 0x9e3779b9u;
        return s ? s : 0xA5A5A5A5u;
    };
    auto consider = [&](uint32_t rva, uint32_t fileOff, uint32_t len) {
        if (len < MINLEN) return;
        if (PackOverlaps(ex, rva, rva + len)) return;
        ranges.push_back({ rva, len, seedFor(rva), fileOff });
    };

    std::vector<bool> anyInSection(nSec, false);
    for (WORD i = 0; i < nSec; ++i) {
        bool isData = std::memcmp(sec[i].Name, ".rdata", 6) == 0 ||
                      std::memcmp(sec[i].Name, ".data",  5) == 0;
        if (!isData) continue;
        uint32_t base = sec[i].PointerToRawData;
        uint32_t raw  = sec[i].SizeOfRawData;
        uint32_t vsz  = sec[i].Misc.VirtualSize;
        uint32_t scan = (std::min)(raw, vsz ? vsz : raw);
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

    if (ranges.empty()) return err(OBF(L"No encryptable strings found (nothing to do).").str());

    // Encrypt in place (advance-then-use keystream, matching the stub).
    for (auto& r : ranges) {
        uint32_t st = r.seed;
        for (uint32_t j = 0; j < r.len; ++j) { st = xorshift32(st); img[r.fileOff + j] ^= (uint8_t)st; }
    }
    // Make touched sections writable so the stub can decrypt in memory.
    for (WORD i = 0; i < nSec; ++i)
        if (anyInSection[i]) sec[i].Characteristics |= IMAGE_SCN_MEM_WRITE;

    // ---- lay out the new .pak section (stub + range table) --------------
    const size_t tableSize   = ranges.size() * 16;
    const size_t contentSize = kStubLen + tableSize;

    uint32_t secTabOff = peOff + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader;
    uint32_t secTabEnd = secTabOff + (uint32_t)nSec * sizeof(IMAGE_SECTION_HEADER);
    if (secTabEnd + sizeof(IMAGE_SECTION_HEADER) > opt.SizeOfHeaders)
        return err(OBF(L"No room in the header for a new section (unsupported layout).").str());

    uint32_t maxEnd = 0;
    for (WORD i = 0; i < nSec; ++i)
        maxEnd = (std::max<uint32_t>)(maxEnd, sec[i].VirtualAddress +
                 (std::max)(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData));
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
        std::memcpy(e + 8, &ranges[i].len,  4);
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

    if (!WriteFileBytes(outPath, img)) return err(OBF(L"Could not write the output file.").str());

    uint64_t bytesEnc = 0; for (auto& r : ranges) bytesEnc += r.len;
    std::wostringstream m;
    m << OBF(L"String encryption complete.\r\n\r\n")
      << OBF(L"Encrypted ") << ranges.size() << OBF(L" string run(s), ")
      << bytesEnc << OBF(L" bytes.\r\n")
      << OBF(L"Added a ") << contentSize << OBF(L"-byte .pak decryptor stub.\r\n\r\n")
      << OBF(L"Saved:\r\n") << outPath;
    return PackResult{ true, m.str() };
}

// ===========================================================================
//  Code-encryption pass — the "Encrypt code" button.
//
//  Encrypts the target's code section (.text) in place and appends a decryptor
//  stub (a new ".pakc" section). If the target has TLS callbacks (most compiled
//  exes do) the stub is prepended to the TLS callback array so it runs before
//  any real code; otherwise it is installed at the entry point. The code section
//  is marked writable so the loader maps it RWX and the stub decrypts in place.
//  On disk the code is ciphertext, so IDA's static view shows garbage until the
//  program runs. Composes with PackStrings (.pak vs .pakc; each pass captures the
//  current entry so the stubs chain). Defeats static analysis only — a runtime
//  dump still recovers the code. For protecting software you own.
// ===========================================================================
static PackResult PackCode(const std::wstring& inPath, const std::wstring& outPath) {
    auto err = [](std::wstring m) { return PackResult{ false, std::move(m) }; };

    std::vector<BYTE> img;
    if (!LoadFileBytes(inPath, img)) return err(OBF(L"Could not read the input file.").str());

    auto at = [&](size_t off) -> BYTE* { return img.data() + off; };
    auto in = [&](size_t off, size_t len) { return off + len <= img.size(); };

    // ---- parse + validate headers --------------------------------------
    if (!in(0, sizeof(IMAGE_DOS_HEADER))) return err(OBF(L"File is too small to be a PE.").str());
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(at(0));
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return err(OBF(L"Not a PE file (missing 'MZ').").str());
    DWORD peOff = dos->e_lfanew;
    if (!in(peOff, sizeof(IMAGE_NT_HEADERS64))) return err(OBF(L"Not a PE file (truncated).").str());
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(at(peOff));
    if (nt->Signature != IMAGE_NT_SIGNATURE) return err(OBF(L"Not a PE file (missing 'PE\\0\\0').").str());
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return err(OBF(L"Only x64 (AMD64) executables are supported.").str());
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return err(OBF(L"Only PE32+ (64-bit) is supported.").str());
    if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL)
        return err(OBF(L"DLLs are not supported (EXE only).").str());

    IMAGE_OPTIONAL_HEADER64& opt = nt->OptionalHeader;
    if (opt.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR &&
        opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress)
        return err(OBF(L".NET assemblies are not supported.").str());

    const uint64_t imageBase = opt.ImageBase;
    const uint32_t fileAlign = opt.FileAlignment;
    const uint32_t secAlign  = opt.SectionAlignment;
    auto alignUp = [](uint64_t v, uint64_t a) { return (v + a - 1) / a * a; };

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    const WORD nSec = nt->FileHeader.NumberOfSections;
    for (WORD i = 0; i < nSec; ++i)
        if (std::memcmp(sec[i].Name, ".pakc", 5) == 0)
            return err(OBF(L"This file is already code-encrypted.").str());

    auto rvaToOff = [&](uint32_t rva) -> uint32_t {
        if (rva < opt.SizeOfHeaders) return rva;
        for (WORD i = 0; i < nSec; ++i) {
            uint32_t va = sec[i].VirtualAddress;
            uint32_t span = (std::max)(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
            if (rva >= va && rva < va + span) return sec[i].PointerToRawData + (rva - va);
        }
        return 0;
    };

    // ---- gather TLS callbacks (we hook ahead of them, not refuse) -------
    std::vector<uint64_t> tlsCallbacks;
    uint32_t tlsDirFileOff = 0;
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
    std::vector<PackSpan> ex;
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

    // ---- pick the code section (prefer ".text", skip our own stubs) -----
    int codeIdx = -1;
    for (WORD i = 0; i < nSec; ++i) {
        if (std::memcmp(sec[i].Name, ".pak", 4) == 0) continue;   // skip .pak / .pakc
        bool exec = (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool code = (sec[i].Characteristics & IMAGE_SCN_CNT_CODE)    != 0;
        if (!(exec || code)) continue;
        if (std::memcmp(sec[i].Name, ".text\0\0\0", 8) == 0) { codeIdx = i; break; }
        if (codeIdx < 0) codeIdx = i;
    }
    if (codeIdx < 0) return err(OBF(L"No code/.text section found.").str());
    IMAGE_SECTION_HEADER& cs = sec[codeIdx];
    char codeName[9] = {0}; std::memcpy(codeName, cs.Name, 8);   // cs dangles after img.resize()

    uint32_t codeVA  = cs.VirtualAddress;
    uint32_t codeOff = cs.PointerToRawData;
    uint32_t vsz     = cs.Misc.VirtualSize ? cs.Misc.VirtualSize : cs.SizeOfRawData;
    uint32_t codeLen = (std::min<uint32_t>)(cs.SizeOfRawData, vsz);
    if (!codeOff || !codeLen) return err(OBF(L"Code section has no raw data.").str());
    if ((size_t)codeOff + codeLen > img.size()) codeLen = (uint32_t)(img.size() - codeOff);

    // ---- carve the code section into runs that avoid excluded bytes -----
    uint32_t globalSeed = (uint32_t)(opt.AddressOfEntryPoint * 2654435761u + 0x5eed1234u);
    auto seedFor = [&](uint32_t rva) {
        uint32_t s = rva * 2246822519u + globalSeed + 0x9e3779b9u;
        return s ? s : 0xA5A5A5A5u;
    };
    std::vector<PackRange> ranges;
    uint32_t endRVA = codeVA + codeLen;
    for (uint32_t p = codeVA; p < endRVA;) {
        bool inside = false; uint32_t curEnd = p, nextBeg = endRVA;
        for (auto& s : ex) {
            if (p >= s.beg && p < s.end) { inside = true; if (s.end > curEnd) curEnd = s.end; }
            else if (s.beg > p && s.beg < nextBeg) nextBeg = s.beg;
        }
        if (inside) { p = (std::min)(curEnd, endRVA); continue; }
        uint32_t runEnd = (std::min)(nextBeg, endRVA);
        if (runEnd > p) ranges.push_back({ p, runEnd - p, seedFor(p), codeOff + (p - codeVA) });
        p = runEnd;
    }
    if (ranges.empty()) return err(OBF(L"Nothing encryptable in the code section.").str());

    // ---- encrypt in place (advance-then-use keystream, matches the stub) -
    for (auto& r : ranges) {
        uint32_t st = r.seed;
        for (uint32_t j = 0; j < r.len; ++j) { st = xorshift32(st); img[r.fileOff + j] ^= (uint8_t)st; }
    }
    cs.Characteristics |= IMAGE_SCN_MEM_WRITE;   // let the loader map .text RWX

    // ---- assemble the .pakc section (stub + table [+ TLS callback array]) -
    size_t offT, offC;
    std::vector<BYTE> stub = hookTls ? MakeTlsStub(offT, offC)
                                     : std::vector<BYTE>(kStub, kStub + kStubLen);
    if (!hookTls) { offT = kOffTable; offC = kOffCount; }

    const size_t stubLen     = stub.size();
    const size_t tableSize   = ranges.size() * 16;
    const size_t cbArrSize   = hookTls ? (tlsCallbacks.size() + 2) * 8 : 0;
    const size_t contentSize = stubLen + tableSize + cbArrSize;

    uint32_t secTabOff = peOff + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader;
    uint32_t secTabEnd = secTabOff + (uint32_t)nSec * sizeof(IMAGE_SECTION_HEADER);
    if (secTabEnd + sizeof(IMAGE_SECTION_HEADER) > opt.SizeOfHeaders)
        return err(OBF(L"No room in the header for a new section (unsupported layout).").str());

    uint32_t maxEnd = 0;
    for (WORD i = 0; i < nSec; ++i)
        maxEnd = (std::max<uint32_t>)(maxEnd, sec[i].VirtualAddress +
                 (std::max)(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData));
    uint32_t newVA  = (uint32_t)alignUp(maxEnd, secAlign);
    uint32_t rawPtr = (uint32_t)alignUp(img.size(), fileAlign);
    uint32_t rawSz  = (uint32_t)alignUp(contentSize, fileAlign);

    uint64_t tableVA = imageBase + newVA + stubLen;
    uint64_t oepVA   = imageBase + opt.AddressOfEntryPoint;   // current entry (chains)

    std::vector<BYTE> content(contentSize, 0);
    std::memcpy(content.data(), stub.data(), stubLen);
    std::memcpy(content.data() + offT, &tableVA, 8);
    uint32_t cnt = (uint32_t)ranges.size();
    std::memcpy(content.data() + offC, &cnt, 4);
    if (!hookTls) std::memcpy(content.data() + kOffOep, &oepVA, 8);
    for (size_t i = 0; i < ranges.size(); ++i) {
        uint64_t absVA = imageBase + ranges[i].rva;
        BYTE* e = content.data() + stubLen + i * 16;
        std::memcpy(e + 0, &absVA, 8);
        std::memcpy(e + 8, &ranges[i].len,  4);
        std::memcpy(e + 12, &ranges[i].seed, 4);
    }
    uint64_t newCbArrVA = 0;
    if (hookTls) {
        BYTE* a = content.data() + stubLen + tableSize;
        uint64_t mine = imageBase + newVA;                   // our callback = stub start
        std::memcpy(a, &mine, 8);
        for (size_t i = 0; i < tlsCallbacks.size(); ++i)
            std::memcpy(a + (i + 1) * 8, &tlsCallbacks[i], 8);
        newCbArrVA = imageBase + newVA + stubLen + tableSize;  // trailing 8 bytes = null terminator
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
    if (!hookTls) opt.AddressOfEntryPoint = newVA;   // entry-point form: run the stub first

    img.resize(rawPtr + rawSz, 0);
    std::memcpy(img.data() + rawPtr, content.data(), contentSize);
    if (hookTls) {   // repoint the callback array at our prepended copy (after resize)
        size_t cbField = tlsDirFileOff + offsetof(IMAGE_TLS_DIRECTORY64, AddressOfCallBacks);
        std::memcpy(img.data() + cbField, &newCbArrVA, 8);
    }

    if (!WriteFileBytes(outPath, img)) return err(OBF(L"Could not write the output file.").str());

    uint64_t bytesEnc = 0; for (auto& r : ranges) bytesEnc += r.len;
    std::wstring secW;
    for (int i = 0; i < 8 && codeName[i]; ++i) secW += (wchar_t)(unsigned char)codeName[i];
    std::wostringstream m;
    m << OBF(L"Code encryption complete.\r\n\r\n")
      << OBF(L"Encrypted section \"") << secW << OBF(L"\": ")
      << bytesEnc << OBF(L" bytes in ") << ranges.size() << OBF(L" run(s).\r\n")
      << OBF(L"Decryptor hooked via ")
      << (hookTls ? OBF(L"a TLS callback (ahead of the target's own).\r\n").str()
                  : OBF(L"the entry point.\r\n").str())
      << OBF(L"Added a ") << contentSize << OBF(L"-byte .pakc stub.\r\n\r\n")
      << OBF(L"Saved:\r\n") << outPath;
    return PackResult{ true, m.str() };
}

// Suggest "<name><suffix>.exe" next to the input, for the Save dialog.
static std::wstring DefaultOutputName(const std::wstring& in, const wchar_t* suffix) {
    size_t dot   = in.find_last_of(L'.');
    size_t slash = in.find_last_of(L"\\/");
    std::wstring stem = (dot != std::wstring::npos &&
                         (slash == std::wstring::npos || dot > slash))
                        ? in.substr(0, dot) : in;
    return stem + suffix + L".exe";
}

// ---- UI ------------------------------------------------------------------
static std::wstring SaveProtectedAs(HWND owner, const std::wstring& suggested) {
    wchar_t file[MAX_PATH] = {0};
    lstrcpynW(file, suggested.c_str(), MAX_PATH);
    auto filter = OBF(L"Executable files (*.exe)\0*.exe\0All files (*.*)\0*.*\0");
    auto title  = OBF(L"Save the protected executable as");
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = owner;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile   = file;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrTitle  = title;
    ofn.lpstrDefExt = L"exe";
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    if (GetSaveFileNameW(&ofn)) return file;
    return L"";
}

// A unique scratch path in %TEMP%, used to hold the intermediate when the
// "Protect (both)" button chains the two passes (PackStrings -> PackCode).
static std::wstring MakeTempExe() {
    wchar_t dir[MAX_PATH]; DWORD n = GetTempPathW(MAX_PATH, dir);
    if (!n || n > MAX_PATH) return L"";
    wchar_t file[MAX_PATH];
    if (!GetTempFileNameW(dir, L"exp", 0, file)) return L"";
    return file;
}

static std::wstring BrowseForExe(HWND owner) {
    wchar_t file[MAX_PATH] = {0};
    // Named locals: the filter (with its embedded NULs) and title must stay
    // alive for the whole GetOpenFileNameW call, not just one sub-expression.
    auto filter = OBF(L"Executable files (*.exe)\0*.exe\0All files (*.*)\0*.*\0");
    auto title  = OBF(L"Select an executable to inspect");
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = owner;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile   = file;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrTitle  = title;
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    if (GetOpenFileNameW(&ofn)) return file;
    return L"";
}

static void LayoutChildren(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    const int pad = 10, browseW = 90, protW = 140, rowH = 26, gap = 8;
    int w = rc.right - rc.left, h = rc.bottom - rc.top;
    // Row 1: path edit + Browse.
    MoveWindow(g_hPath, pad, pad, w - browseW - 3 * pad, rowH, TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_BROWSE), w - browseW - pad, pad, browseW, rowH, TRUE);
    // Row 2: the combined pass (primary) then the two individual passes.
    int row2 = pad + rowH + pad;
    int x = pad;
    MoveWindow(GetDlgItem(hwnd, IDC_PROTECT), x, row2, protW, rowH, TRUE); x += protW + gap;
    MoveWindow(GetDlgItem(hwnd, IDC_ENCRYPT), x, row2, protW, rowH, TRUE); x += protW + gap;
    MoveWindow(GetDlgItem(hwnd, IDC_ENCCODE), x, row2, protW, rowH, TRUE);
    // Report pane fills the rest.
    int infoY = row2 + rowH + pad;
    MoveWindow(g_hInfo, pad, infoY, w - 2 * pad, h - infoY - pad, TRUE);
}

static void LoadAndShow(const std::wstring& path) {
    g_currentPath = path;
    SetWindowTextW(g_hPath, path.c_str());
    std::wstring report = AnalyzePE(path);
    SetWindowTextW(g_hInfo, report.c_str());
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_uiFont   = CreateFontW(-16, 0,0,0, FW_NORMAL, 0,0,0, DEFAULT_CHARSET,
                                 0,0,0,0, OBF(L"Segoe UI"));
        g_monoFont = CreateFontW(-14, 0,0,0, FW_NORMAL, 0,0,0, DEFAULT_CHARSET,
                                 0,0, PROOF_QUALITY, FIXED_PITCH|FF_MODERN, OBF(L"Consolas"));

        g_hPath = CreateWindowExW(WS_EX_CLIENTEDGE, OBF(L"EDIT"), L"",
            WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL|ES_READONLY,
            0,0,0,0, hwnd, (HMENU)IDC_PATH, nullptr, nullptr);
        CreateWindowExW(0, OBF(L"BUTTON"), OBF(L"Browse…"),
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            0,0,0,0, hwnd, (HMENU)IDC_BROWSE, nullptr, nullptr);
        CreateWindowExW(0, OBF(L"BUTTON"), OBF(L"Encrypt strings"),
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            0,0,0,0, hwnd, (HMENU)IDC_ENCRYPT, nullptr, nullptr);
        CreateWindowExW(0, OBF(L"BUTTON"), OBF(L"Encrypt code"),
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            0,0,0,0, hwnd, (HMENU)IDC_ENCCODE, nullptr, nullptr);
        CreateWindowExW(0, OBF(L"BUTTON"), OBF(L"Protect (both)"),
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON|BS_DEFPUSHBUTTON,
            0,0,0,0, hwnd, (HMENU)IDC_PROTECT, nullptr, nullptr);
        g_hInfo = CreateWindowExW(WS_EX_CLIENTEDGE, OBF(L"EDIT"),
            OBF(L"Click “Browse…”, or drag an .exe onto this window, to see its PE structure.\r\n"
                L"“Protect (both)” encrypts its strings and its code in one step so IDA shows only "
                L"garbage until the program runs — or use “Encrypt strings” / “Encrypt code” on their own."),
            WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
            0,0,0,0, hwnd, (HMENU)IDC_INFO, nullptr, nullptr);

        SendMessageW(g_hPath, WM_SETFONT, (WPARAM)g_uiFont, TRUE);
        SendMessageW(GetDlgItem(hwnd, IDC_BROWSE),  WM_SETFONT, (WPARAM)g_uiFont, TRUE);
        SendMessageW(GetDlgItem(hwnd, IDC_ENCRYPT), WM_SETFONT, (WPARAM)g_uiFont, TRUE);
        SendMessageW(GetDlgItem(hwnd, IDC_ENCCODE), WM_SETFONT, (WPARAM)g_uiFont, TRUE);
        SendMessageW(GetDlgItem(hwnd, IDC_PROTECT), WM_SETFONT, (WPARAM)g_uiFont, TRUE);
        SendMessageW(g_hInfo, WM_SETFONT, (WPARAM)g_monoFont, TRUE);
        DragAcceptFiles(hwnd, TRUE);
        return 0;
    }
    case WM_DROPFILES: {
        HDROP drop = (HDROP)wp;
        wchar_t file[MAX_PATH] = {0};
        if (DragQueryFileW(drop, 0, file, MAX_PATH))
            LoadAndShow(file);
        DragFinish(drop);
        return 0;
    }
    case WM_SIZE:
        LayoutChildren(hwnd);
        return 0;
    case WM_GETMINMAXINFO: {
        auto mmi = reinterpret_cast<MINMAXINFO*>(lp);
        mmi->ptMinTrackSize.x = 520;
        mmi->ptMinTrackSize.y = 360;
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_BROWSE && HIWORD(wp) == BN_CLICKED) {
            std::wstring path = BrowseForExe(hwnd);
            if (!path.empty()) LoadAndShow(path);
            return 0;
        }
        if (LOWORD(wp) == IDC_ENCRYPT && HIWORD(wp) == BN_CLICKED) {
            if (g_currentPath.empty()) {
                MessageBoxW(hwnd, OBF(L"Load an .exe first (Browse… or drag one in)."),
                            OBF(L"Encrypt strings"), MB_OK | MB_ICONINFORMATION);
                return 0;
            }
            std::wstring out = SaveProtectedAs(hwnd, DefaultOutputName(g_currentPath, L"_strenc"));
            if (out.empty()) return 0;   // user cancelled the Save dialog
            PackResult res = PackStrings(g_currentPath, out);
            MessageBoxW(hwnd, res.message.c_str(),
                        res.ok ? OBF(L"Done") : OBF(L"Encrypt strings — failed"),
                        MB_OK | (res.ok ? MB_ICONINFORMATION : MB_ICONERROR));
            if (res.ok) LoadAndShow(out);   // re-inspect the protected copy
            return 0;
        }
        if (LOWORD(wp) == IDC_ENCCODE && HIWORD(wp) == BN_CLICKED) {
            if (g_currentPath.empty()) {
                MessageBoxW(hwnd, OBF(L"Load an .exe first (Browse… or drag one in)."),
                            OBF(L"Encrypt code"), MB_OK | MB_ICONINFORMATION);
                return 0;
            }
            std::wstring out = SaveProtectedAs(hwnd, DefaultOutputName(g_currentPath, L"_codeenc"));
            if (out.empty()) return 0;   // user cancelled the Save dialog
            PackResult res = PackCode(g_currentPath, out);
            MessageBoxW(hwnd, res.message.c_str(),
                        res.ok ? OBF(L"Done") : OBF(L"Encrypt code — failed"),
                        MB_OK | (res.ok ? MB_ICONINFORMATION : MB_ICONERROR));
            if (res.ok) LoadAndShow(out);   // re-inspect the protected copy
            return 0;
        }
        if (LOWORD(wp) == IDC_PROTECT && HIWORD(wp) == BN_CLICKED) {
            if (g_currentPath.empty()) {
                MessageBoxW(hwnd, OBF(L"Load an .exe first (Browse… or drag one in)."),
                            OBF(L"Protect"), MB_OK | MB_ICONINFORMATION);
                return 0;
            }
            std::wstring out = SaveProtectedAs(hwnd, DefaultOutputName(g_currentPath, L"_protected"));
            if (out.empty()) return 0;   // user cancelled the Save dialog
            std::wstring tmp = MakeTempExe();
            if (tmp.empty()) {
                MessageBoxW(hwnd, OBF(L"Could not create a temporary file."),
                            OBF(L"Protect — failed"), MB_OK | MB_ICONERROR);
                return 0;
            }
            // Pass 1: strings -> temp. If it finds nothing (or the file already
            // has strings packed), fall back to code-encrypting the original so
            // "both" still protects what it can.
            PackResult r1 = PackStrings(g_currentPath, tmp);
            std::wstring codeInput = r1.ok ? tmp : g_currentPath;
            // Pass 2: code -> output.
            PackResult r2 = PackCode(codeInput, out);
            DeleteFileW(tmp.c_str());
            if (!r2.ok) {
                MessageBoxW(hwnd, r2.message.c_str(),
                            OBF(L"Protect — failed"), MB_OK | MB_ICONERROR);
                return 0;
            }
            std::wstring msg = r1.ok
                ? OBF(L"Both passes applied — strings and code are now encrypted.\r\n\r\n").str()
                : (OBF(L"Code encrypted. Strings pass was skipped:\r\n").str() + r1.message + L"\r\n\r\n");
            msg += OBF(L"Saved:\r\n").str() + out;
            MessageBoxW(hwnd, msg.c_str(), OBF(L"Done"), MB_OK | MB_ICONINFORMATION);
            LoadAndShow(out);
            return 0;
        }
        break;
    case WM_DESTROY:
        if (g_uiFont)   DeleteObject(g_uiFont);
        if (g_monoFont) DeleteObject(g_monoFont);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nShow) {
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES };
    InitCommonControlsEx(&icc);

    // Named local: the class name must outlive both RegisterClassExW and the
    // CreateWindowExW call below, so bind the decryptor to a variable.
    auto kClassObj = OBF(L"ExeProtectorWindow");
    const wchar_t* kClass = kClassObj;
    WNDCLASSEXW wc = {0};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = kClass;
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(0, kClass, OBF(L"exe-protector — PE inspector + string encryption"),
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 820, 600,
        nullptr, nullptr, hInst, nullptr);
    if (!hwnd) return 1;

    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
