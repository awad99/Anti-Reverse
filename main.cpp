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
#include <random>
#include <type_traits>
#include "obfuscate.h"
#include "pak_core.h"
#include "str_core.h"

// ---- control IDs ---------------------------------------------------------
enum {
    IDC_PATH = 1001,
    IDC_BROWSE,
    IDC_ENCRYPT,   // encrypt strings
    IDC_ENCCODE,   // encrypt code section
    IDC_PROTECT,   // all three passes in one click
    IDC_PACK,      // compress + encrypt + anti-debug packer
    IDC_INFO,
    IDC_STATUS,    // bottom status bar
};

static const int kHeaderH = 56;      // accent header band height (px)

static HFONT  g_uiFont    = nullptr; // Segoe UI for labels / buttons
static HFONT  g_monoFont  = nullptr; // Consolas for the report pane
static HFONT  g_titleFont = nullptr; // header title
static HFONT  g_subFont   = nullptr; // header subtitle
static HBRUSH g_accentBrush = nullptr;
static HWND  g_hMain   = nullptr;
static HWND  g_hPath   = nullptr;
static HWND  g_hInfo   = nullptr;
static HWND  g_hStatus = nullptr;
static HWND  g_hTip    = nullptr;
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
    // Share read/write/delete so we can still open a file another program (a
    // debugger, hex editor, AV scan) has open. On failure, preserve the Win32
    // error code across CloseHandle so callers can report why.
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;   // GetLastError set by CreateFileW
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (1LL << 31)) {
        DWORD e = GetLastError(); CloseHandle(h);
        SetLastError(e ? e : ERROR_INVALID_DATA);
        return false;
    }
    out.resize(static_cast<size_t>(sz.QuadPart));
    DWORD read = 0;
    BOOL ok = ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &read, nullptr);
    DWORD e = GetLastError();
    CloseHandle(h);
    if (!(ok && read == out.size())) { SetLastError(e); return false; }
    return true;
}

// LoadFileBytes + a human error message (empty on success) for the input file.
static std::wstring ReadInput(const std::wstring& path, std::vector<BYTE>& out) {
    if (LoadFileBytes(path, out)) return L"";
    DWORD e = GetLastError();
    std::wstring m = OBF(L"Could not read the input file").str();
    if (e == ERROR_SHARING_VIOLATION || e == ERROR_LOCK_VIOLATION)
        m += OBF(L" — it is open or locked in another program (e.g. a debugger). Close it and try again.").str();
    else if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND)
        m += OBF(L" — it may have been moved or deleted.").str();
    else
        m += OBF(L".").str();
    return m;
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
//  This is the strcrypt packer built into the GUI. It takes the loaded .exe (x64
//  or x86), XOR-encrypts the ASCII / UTF-16 string runs in its .rdata / .data,
//  and appends a tiny decryptor stub (a new ".pak" section) that runs before the
//  original entry point, restores the strings in memory, then jumps to the real
//  code. On disk the protected file shows ciphertext where the strings were, so
//  `strings` / a hex editor reveal nothing. For protecting software you own; the
//  standalone CLI equivalent (and the annotated stub source) lives in strcrypt.cpp.
// ===========================================================================

// The decryptor stubs (x64 + x86, entry-point and TLS framings) and the 16-byte
// range table layout live in str_core.h, shared with codeenc. The keystream here
// must match them: advance xorshift32, then use the low byte.
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
template<bool X64>
static PackResult PackStringsImpl(std::vector<BYTE>& img, const std::wstring& outPath) {
    auto err = [](std::wstring m) { return PackResult{ false, std::move(m) }; };
    using NT  = std::conditional_t<X64, IMAGE_NT_HEADERS64,     IMAGE_NT_HEADERS32>;
    using OPT = std::conditional_t<X64, IMAGE_OPTIONAL_HEADER64, IMAGE_OPTIONAL_HEADER32>;
    constexpr int      PW  = X64 ? 8 : 4;
    constexpr uint64_t ORD = X64 ? IMAGE_ORDINAL_FLAG64 : (uint64_t)IMAGE_ORDINAL_FLAG32;

    auto at = [&](size_t off) -> BYTE* { return img.data() + off; };
    auto in = [&](size_t off, size_t len) { return off + len <= img.size(); };

    DWORD peOff = reinterpret_cast<IMAGE_DOS_HEADER*>(at(0))->e_lfanew;
    if (!in(peOff, sizeof(NT))) return err(OBF(L"Not a PE file (truncated).").str());
    auto nt = reinterpret_cast<NT*>(at(peOff));
    if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL)
        return err(OBF(L"DLLs are not supported (EXE only).").str());

    OPT& opt = nt->OptionalHeader;
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
                while (arrOff && in(arrOff + k * PW, PW)) {
                    uint64_t t = 0; std::memcpy(&t, at(arrOff + k * PW), PW);
                    if (!t) break;
                    if (!(t & ORD)) {
                        uint32_t ibnRva = (uint32_t)(t & 0x7fffffff);
                        uint32_t ibnOff = rvaToOff(ibnRva), n = 0;   // hint(2) + name
                        while (ibnOff && in(ibnOff + 2 + n, 1) && img[ibnOff + 2 + n]) ++n;
                        ex.push_back({ ibnRva, ibnRva + 2 + n + 1 });
                    }
                    ++k;
                }
                ex.push_back({ arrRva, arrRva + (k + 1) * PW });
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

        for (uint32_t p = 0; p < scan;) {
            uint8_t c = img[base + p];
            if (c >= 0x20 && c <= 0x7e) {
                uint32_t q = p;
                while (q < scan) { uint8_t d = img[base + q]; if (d < 0x20 || d > 0x7e) break; ++q; }
                consider(vbase + p, base + p, q - p);
                p = q;
            } else ++p;
        }
        for (uint32_t p = 0; p + 1 < scan;) {
            if (img[base + p] >= 0x20 && img[base + p] <= 0x7e && img[base + p + 1] == 0x00) {
                uint32_t q = p;
                while (q + 1 < scan && img[base + q] >= 0x20 && img[base + q] <= 0x7e &&
                       img[base + q + 1] == 0x00) q += 2;
                consider(vbase + p, base + p, q - p);
                p = q;
            } else ++p;
        }
        anyInSection[i] = ranges.size() > before;
    }

    if (ranges.empty()) return err(OBF(L"No encryptable strings found (nothing to do).").str());

    for (auto& r : ranges) {
        uint32_t st = r.seed;
        for (uint32_t j = 0; j < r.len; ++j) { st = xorshift32(st); img[r.fileOff + j] ^= (uint8_t)st; }
    }
    for (WORD i = 0; i < nSec; ++i)
        if (anyInSection[i]) sec[i].Characteristics |= IMAGE_SCN_MEM_WRITE;

    // ---- lay out the new .pak section (stub + range table) --------------
    size_t offT, offC, offO;
    std::vector<uint8_t> stub;
    if constexpr (X64) stub = MakeStrEntryStub(offT, offC, offO);
    else               stub = MakeStrEntryStub32(offT, offC, offO);
    const size_t stubLen     = stub.size();
    const size_t tableSize   = ranges.size() * 16;
    const size_t contentSize = stubLen + tableSize;

    uint32_t secTabOff = peOff + offsetof(NT, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader;
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
    uint64_t oepVA   = imageBase + opt.AddressOfEntryPoint;

    std::vector<uint8_t> content(contentSize, 0);
    std::memcpy(content.data(), stub.data(), stubLen);
    std::memcpy(content.data() + offT, &tableVA, PW);
    uint32_t cnt = (uint32_t)ranges.size();
    std::memcpy(content.data() + offC, &cnt, 4);
    std::memcpy(content.data() + offO, &oepVA, PW);
    for (size_t i = 0; i < ranges.size(); ++i) {
        uint64_t absVA = imageBase + ranges[i].rva;
        uint8_t* e = content.data() + stubLen + i * 16;
        std::memcpy(e + 0, &absVA, 8);
        std::memcpy(e + 8, &ranges[i].len,  4);
        std::memcpy(e + 12, &ranges[i].seed, 4);
    }

    IMAGE_SECTION_HEADER nh = {};
    std::memcpy(nh.Name, ".pak\0\0\0", 8);
    nh.Misc.VirtualSize = (DWORD)contentSize;
    nh.VirtualAddress   = newVA;
    nh.SizeOfRawData    = rawSz;
    nh.PointerToRawData = rawPtr;
    nh.Characteristics  = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    std::memcpy(at(secTabEnd), &nh, sizeof(nh));

    nt->FileHeader.NumberOfSections = nSec + 1;
    opt.AddressOfEntryPoint = newVA;                                   // run the stub first
    opt.SizeOfImage = (DWORD)alignUp(newVA + contentSize, secAlign);
    opt.DllCharacteristics &= ~(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA |
                                IMAGE_DLLCHARACTERISTICS_GUARD_CF);

    img.resize(rawPtr + rawSz, 0);
    std::memcpy(img.data() + rawPtr, content.data(), contentSize);

    if (!WriteFileBytes(outPath, img)) return err(OBF(L"Could not write the output file.").str());

    uint64_t bytesEnc = 0; for (auto& r : ranges) bytesEnc += r.len;
    std::wostringstream m;
    m << OBF(L"String encryption complete (") << (X64 ? OBF(L"x64").str() : OBF(L"x86").str()) << OBF(L").\r\n\r\n")
      << OBF(L"Encrypted ") << ranges.size() << OBF(L" string run(s), ")
      << bytesEnc << OBF(L" bytes.\r\n")
      << OBF(L"Added a ") << contentSize << OBF(L"-byte .pak decryptor stub.\r\n\r\n")
      << OBF(L"Saved:\r\n") << outPath;
    return PackResult{ true, m.str() };
}

// Encrypt the string runs of `inPath` and write a protected copy to `outPath`.
// Supports x64 (PE32+) and x86 (PE32); dispatches on the machine field.
// Returns {ok, human-readable message}; never throws, never exits.
static PackResult PackStrings(const std::wstring& inPath, const std::wstring& outPath) {
    auto err = [](std::wstring m) { return PackResult{ false, std::move(m) }; };
    std::vector<BYTE> img;
    { std::wstring e = ReadInput(inPath, img); if (!e.empty()) return err(e); }
    if (img.size() < sizeof(IMAGE_DOS_HEADER)) return err(OBF(L"File is too small to be a PE.").str());
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(img.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return err(OBF(L"Not a PE file (missing 'MZ').").str());
    DWORD peOff = dos->e_lfanew;
    if ((size_t)peOff + 6 > img.size()) return err(OBF(L"Not a PE file (truncated).").str());
    if (*reinterpret_cast<DWORD*>(img.data() + peOff) != IMAGE_NT_SIGNATURE)
        return err(OBF(L"Not a PE file (missing 'PE\\0\\0').").str());
    WORD machine = *reinterpret_cast<WORD*>(img.data() + peOff + 4);
    if (machine == IMAGE_FILE_MACHINE_AMD64) return PackStringsImpl<true>(img, outPath);
    if (machine == IMAGE_FILE_MACHINE_I386)  return PackStringsImpl<false>(img, outPath);
    return err(OBF(L"Only x64 (AMD64) and x86 (i386) executables are supported.").str());
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
template<bool X64>
static PackResult PackCodeImpl(std::vector<BYTE>& img, const std::wstring& outPath) {
    auto err = [](std::wstring m) { return PackResult{ false, std::move(m) }; };
    using NT  = std::conditional_t<X64, IMAGE_NT_HEADERS64,     IMAGE_NT_HEADERS32>;
    using OPT = std::conditional_t<X64, IMAGE_OPTIONAL_HEADER64, IMAGE_OPTIONAL_HEADER32>;
    using TLS = std::conditional_t<X64, IMAGE_TLS_DIRECTORY64,   IMAGE_TLS_DIRECTORY32>;
    constexpr int      PW  = X64 ? 8 : 4;
    constexpr uint64_t ORD = X64 ? IMAGE_ORDINAL_FLAG64 : (uint64_t)IMAGE_ORDINAL_FLAG32;

    auto at = [&](size_t off) -> BYTE* { return img.data() + off; };
    auto in = [&](size_t off, size_t len) { return off + len <= img.size(); };

    DWORD peOff = reinterpret_cast<IMAGE_DOS_HEADER*>(at(0))->e_lfanew;
    if (!in(peOff, sizeof(NT))) return err(OBF(L"Not a PE file (truncated).").str());
    auto nt = reinterpret_cast<NT*>(at(peOff));
    if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL)
        return err(OBF(L"DLLs are not supported (EXE only).").str());

    OPT& opt = nt->OptionalHeader;
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
            if (o && in(o, sizeof(TLS))) {
                auto tls = reinterpret_cast<TLS*>(at(o));
                if ((uint64_t)tls->AddressOfCallBacks >= imageBase) {
                    uint32_t arrOff = rvaToOff((uint32_t)((uint64_t)tls->AddressOfCallBacks - imageBase));
                    for (uint32_t k = 0; arrOff && in(arrOff + k * PW, PW) && k < 4096; ++k) {
                        uint64_t cb = 0; std::memcpy(&cb, at(arrOff + k * PW), PW);
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
                while (arrOff && in(arrOff + k * PW, PW)) {
                    uint64_t t = 0; std::memcpy(&t, at(arrOff + k * PW), PW);
                    if (!t) break;
                    if (!(t & ORD)) {
                        uint32_t ibnRva = (uint32_t)(t & 0x7fffffff);
                        uint32_t ibnOff = rvaToOff(ibnRva), n = 0;
                        while (ibnOff && in(ibnOff + 2 + n, 1) && img[ibnOff + 2 + n]) ++n;
                        ex.push_back({ ibnRva, ibnRva + 2 + n + 1 });
                    }
                    ++k;
                }
                ex.push_back({ arrRva, arrRva + (k + 1) * PW });
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

    for (auto& r : ranges) {
        uint32_t st = r.seed;
        for (uint32_t j = 0; j < r.len; ++j) { st = xorshift32(st); img[r.fileOff + j] ^= (uint8_t)st; }
    }
    cs.Characteristics |= IMAGE_SCN_MEM_WRITE;   // let the loader map .text RWX

    // ---- assemble the .pakc section (stub + table [+ TLS callback array]) -
    size_t offT, offC, offO = 0;
    std::vector<BYTE> stub;
    if constexpr (X64) stub = hookTls ? MakeStrTlsStub(offT, offC) : MakeStrEntryStub(offT, offC, offO);
    else               stub = hookTls ? MakeStrTlsStub32(offT, offC) : MakeStrEntryStub32(offT, offC, offO);

    const size_t stubLen     = stub.size();
    const size_t tableSize   = ranges.size() * 16;
    const size_t cbArrSize   = hookTls ? (tlsCallbacks.size() + 2) * PW : 0;
    const size_t contentSize = stubLen + tableSize + cbArrSize;

    uint32_t secTabOff = peOff + offsetof(NT, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader;
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
    std::memcpy(content.data() + offT, &tableVA, PW);
    uint32_t cnt = (uint32_t)ranges.size();
    std::memcpy(content.data() + offC, &cnt, 4);
    if (!hookTls) std::memcpy(content.data() + offO, &oepVA, PW);
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
        std::memcpy(a, &mine, PW);
        for (size_t i = 0; i < tlsCallbacks.size(); ++i)
            std::memcpy(a + (i + 1) * PW, &tlsCallbacks[i], PW);
        newCbArrVA = imageBase + newVA + stubLen + tableSize;  // trailing slot = null terminator
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
        size_t cbField = tlsDirFileOff + offsetof(TLS, AddressOfCallBacks);
        std::memcpy(img.data() + cbField, &newCbArrVA, PW);
    }

    if (!WriteFileBytes(outPath, img)) return err(OBF(L"Could not write the output file.").str());

    uint64_t bytesEnc = 0; for (auto& r : ranges) bytesEnc += r.len;
    std::wstring secW;
    for (int i = 0; i < 8 && codeName[i]; ++i) secW += (wchar_t)(unsigned char)codeName[i];
    std::wostringstream m;
    m << OBF(L"Code encryption complete (") << (X64 ? OBF(L"x64").str() : OBF(L"x86").str()) << OBF(L").\r\n\r\n")
      << OBF(L"Encrypted section \"") << secW << OBF(L"\": ")
      << bytesEnc << OBF(L" bytes in ") << ranges.size() << OBF(L" run(s).\r\n")
      << OBF(L"Decryptor hooked via ")
      << (hookTls ? OBF(L"a TLS callback (ahead of the target's own).\r\n").str()
                  : OBF(L"the entry point.\r\n").str())
      << OBF(L"Added a ") << contentSize << OBF(L"-byte .pakc stub.\r\n\r\n")
      << OBF(L"Saved:\r\n") << outPath;
    return PackResult{ true, m.str() };
}

// Encrypt the target's code section and write a protected copy to `outPath`.
// Supports x64 (PE32+) and x86 (PE32); dispatches on the machine field.
static PackResult PackCode(const std::wstring& inPath, const std::wstring& outPath) {
    auto err = [](std::wstring m) { return PackResult{ false, std::move(m) }; };
    std::vector<BYTE> img;
    { std::wstring e = ReadInput(inPath, img); if (!e.empty()) return err(e); }
    if (img.size() < sizeof(IMAGE_DOS_HEADER)) return err(OBF(L"File is too small to be a PE.").str());
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(img.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return err(OBF(L"Not a PE file (missing 'MZ').").str());
    DWORD peOff = dos->e_lfanew;
    if ((size_t)peOff + 6 > img.size()) return err(OBF(L"Not a PE file (truncated).").str());
    if (*reinterpret_cast<DWORD*>(img.data() + peOff) != IMAGE_NT_SIGNATURE)
        return err(OBF(L"Not a PE file (missing 'PE\\0\\0').").str());
    WORD machine = *reinterpret_cast<WORD*>(img.data() + peOff + 4);
    if (machine == IMAGE_FILE_MACHINE_AMD64) return PackCodeImpl<true>(img, outPath);
    if (machine == IMAGE_FILE_MACHINE_I386)  return PackCodeImpl<false>(img, outPath);
    return err(OBF(L"Only x64 (AMD64) and x86 (i386) executables are supported.").str());
}

// ===========================================================================
//  Pack pass — the "Pack" button.
//
//  This is the `pack` packer built into the GUI. It LZSS-compresses the target's
//  non-loader-critical sections (.text/.data), encrypts each compressed blob with
//  the PAKP stream cipher (custom ChaCha-derived ARX; a fresh random 256-bit key
//  per pack, so the output is polymorphic), strips their raw bytes, and appends a
//  self-contained anti-debug + decrypt + decompress stub (a new ".pakp" section).
//  At load the stub checks the PEB for a debugger (folding the result into the
//  key, so a debugged run decrypts to garbage), decrypts, and rebuilds each
//  section in memory, then runs the original program. Statically a tool sees
//  uniform high-entropy data, not code; the file is also smaller. Composes with
//  PackStrings/PackCode (distinct section names; stubs chain). The standalone CLI
//  equivalent and the annotated stub source live in pack.cpp / stub_src.c.
// ===========================================================================

// Compress+encrypt the target and write a packed copy to `outPath`.
// Returns {ok, human-readable message}; never throws, never exits.
// The GUI packer core, parameterized on architecture (same shape as pack.cpp's
// packImpl). X64 => PE32+/AMD64 + the x86-64 stub; !X64 => PE32/i386 + the x86
// stub. Only the header types, the pointer width PW (stub patches, the TLS
// callback array, import thunks, AddressOfCallBacks) and the ordinal flag differ;
// the 32-byte Ent table is identical (32-bit VAs zero-extend into its u64s).
template<bool X64>
static PackResult PackExeImpl(std::vector<BYTE>& img, const std::wstring& outPath) {
    auto err = [](std::wstring m) { return PackResult{ false, std::move(m) }; };
    using NT  = std::conditional_t<X64, IMAGE_NT_HEADERS64,     IMAGE_NT_HEADERS32>;
    using OPT = std::conditional_t<X64, IMAGE_OPTIONAL_HEADER64, IMAGE_OPTIONAL_HEADER32>;
    using TLS = std::conditional_t<X64, IMAGE_TLS_DIRECTORY64,   IMAGE_TLS_DIRECTORY32>;
    constexpr int      PW  = X64 ? 8 : 4;
    constexpr uint64_t ORD = X64 ? IMAGE_ORDINAL_FLAG64 : (uint64_t)IMAGE_ORDINAL_FLAG32;

    auto at = [&](size_t off) -> BYTE* { return img.data() + off; };
    auto in = [&](size_t off, size_t len) { return off + len <= img.size(); };

    DWORD peOff = reinterpret_cast<IMAGE_DOS_HEADER*>(at(0))->e_lfanew;
    if (!in(peOff, sizeof(NT))) return err(OBF(L"Not a PE file (truncated).").str());
    auto nt = reinterpret_cast<NT*>(at(peOff));
    if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL)
        return err(OBF(L"DLLs are not supported (EXE only).").str());

    OPT& opt = nt->OptionalHeader;
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
        if (std::memcmp(sec[i].Name, ".pakp", 5) == 0)
            return err(OBF(L"This file is already packed.").str());

    auto rvaToOff = [&](uint32_t rva) -> uint32_t {
        if (rva < opt.SizeOfHeaders) return rva;
        for (WORD i = 0; i < nSec; ++i) {
            uint32_t va = sec[i].VirtualAddress;
            uint32_t span = (std::max)(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
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
            if (o && in(o, sizeof(TLS))) {
                auto tls = reinterpret_cast<TLS*>(at(o));
                if ((uint64_t)tls->AddressOfCallBacks >= imageBase) {
                    uint32_t arrOff = rvaToOff((uint32_t)((uint64_t)tls->AddressOfCallBacks - imageBase));
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
                while (arrOff && in(arrOff + k * PW, PW)) {
                    uint64_t t = 0; std::memcpy(&t, at(arrOff + k * PW), PW);
                    if (!t) break;
                    if (!(t & ORD)) {
                        uint32_t ibnRva = (uint32_t)(t & 0x7fffffff);
                        uint32_t ibnOff = rvaToOff(ibnRva), n = 0;
                        while (ibnOff && in(ibnOff + 2 + n, 1) && img[ibnOff + 2 + n]) ++n;
                        ex.push_back({ ibnRva, ibnRva + 2 + n + 1 });
                    }
                    ++k;
                }
                ex.push_back({ arrRva, arrRva + (k + 1) * PW });
            }
            off += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
    }

    // ---- choose compressible sections + compress -----------------------
    struct Plan { int idx; std::vector<BYTE> blob; uint32_t origLen; };
    std::vector<Plan> plans;
    for (WORD i = 0; i < nSec; ++i) {
        if (std::memcmp(sec[i].Name, ".pak", 4) == 0) continue;     // our own stub sections
        uint32_t raw = sec[i].SizeOfRawData, ptr = sec[i].PointerToRawData;
        if (!raw || !ptr) continue;                                  // nothing on disk
        uint32_t va  = sec[i].VirtualAddress;
        uint32_t span = (std::max<uint32_t>)(sec[i].Misc.VirtualSize, raw);
        if (PackOverlaps(ex, va, va + span)) continue;               // loader needs it intact
        uint32_t clamp = raw;
        if ((size_t)ptr + clamp > img.size()) clamp = (uint32_t)(img.size() - ptr);
        if (!clamp) continue;
        Plan p; p.idx = i; p.origLen = clamp;
        p.blob = pakp_lz_compress(at(ptr), clamp);
        if (p.blob.size() >= clamp) continue;                        // skip if it would not shrink
        plans.push_back(std::move(p));
    }
    if (plans.empty()) return err(OBF(L"No compressible sections found (nothing to pack).").str());

    std::vector<bool> isComp(nSec, false);
    for (auto& p : plans) isComp[p.idx] = true;

    // ---- fresh random 256-bit key; encrypt each blob (nonce = index) ---
    uint32_t key[8];
    { std::random_device rd; for (int i = 0; i < 8; ++i) key[i] = rd(); }
    for (size_t i = 0; i < plans.size(); ++i)
        pakp_xor(plans[i].blob.data(), (uint32_t)plans[i].blob.size(), key, (uint64_t)i);

    // ---- assemble the .pakp content: stub + table + blobs [+ cb] + key -
    uint32_t maxEnd = 0;
    for (WORD i = 0; i < nSec; ++i)
        maxEnd = (std::max<uint32_t>)(maxEnd, sec[i].VirtualAddress +
                 (std::max)(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData));
    uint32_t newVA = (uint32_t)alignUp(maxEnd, secAlign);

    size_t offT, offC, offO = 0, offK = 0;
    std::vector<BYTE> stub;
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

    uint32_t secTabOff = peOff + offsetof(NT, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader;
    uint32_t secTabEnd = secTabOff + (uint32_t)nSec * sizeof(IMAGE_SECTION_HEADER);
    if (secTabEnd + sizeof(IMAGE_SECTION_HEADER) > opt.SizeOfHeaders)
        return err(OBF(L"No room in the header for a new section (unsupported layout).").str());

    uint64_t tableVA = imageBase + newVA + stubLen;
    uint64_t oepVA   = imageBase + opt.AddressOfEntryPoint;
    uint64_t keyVA   = imageBase + newVA + keyOff;

    std::vector<BYTE> content(contentSize, 0);
    std::memcpy(content.data(), stub.data(), stubLen);
    std::memcpy(content.data() + offT, &tableVA, PW);
    uint32_t cnt = (uint32_t)plans.size();
    std::memcpy(content.data() + offC, &cnt, 4);
    if (!hookTls) std::memcpy(content.data() + offO, &oepVA, PW);
    std::memcpy(content.data() + offK, &keyVA, PW);
    std::memcpy(content.data() + keyOff, key, kKeyLen);

    size_t blobCursor = stubLen + tableSize;
    for (size_t i = 0; i < plans.size(); ++i) {
        uint64_t dstVA = imageBase + sec[plans[i].idx].VirtualAddress;
        uint64_t srcVA = imageBase + newVA + blobCursor;
        uint32_t clen  = (uint32_t)plans[i].blob.size();
        uint32_t olen  = plans[i].origLen;
        uint64_t nonce = (uint64_t)i;
        BYTE* e = content.data() + stubLen + i * 32;
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
        BYTE* a = content.data() + stubLen + tableSize + blobsSize;
        uint64_t mine = imageBase + newVA;
        std::memcpy(a, &mine, PW);
        for (size_t i = 0; i < tlsCallbacks.size(); ++i)
            std::memcpy(a + (i + 1) * PW, &tlsCallbacks[i], PW);
        newCbArrVA = imageBase + newVA + stubLen + tableSize + blobsSize;
    }

    // ---- rebuild the file: headers + kept raw + .pakp ------------------
    std::vector<uint32_t> newPtr(nSec, 0), newRaw(nSec, 0);
    std::vector<BYTE> out(img.begin(), img.begin() + opt.SizeOfHeaders);  // header region verbatim
    for (WORD i = 0; i < nSec; ++i) {
        if (isComp[i]) continue;                             // compressed: no raw data on disk
        uint32_t raw = sec[i].SizeOfRawData, ptr = sec[i].PointerToRawData;
        if (!raw || !ptr) continue;                          // .bss etc.
        uint32_t clamp = raw;
        if ((size_t)ptr + clamp > img.size()) clamp = (uint32_t)(img.size() - ptr);
        uint32_t dstOff = (uint32_t)alignUp(out.size(), fileAlign);
        out.resize(dstOff, 0);
        out.insert(out.end(), img.begin() + ptr, img.begin() + ptr + clamp);
        newPtr[i] = dstOff; newRaw[i] = raw;
    }
    uint32_t pakpPtr = (uint32_t)alignUp(out.size(), fileAlign);
    uint32_t pakpRaw = (uint32_t)alignUp(contentSize, fileAlign);
    out.resize(pakpPtr, 0);
    out.insert(out.end(), content.begin(), content.end());
    out.resize(pakpPtr + pakpRaw, 0);

    // ---- patch headers in the rebuilt image ----------------------------
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
    nh.Characteristics  = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE |
                          IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;   // stub decrypts in place
    std::memcpy(out.data() + secTabEnd, &nh, sizeof(nh));

    nt2->FileHeader.NumberOfSections = nSec + 1;
    nt2->OptionalHeader.SizeOfImage  = (DWORD)alignUp(newVA + contentSize, secAlign);
    nt2->OptionalHeader.DllCharacteristics &= ~(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                                IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA |
                                                IMAGE_DLLCHARACTERISTICS_GUARD_CF);
    if (!hookTls) nt2->OptionalHeader.AddressOfEntryPoint = newVA;

    if (hookTls) {
        auto rvaToNewOff = [&](uint32_t rva) -> uint32_t {
            if (rva < nt2->OptionalHeader.SizeOfHeaders) return rva;
            for (WORD i = 0; i < nSec; ++i) {
                uint32_t va = sec2[i].VirtualAddress;
                uint32_t span = (std::max)(sec2[i].Misc.VirtualSize, sec2[i].SizeOfRawData);
                if (sec2[i].PointerToRawData && rva >= va && rva < va + span)
                    return sec2[i].PointerToRawData + (rva - va);
            }
            return 0;
        };
        uint32_t to = rvaToNewOff(tlsDirRva);
        if (!to) return err(OBF(L"Could not relocate the TLS directory (unsupported layout).").str());
        size_t cbField = to + offsetof(TLS, AddressOfCallBacks);
        std::memcpy(out.data() + cbField, &newCbArrVA, PW);
    }

    if (!WriteFileBytes(outPath, out)) return err(OBF(L"Could not write the output file.").str());

    uint64_t origBytes = 0, compBytes = 0;
    for (auto& p : plans) { origBytes += p.origLen; compBytes += p.blob.size(); }
    double pct = origBytes ? 100.0 * (double)compBytes / (double)origBytes : 0.0;
    std::wostringstream m;
    m << OBF(L"Pack complete (") << (X64 ? OBF(L"x64").str() : OBF(L"x86").str()) << OBF(L").\r\n\r\n")
      << OBF(L"Compressed ") << plans.size() << OBF(L" section(s): ")
      << origBytes << OBF(L" -> ") << compBytes << OBF(L" bytes (")
      << std::fixed << std::setprecision(1) << pct << OBF(L"%).\r\n")
      << OBF(L"Encrypted with a random 256-bit key (PAKP cipher); anti-debug built in.\r\n")
      << OBF(L"Hooked via ")
      << (hookTls ? OBF(L"a TLS callback.\r\n").str() : OBF(L"the entry point.\r\n").str())
      << OBF(L"File ") << (unsigned long long)img.size()
      << OBF(L" -> ") << (unsigned long long)out.size() << OBF(L" bytes.\r\n")
      << OBF(L"Added a ") << contentSize << OBF(L"-byte .pakp section.\r\n\r\n")
      << OBF(L"Saved:\r\n") << outPath;
    return PackResult{ true, m.str() };
}

// Compress+encrypt the target and write a packed copy to `outPath`. Supports
// both x64 (PE32+) and x86 (PE32) EXEs; dispatches on the machine field.
static PackResult PackExe(const std::wstring& inPath, const std::wstring& outPath) {
    auto err = [](std::wstring m) { return PackResult{ false, std::move(m) }; };
    std::vector<BYTE> img;
    { std::wstring e = ReadInput(inPath, img); if (!e.empty()) return err(e); }
    if (img.size() < sizeof(IMAGE_DOS_HEADER)) return err(OBF(L"File is too small to be a PE.").str());
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(img.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return err(OBF(L"Not a PE file (missing 'MZ').").str());
    DWORD peOff = dos->e_lfanew;
    if ((size_t)peOff + 6 > img.size()) return err(OBF(L"Not a PE file (truncated).").str());
    if (*reinterpret_cast<DWORD*>(img.data() + peOff) != IMAGE_NT_SIGNATURE)
        return err(OBF(L"Not a PE file (bad NT signature).").str());
    WORD machine = *reinterpret_cast<WORD*>(img.data() + peOff + 4);
    if (machine == IMAGE_FILE_MACHINE_AMD64) return PackExeImpl<true>(img, outPath);
    if (machine == IMAGE_FILE_MACHINE_I386)  return PackExeImpl<false>(img, outPath);
    return err(OBF(L"Only x64 (AMD64) and x86 (i386) executables are supported.").str());
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
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_EXPLORER | OFN_NOCHANGEDIR;
    if (GetSaveFileNameW(&ofn)) return file;
    return L"";
}

// A unique scratch path in %TEMP%, used to hold the intermediates when the
// "Protect (all)" button chains the passes (PackStrings -> PackCode -> PackExe).
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
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER | OFN_NOCHANGEDIR;
    if (GetOpenFileNameW(&ofn)) return file;
    return L"";
}

// ---- small GUI helpers -----------------------------------------------------
static std::wstring BaseName(const std::wstring& p) {
    size_t s = p.find_last_of(L"\\/");
    return s == std::wstring::npos ? p : p.substr(s + 1);
}
static std::wstring HumanSize(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) return L"—";
    unsigned long long sz = ((unsigned long long)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    std::wostringstream o; o.setf(std::ios::fixed); o.precision(1);
    if      (sz >= 1024ull * 1024) o << (sz / 1048576.0) << OBF(L" MB");
    else if (sz >= 1024)           o << (sz / 1024.0)    << OBF(L" KB");
    else                           o << sz << OBF(L" B");
    return o.str();
}
static void SetStatus(int part, const std::wstring& s) {
    if (g_hStatus) SendMessageW(g_hStatus, SB_SETTEXTW, part, (LPARAM)s.c_str());
}
static void EnableActions(bool on) {
    for (int id : { IDC_ENCRYPT, IDC_ENCCODE, IDC_PROTECT, IDC_PACK })
        EnableWindow(GetDlgItem(g_hMain, id), on);
}

static void LayoutChildren(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    const int pad = 12, browseW = 92, protW = 124, rowH = 30, gap = 8, primaryGap = 20;
    int w = rc.right - rc.left, h = rc.bottom - rc.top;

    // Status bar sizes itself to the bottom edge; measure its height, set parts.
    SendMessageW(g_hStatus, WM_SIZE, 0, 0);
    RECT sbr; GetWindowRect(g_hStatus, &sbr);
    int sbH = sbr.bottom - sbr.top;
    int sp[3] = { (w * 9) / 20, (w * 13) / 20, -1 };   // file | size | last action
    SendMessageW(g_hStatus, SB_SETPARTS, 3, (LPARAM)sp);

    // Row 1 (below the accent header): path edit + Browse.
    int top = kHeaderH + pad;
    MoveWindow(g_hPath, pad, top, w - browseW - 3 * pad, rowH, TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_BROWSE), w - browseW - pad, top, browseW, rowH, TRUE);

    // Row 2: the primary action, a gap, then the three component passes.
    int row2 = top + rowH + pad;
    int x = pad;
    MoveWindow(GetDlgItem(hwnd, IDC_PROTECT), x, row2, protW, rowH, TRUE); x += protW + primaryGap;
    MoveWindow(GetDlgItem(hwnd, IDC_ENCRYPT), x, row2, protW, rowH, TRUE); x += protW + gap;
    MoveWindow(GetDlgItem(hwnd, IDC_ENCCODE), x, row2, protW, rowH, TRUE); x += protW + gap;
    MoveWindow(GetDlgItem(hwnd, IDC_PACK),    x, row2, protW, rowH, TRUE);

    // Report pane fills the gap between the buttons and the status bar.
    int infoY = row2 + rowH + pad;
    MoveWindow(g_hInfo, pad, infoY, w - 2 * pad, h - infoY - pad - sbH, TRUE);
}

static void LoadAndShow(const std::wstring& path) {
    // Resolve to an ABSOLUTE path now: the Save/Open dialogs change the process's
    // current directory, so a relative path (from the command line / "Open with")
    // would stop resolving by the time a protect pass reads it.
    wchar_t full[MAX_PATH];
    DWORD n = GetFullPathNameW(path.c_str(), MAX_PATH, full, nullptr);
    std::wstring abs = (n > 0 && n < MAX_PATH) ? std::wstring(full) : path;

    g_currentPath = abs;
    SetWindowTextW(g_hPath, abs.c_str());
    std::wstring report = AnalyzePE(abs);
    SetWindowTextW(g_hInfo, report.c_str());
    EnableActions(true);                       // actions become available
    SetStatus(0, BaseName(abs));
    SetStatus(1, HumanSize(abs));
    SetStatus(2, OBF(L"Loaded").str());
}

// Run one single-pass protector (strings / code / pack): Save dialog, result
// dialog, status update, and re-inspection of the output. Collapses three
// near-identical button handlers into one.
static void RunSinglePass(HWND hwnd, const wchar_t* failTitle, const wchar_t* suffix,
                          PackResult (*pass)(const std::wstring&, const std::wstring&)) {
    if (g_currentPath.empty()) return;         // actions are disabled with no file anyway
    std::wstring out = SaveProtectedAs(hwnd, DefaultOutputName(g_currentPath, suffix));
    if (out.empty()) return;                   // user cancelled the Save dialog
    SetStatus(2, OBF(L"Working…").str());
    PackResult res = pass(g_currentPath, out);
    if (res.ok) {
        MessageBoxW(hwnd, res.message.c_str(), OBF(L"Done"), MB_OK | MB_ICONINFORMATION);
        LoadAndShow(out);                      // re-inspect the protected copy
        SetStatus(2, OBF(L"Done · ").str() + BaseName(out));
    } else {
        MessageBoxW(hwnd, res.message.c_str(), failTitle, MB_OK | MB_ICONERROR);
        SetStatus(2, OBF(L"Failed").str());
    }
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_hMain    = hwnd;
        g_uiFont   = CreateFontW(-16, 0,0,0, FW_NORMAL, 0,0,0, DEFAULT_CHARSET,
                                 0,0,0,0, OBF(L"Segoe UI"));
        g_monoFont = CreateFontW(-14, 0,0,0, FW_NORMAL, 0,0,0, DEFAULT_CHARSET,
                                 0,0, PROOF_QUALITY, FIXED_PITCH|FF_MODERN, OBF(L"Consolas"));
        g_titleFont = CreateFontW(-24, 0,0,0, FW_SEMIBOLD, 0,0,0, DEFAULT_CHARSET,
                                  0,0,0,0, OBF(L"Segoe UI Semibold"));
        g_subFont  = CreateFontW(-13, 0,0,0, FW_NORMAL, 0,0,0, DEFAULT_CHARSET,
                                 0,0,0,0, OBF(L"Segoe UI"));
        g_accentBrush = CreateSolidBrush(RGB(28, 42, 74));

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
        CreateWindowExW(0, OBF(L"BUTTON"), OBF(L"Protect (all)"),
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON|BS_DEFPUSHBUTTON,
            0,0,0,0, hwnd, (HMENU)IDC_PROTECT, nullptr, nullptr);
        CreateWindowExW(0, OBF(L"BUTTON"), OBF(L"Pack"),
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            0,0,0,0, hwnd, (HMENU)IDC_PACK, nullptr, nullptr);
        g_hInfo = CreateWindowExW(WS_EX_CLIENTEDGE, OBF(L"EDIT"),
            OBF(L"Click “Browse…”, or drag an .exe onto this window, to see its PE structure.\r\n"
                L"“Protect (all)” runs every pass — encrypt strings, encrypt code, then pack — so IDA "
                L"shows only garbage and the file carries an anti-debug loader.\r\n"
                L"Or apply a single pass on its own: “Encrypt strings”, “Encrypt code”, or “Pack” "
                L"(compress + encrypt + anti-debug)."),
            WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
            0,0,0,0, hwnd, (HMENU)IDC_INFO, nullptr, nullptr);

        SendMessageW(g_hPath, WM_SETFONT, (WPARAM)g_uiFont, TRUE);
        SendMessageW(GetDlgItem(hwnd, IDC_BROWSE),  WM_SETFONT, (WPARAM)g_uiFont, TRUE);
        SendMessageW(GetDlgItem(hwnd, IDC_ENCRYPT), WM_SETFONT, (WPARAM)g_uiFont, TRUE);
        SendMessageW(GetDlgItem(hwnd, IDC_ENCCODE), WM_SETFONT, (WPARAM)g_uiFont, TRUE);
        SendMessageW(GetDlgItem(hwnd, IDC_PROTECT), WM_SETFONT, (WPARAM)g_uiFont, TRUE);
        SendMessageW(GetDlgItem(hwnd, IDC_PACK),    WM_SETFONT, (WPARAM)g_uiFont, TRUE);
        SendMessageW(g_hInfo, WM_SETFONT, (WPARAM)g_monoFont, TRUE);

        // Status bar: file · size · last action.
        g_hStatus = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr,
            WS_CHILD|WS_VISIBLE|SBARS_SIZEGRIP, 0,0,0,0, hwnd, (HMENU)IDC_STATUS,
            ((CREATESTRUCTW*)lp)->hInstance, nullptr);
        SendMessageW(g_hStatus, WM_SETFONT, (WPARAM)g_uiFont, TRUE);
        { RECT cr; GetClientRect(hwnd, &cr);
          int sp0[3] = { (cr.right * 9) / 20, (cr.right * 13) / 20, -1 };
          SendMessageW(g_hStatus, SB_SETPARTS, 3, (LPARAM)sp0); }

        // Tooltips (TTF_SUBCLASS -> the tooltip handles the mouse itself, no relay).
        g_hTip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr,
            WS_POPUP|TTS_ALWAYSTIP|TTS_NOPREFIX, 0,0,0,0, hwnd, nullptr,
            ((CREATESTRUCTW*)lp)->hInstance, nullptr);
        {
            static std::wstring tB = OBF(L"Pick an .exe to inspect and protect.").str();
            static std::wstring tP = OBF(L"Run all passes: encrypt strings, encrypt code, then pack (adds .pak + .pakc + .pakp).").str();
            static std::wstring tS = OBF(L"XOR-encrypt the string runs in .rdata / .data (adds .pak).").str();
            static std::wstring tC = OBF(L"Encrypt the .text code section (adds .pakc).").str();
            static std::wstring tK = OBF(L"Compress + encrypt code/data and add an anti-debug loader (adds .pakp).").str();
            auto addTip = [&](int id, std::wstring& text) {
                TOOLINFOW ti = {}; ti.cbSize = sizeof(ti);
                ti.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
                ti.hwnd = hwnd; ti.uId = (UINT_PTR)GetDlgItem(hwnd, id);
                ti.lpszText = (LPWSTR)text.c_str();
                SendMessageW(g_hTip, TTM_ADDTOOLW, 0, (LPARAM)&ti);
            };
            addTip(IDC_BROWSE, tB);  addTip(IDC_PROTECT, tP); addTip(IDC_ENCRYPT, tS);
            addTip(IDC_ENCCODE, tC); addTip(IDC_PACK, tK);
            SendMessageW(g_hTip, TTM_SETMAXTIPWIDTH, 0, 360);
        }

        EnableActions(false);                  // nothing to act on until a file loads
        SetStatus(0, OBF(L"No file loaded").str());
        SetStatus(1, L"—");
        SetStatus(2, OBF(L"Ready").str());
        DragAcceptFiles(hwnd, TRUE);
        return 0;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC dc = BeginPaint(hwnd, &ps);
        RECT rc; GetClientRect(hwnd, &rc);
        RECT band = { 0, 0, rc.right, kHeaderH };
        FillRect(dc, &band, g_accentBrush);
        SetBkMode(dc, TRANSPARENT);
        HFONT old = (HFONT)SelectObject(dc, g_titleFont);
        SetTextColor(dc, RGB(255, 255, 255));
        RECT tr = { 16, 7, rc.right - 12, 36 };
        DrawTextW(dc, OBF(L"exe-protector"), -1, &tr, DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);
        SelectObject(dc, g_subFont);
        SetTextColor(dc, RGB(176, 196, 230));
        RECT sr = { 16, 33, rc.right - 12, kHeaderH - 4 };
        DrawTextW(dc, OBF(L"PE inspector · string / code encryption · pack"), -1, &sr,
                  DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);
        SelectObject(dc, old);
        EndPaint(hwnd, &ps);
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
    case WM_SIZE: {
        LayoutChildren(hwnd);
        RECT hr = { 0, 0, (int)LOWORD(lp), kHeaderH };   // repaint the header band
        InvalidateRect(hwnd, &hr, FALSE);
        return 0;
    }
    case WM_GETMINMAXINFO: {
        auto mmi = reinterpret_cast<MINMAXINFO*>(lp);
        mmi->ptMinTrackSize.x = 560;
        mmi->ptMinTrackSize.y = 440;
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_BROWSE && HIWORD(wp) == BN_CLICKED) {
            std::wstring path = BrowseForExe(hwnd);
            if (!path.empty()) LoadAndShow(path);
            return 0;
        }
        if (LOWORD(wp) == IDC_ENCRYPT && HIWORD(wp) == BN_CLICKED) {
            RunSinglePass(hwnd, OBF(L"Encrypt strings — failed").str().c_str(), L"_strenc", PackStrings);
            return 0;
        }
        if (LOWORD(wp) == IDC_ENCCODE && HIWORD(wp) == BN_CLICKED) {
            RunSinglePass(hwnd, OBF(L"Encrypt code — failed").str().c_str(), L"_codeenc", PackCode);
            return 0;
        }
        if (LOWORD(wp) == IDC_PROTECT && HIWORD(wp) == BN_CLICKED) {
            if (g_currentPath.empty()) return 0;   // actions disabled with no file
            std::wstring out = SaveProtectedAs(hwnd, DefaultOutputName(g_currentPath, L"_protected"));
            if (out.empty()) return 0;   // user cancelled the Save dialog
            std::wstring tmp1 = MakeTempExe(), tmp2 = MakeTempExe();
            if (tmp1.empty() || tmp2.empty()) {
                if (!tmp1.empty()) DeleteFileW(tmp1.c_str());
                if (!tmp2.empty()) DeleteFileW(tmp2.c_str());
                MessageBoxW(hwnd, OBF(L"Could not create temporary files."),
                            OBF(L"Protect — failed"), MB_OK | MB_ICONERROR);
                return 0;
            }
            SetStatus(2, OBF(L"Working…").str());
            // Apply all three passes in order: strings -> code -> pack. Each
            // stage that succeeds advances the working file; one that finds
            // nothing (e.g. no strings) is skipped so the rest still apply. pack
            // runs last so its stub — and the anti-debug — ends up outermost and
            // fires first at load (decompress, then code-decrypt, then strings).
            std::wstring cur = g_currentPath, applied, skipped;
            PackResult r1 = PackStrings(cur, tmp1);
            if (r1.ok) { cur = tmp1; applied += OBF(L"strings, ").str(); }
            else skipped += OBF(L"strings, ").str();
            PackResult r2 = PackCode(cur, tmp2);
            if (r2.ok) { cur = tmp2; applied += OBF(L"code, ").str(); }
            else skipped += OBF(L"code, ").str();
            PackResult r3 = PackExe(cur, out);
            bool haveOut = r3.ok;
            if (r3.ok) applied += OBF(L"pack").str();
            else {
                skipped += OBF(L"pack").str();
                // Keep the strings/code result if any pass succeeded.
                if (cur != g_currentPath) haveOut = CopyFileW(cur.c_str(), out.c_str(), FALSE) != 0;
            }
            DeleteFileW(tmp1.c_str()); DeleteFileW(tmp2.c_str());

            if (!haveOut) {
                MessageBoxW(hwnd, (OBF(L"Nothing could be applied.\r\n\r\n").str() + r3.message).c_str(),
                            OBF(L"Protect — failed"), MB_OK | MB_ICONERROR);
                SetStatus(2, OBF(L"Failed").str());
                return 0;
            }
            auto trimComma = [](std::wstring s) {
                if (s.size() >= 2 && s.compare(s.size() - 2, 2, L", ") == 0) s.resize(s.size() - 2);
                return s;
            };
            std::wstring msg = OBF(L"Applied: ").str() +
                               (applied.empty() ? OBF(L"(none)").str() : trimComma(applied)) + L"\r\n";
            if (!skipped.empty())
                msg += OBF(L"Skipped (nothing to do): ").str() + trimComma(skipped) + L"\r\n";
            msg += OBF(L"\r\nSaved:\r\n").str() + out;
            MessageBoxW(hwnd, msg.c_str(), OBF(L"Done"), MB_OK | MB_ICONINFORMATION);
            LoadAndShow(out);
            SetStatus(2, OBF(L"Done · ").str() + BaseName(out));
            return 0;
        }
        if (LOWORD(wp) == IDC_PACK && HIWORD(wp) == BN_CLICKED) {
            RunSinglePass(hwnd, OBF(L"Pack — failed").str().c_str(), L"_packed", PackExe);
            return 0;
        }
        break;
    case WM_DESTROY:
        if (g_uiFont)      DeleteObject(g_uiFont);
        if (g_monoFont)    DeleteObject(g_monoFont);
        if (g_titleFont)   DeleteObject(g_titleFont);
        if (g_subFont)     DeleteObject(g_subFont);
        if (g_accentBrush) DeleteObject(g_accentBrush);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nShow) {
    INITCOMMONCONTROLSEX icc = { sizeof(icc),
        ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES | ICC_BAR_CLASSES };
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

    HWND hwnd = CreateWindowExW(0, kClass, OBF(L"exe-protector — PE inspector + protector"),
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 860, 640,
        nullptr, nullptr, hInst, nullptr);
    if (!hwnd) return 1;

    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    // Open a file passed on the command line (also handles "Open with" / a file
    // dropped onto the .exe), so the inspector starts on it.
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        if (argc >= 2 && argv[1][0]) {
            DWORD a = GetFileAttributesW(argv[1]);
            if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY))
                LoadAndShow(argv[1]);
        }
        LocalFree(argv);
    }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}