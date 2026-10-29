#ifndef PE_CORE_H
#define PE_CORE_H
// pe_core.h — shared PE-manipulation core for the Anti-Reverse CLI tools
// (strcrypt, codeenc, pack). Before this header, each tool carried its own copy
// of the same PE plumbing: header parse + validation, RVA->file-offset mapping,
// the loader-critical "exclusion list" (data directories + a full import-table
// walk), and the new-section layout math. That duplication is where the three
// tools could silently drift apart — especially the import walk, the easiest
// part to get subtly wrong. They now share this one implementation.
//
// Everything is templated on `bool X64` so a single body serves both PE32+
// (AMD64) and PE32 (i386); the pointer width PW and the ordinal flag are the
// only things that vary. `pack` instantiates both; `strcrypt`/`codeenc` use the
// x64 instantiation only (they remain x64-only by design, see their headers).
//
// Pointer-lifetime contract: View<X64> holds pointers INTO the caller's image
// buffer (nt/opt/sec). They stay valid until the caller resizes or replaces that
// buffer. Do all header/section inspection through the View first, then do the
// buffer surgery — exactly how all three tools are structured.

#include <windows.h>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
#include <type_traits>

namespace pe {

// [beg, end) in RVA space — a byte range the loader needs left untouched.
struct Span { uint32_t beg; uint32_t end; };

inline bool overlaps(const std::vector<Span>& ex, uint32_t beg, uint32_t end) {
    for (const auto& s : ex) if (beg < s.end && s.beg < end) return true;
    return false;
}

// Architecture-dependent types/constants in one place.
template<bool X64>
struct Traits {
    using NT  = std::conditional_t<X64, IMAGE_NT_HEADERS64,      IMAGE_NT_HEADERS32>;
    using OPT = std::conditional_t<X64, IMAGE_OPTIONAL_HEADER64,  IMAGE_OPTIONAL_HEADER32>;
    using TLS = std::conditional_t<X64, IMAGE_TLS_DIRECTORY64,    IMAGE_TLS_DIRECTORY32>;
    static constexpr int      PW  = X64 ? 8 : 4;                      // pointer width
    static constexpr uint64_t ORD = X64 ? IMAGE_ORDINAL_FLAG64 : (uint64_t)IMAGE_ORDINAL_FLAG32;
    static constexpr WORD     MAG = X64 ? IMAGE_NT_OPTIONAL_HDR64_MAGIC
                                        : IMAGE_NT_OPTIONAL_HDR32_MAGIC;
};

// A parsed, bounds-checked view over a PE image already resident in `img`.
template<bool X64>
struct View {
    using NT  = typename Traits<X64>::NT;
    using OPT = typename Traits<X64>::OPT;
    static constexpr int PW = Traits<X64>::PW;

    std::vector<uint8_t>& img;
    DWORD  peOff   = 0;
    NT*    nt      = nullptr;
    OPT*   opt     = nullptr;
    IMAGE_SECTION_HEADER* sec = nullptr;
    WORD   nSec    = 0;
    uint64_t imageBase = 0;
    uint32_t fileAlign = 0, secAlign = 0, sizeOfHeaders = 0;

    explicit View(std::vector<uint8_t>& image) : img(image) {}

    uint8_t* at(size_t off) { return img.data() + off; }
    bool     in(size_t off, size_t len) const { return off + len <= img.size(); }
    static uint64_t alignUp(uint64_t v, uint64_t a) { return (v + a - 1) / a * a; }

    // RVA -> raw file offset via the section table (headers map 1:1 below
    // SizeOfHeaders). Returns 0 on a miss.
    uint32_t rvaToOff(uint32_t rva) const {
        if (rva < sizeOfHeaders) return rva;
        for (WORD i = 0; i < nSec; ++i) {
            uint32_t va   = sec[i].VirtualAddress;
            uint32_t span = (std::max)(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
            if (rva >= va && rva < va + span) return sec[i].PointerToRawData + (rva - va);
        }
        return 0;
    }

    // Highest VA end across all sections — where a newly appended section starts.
    uint32_t maxSectionEnd() const {
        uint32_t m = 0;
        for (WORD i = 0; i < nSec; ++i)
            m = (std::max<uint32_t>)(m, sec[i].VirtualAddress +
                (std::max)(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData));
        return m;
    }

    // Is there room in the header padding for one more section header?
    bool hasRoomForSectionHeader() const {
        uint32_t secTabOff = peOff + offsetof(NT, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader;
        uint32_t secTabEnd = secTabOff + (uint32_t)nSec * sizeof(IMAGE_SECTION_HEADER);
        return secTabEnd + sizeof(IMAGE_SECTION_HEADER) <= sizeOfHeaders;
    }
    // File offset at which the next section header would be written.
    uint32_t sectionHeaderSlotOff() const {
        uint32_t secTabOff = peOff + offsetof(NT, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader;
        return secTabOff + (uint32_t)nSec * sizeof(IMAGE_SECTION_HEADER);
    }
};

// Parse + validate a PE already loaded in `img`, filling `v`. On success returns
// "" (empty). On any problem returns a human-readable reason. `alreadyName` is a
// section-name prefix whose presence means "already processed by this pass"
// (".pak" / ".pakc" / ".pakp"); pass nullptr to skip that check.
//
// `requireMachine` (default true) rejects a machine word that does not match the
// instantiated architecture — the behavior the x64-only tools want. `pack`
// dispatches on the machine field itself and passes false.
template<bool X64>
std::string open(View<X64>& v, const char* alreadyName, bool requireMachine = true) {
    using NT  = typename Traits<X64>::NT;
    auto& img = v.img;
    if (img.size() < sizeof(IMAGE_DOS_HEADER)) return "file is too small to be a PE";
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(img.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return "not a PE (missing 'MZ')";

    v.peOff = dos->e_lfanew;
    if (!v.in(v.peOff, sizeof(NT))) return "not a PE (truncated)";
    v.nt = reinterpret_cast<NT*>(v.at(v.peOff));
    if (v.nt->Signature != IMAGE_NT_SIGNATURE) return "not a PE (missing 'PE\\0\\0')";

    if (requireMachine) {
        WORD want = X64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
        if (v.nt->FileHeader.Machine != want)
            return X64 ? "only x64 (AMD64) executables are supported"
                       : "only x86 (i386) executables are supported";
    }
    if (v.nt->OptionalHeader.Magic != Traits<X64>::MAG)
        return "optional-header magic does not match the machine";
    if (v.nt->FileHeader.Characteristics & IMAGE_FILE_DLL)
        return "DLLs are not supported (EXE only)";

    v.opt = &v.nt->OptionalHeader;
    if (v.opt->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR &&
        v.opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress)
        return ".NET assemblies are not supported";

    v.sec           = IMAGE_FIRST_SECTION(v.nt);
    v.nSec          = v.nt->FileHeader.NumberOfSections;
    v.imageBase     = v.opt->ImageBase;
    v.fileAlign     = v.opt->FileAlignment;
    v.secAlign      = v.opt->SectionAlignment;
    v.sizeOfHeaders = v.opt->SizeOfHeaders;

    if (alreadyName) {
        size_t n = std::strlen(alreadyName);
        for (WORD i = 0; i < v.nSec; ++i)
            if (std::memcmp(v.sec[i].Name, alreadyName, n) == 0)
                return "this file has already been processed by this pass";
    }
    return "";
}

// Append to `ex` every byte range the Windows loader must read intact before any
// stub runs: SizeOfHeaders, every populated data directory, and a full walk of
// the import table (DLL-name strings, INT/IAT thunk arrays, and import-by-name
// entries). Identical logic for both architectures; thunk width follows PW.
template<bool X64>
void buildExclusions(View<X64>& v, std::vector<Span>& ex) {
    constexpr int      PW  = Traits<X64>::PW;
    constexpr uint64_t ORD = Traits<X64>::ORD;
    auto& img  = v.img;
    auto& opt  = *v.opt;

    ex.push_back({ 0, opt.SizeOfHeaders });
    for (DWORD i = 0; i < opt.NumberOfRvaAndSizes && i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
        auto& d = opt.DataDirectory[i];
        if (d.VirtualAddress && d.Size) ex.push_back({ d.VirtualAddress, d.VirtualAddress + d.Size });
    }

    auto& impDir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    uint32_t off = impDir.VirtualAddress ? v.rvaToOff(impDir.VirtualAddress) : 0;
    int guard = 0;
    while (off && v.in(off, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && ++guard < 4096) {
        auto imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(v.at(off));
        if (imp->Name == 0 && imp->FirstThunk == 0) break;
        if (imp->Name) {
            uint32_t nameOff = v.rvaToOff(imp->Name), n = 0;
            while (nameOff && v.in(nameOff + n, 1) && img[nameOff + n]) ++n;
            ex.push_back({ imp->Name, imp->Name + n + 1 });
        }
        for (int which = 0; which < 2; ++which) {
            uint32_t arrRva = which ? imp->FirstThunk : imp->OriginalFirstThunk;
            if (!arrRva) continue;
            uint32_t arrOff = v.rvaToOff(arrRva), k = 0;
            while (arrOff && v.in(arrOff + k * PW, PW)) {
                uint64_t t = 0; std::memcpy(&t, v.at(arrOff + k * PW), PW);
                if (!t) break;
                if (!(t & ORD)) {                              // import by name
                    uint32_t ibnRva = (uint32_t)(t & 0x7fffffff);
                    uint32_t ibnOff = v.rvaToOff(ibnRva), n = 0;   // hint(2) + name
                    while (ibnOff && v.in(ibnOff + 2 + n, 1) && img[ibnOff + 2 + n]) ++n;
                    ex.push_back({ ibnRva, ibnRva + 2 + n + 1 });
                }
                ++k;
            }
            ex.push_back({ arrRva, arrRva + (k + 1) * PW });
        }
        off += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
}

} // namespace pe

#endif // PE_CORE_H
