// exe-protector — educational software-protection demonstrator (stage 1: inspector)
//
// Stage 1 goal: a native Win32 GUI that lets you pick any .exe and inspect its
// PE layout (headers, sections, imports). This is the read-only foundation a
// packer/protector needs before it can transform a binary. Later stages will
// add protection passes (section encryption + stub loader, self-integrity and
// anti-debug checks) for protecting software you own, the same category of tool
// as UPX / VMProtect.
//
// Build (MSYS2 UCRT64):
//   g++ -O2 -municode -mwindows -o exe-protector.exe main.cpp -lcomdlg32 -lgdi32

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

// ---- control IDs ---------------------------------------------------------
enum {
    IDC_PATH = 1001,
    IDC_BROWSE,
    IDC_INFO,
};

static HFONT g_uiFont   = nullptr;  // Segoe UI for labels / buttons
static HFONT g_monoFont = nullptr;  // Consolas for the report pane
static HWND  g_hPath    = nullptr;
static HWND  g_hInfo    = nullptr;

// ---- small formatting helpers -------------------------------------------
static std::wstring Hex(unsigned long long v, int width = 0) {
    std::wostringstream os;
    os << L"0x" << std::uppercase << std::hex;
    if (width) os << std::setw(width) << std::setfill(L'0');
    os << v;
    return os.str();
}

// Append "NAME" for each bit set in `value`, from a {bit, name} table.
struct FlagName { unsigned long bit; const wchar_t* name; };
static std::wstring DecodeFlags(unsigned long value, const FlagName* tbl, size_t n) {
    std::wstring out;
    for (size_t i = 0; i < n; ++i) {
        if (value & tbl[i].bit) {
            if (!out.empty()) out += L" | ";
            out += tbl[i].name;
        }
    }
    return out.empty() ? std::wstring(L"(none)") : out;
}

static const wchar_t* MachineName(WORD m) {
    switch (m) {
        case IMAGE_FILE_MACHINE_I386:  return L"x86 (i386)";
        case IMAGE_FILE_MACHINE_AMD64: return L"x64 (AMD64)";
        case IMAGE_FILE_MACHINE_ARM:   return L"ARM";
        case IMAGE_FILE_MACHINE_ARM64: return L"ARM64";
        case IMAGE_FILE_MACHINE_IA64:  return L"IA64";
        default:                       return L"unknown";
    }
}

static const wchar_t* SubsystemName(WORD s) {
    switch (s) {
        case IMAGE_SUBSYSTEM_WINDOWS_GUI: return L"Windows GUI";
        case IMAGE_SUBSYSTEM_WINDOWS_CUI: return L"Windows console (CUI)";
        case IMAGE_SUBSYSTEM_NATIVE:      return L"Native";
        case IMAGE_SUBSYSTEM_EFI_APPLICATION: return L"EFI application";
        default:                          return L"other";
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
    if (!LoadFileBytes(path, buf)) return L"Could not read the file.";

    const size_t size = buf.size();
    const BYTE*  base = buf.data();
    auto in = [&](size_t off, size_t len) { return off + len <= size; };

    r << L"File : " << path << L"\r\n";
    r << L"Size : " << size << L" bytes (" << Hex(size) << L")\r\n\r\n";

    if (!in(0, sizeof(IMAGE_DOS_HEADER)))
        return r.str() + L"Too small to be a PE file.";
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return r.str() + L"Not a PE file (missing 'MZ' signature).";

    r << L"== DOS header ==\r\n";
    r << L"  e_lfanew : " << Hex(dos->e_lfanew) << L"  (offset of PE header)\r\n\r\n";

    DWORD peOff = dos->e_lfanew;
    if (!in(peOff, 4) || *reinterpret_cast<const DWORD*>(base + peOff) != IMAGE_NT_SIGNATURE)
        return r.str() + L"Not a PE file (missing 'PE\\0\\0' signature).";

    DWORD fhOff = peOff + 4;
    if (!in(fhOff, sizeof(IMAGE_FILE_HEADER)))
        return r.str() + L"Truncated: file header is cut off.";
    auto fh = reinterpret_cast<const IMAGE_FILE_HEADER*>(base + fhOff);

    static const FlagName kChar[] = {
        { IMAGE_FILE_EXECUTABLE_IMAGE,   L"EXECUTABLE" },
        { IMAGE_FILE_DLL,                L"DLL" },
        { IMAGE_FILE_LARGE_ADDRESS_AWARE,L"LARGE_ADDRESS_AWARE" },
        { IMAGE_FILE_32BIT_MACHINE,      L"32BIT_MACHINE" },
        { IMAGE_FILE_RELOCS_STRIPPED,    L"RELOCS_STRIPPED" },
        { IMAGE_FILE_DEBUG_STRIPPED,     L"DEBUG_STRIPPED" },
    };
    r << L"== File header ==\r\n";
    r << L"  Machine        : " << Hex(fh->Machine) << L"  " << MachineName(fh->Machine) << L"\r\n";
    r << L"  Sections       : " << fh->NumberOfSections << L"\r\n";
    r << L"  TimeDateStamp  : " << Hex(fh->TimeDateStamp) << L"\r\n";
    r << L"  OptHeader size : " << fh->SizeOfOptionalHeader << L" bytes\r\n";
    r << L"  Characteristics: " << DecodeFlags(fh->Characteristics, kChar, 6) << L"\r\n\r\n";

    DWORD ohOff = fhOff + sizeof(IMAGE_FILE_HEADER);
    if (!in(ohOff, sizeof(WORD)))
        return r.str() + L"Truncated: optional header is cut off.";
    WORD magic = *reinterpret_cast<const WORD*>(base + ohOff);

    static const FlagName kDll[] = {
        { IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,    L"DYNAMIC_BASE (ASLR)" },
        { IMAGE_DLLCHARACTERISTICS_NX_COMPAT,       L"NX_COMPAT (DEP)" },
        { IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, L"HIGH_ENTROPY_VA" },
        { IMAGE_DLLCHARACTERISTICS_GUARD_CF,        L"GUARD_CF (CFG)" },
        { IMAGE_DLLCHARACTERISTICS_NO_SEH,          L"NO_SEH" },
        { IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, L"FORCE_INTEGRITY" },
    };

    DWORD entry = 0, subsystem = 0, dllChar = 0;
    unsigned long long imageBase = 0, sizeOfImage = 0;
    const IMAGE_DATA_DIRECTORY* dirs = nullptr;
    DWORD numDirs = 0;

    r << L"== Optional header ==\r\n";
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (!in(ohOff, sizeof(IMAGE_OPTIONAL_HEADER32)))
            return r.str() + L"Truncated: 32-bit optional header is cut off.";
        auto oh = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(base + ohOff);
        entry = oh->AddressOfEntryPoint; imageBase = oh->ImageBase;
        sizeOfImage = oh->SizeOfImage; subsystem = oh->Subsystem;
        dllChar = oh->DllCharacteristics;
        dirs = oh->DataDirectory; numDirs = oh->NumberOfRvaAndSizes;
        r << L"  Format         : PE32 (32-bit)\r\n";
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (!in(ohOff, sizeof(IMAGE_OPTIONAL_HEADER64)))
            return r.str() + L"Truncated: 64-bit optional header is cut off.";
        auto oh = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(base + ohOff);
        entry = oh->AddressOfEntryPoint; imageBase = oh->ImageBase;
        sizeOfImage = oh->SizeOfImage; subsystem = oh->Subsystem;
        dllChar = oh->DllCharacteristics;
        dirs = oh->DataDirectory; numDirs = oh->NumberOfRvaAndSizes;
        r << L"  Format         : PE32+ (64-bit)\r\n";
    } else {
        return r.str() + L"Unknown optional header magic " + Hex(magic) + L".";
    }
    r << L"  Entry point RVA: " << Hex(entry) << L"\r\n";
    r << L"  Image base     : " << Hex(imageBase) << L"\r\n";
    r << L"  Size of image  : " << Hex(sizeOfImage) << L"\r\n";
    r << L"  Subsystem      : " << subsystem << L"  (" << SubsystemName((WORD)subsystem) << L")\r\n";
    r << L"  DLL characteri.: " << DecodeFlags(dllChar, kDll, 6) << L"\r\n\r\n";

    // Section table follows the optional header.
    DWORD secOff = ohOff + fh->SizeOfOptionalHeader;
    WORD  nSec   = fh->NumberOfSections;
    if (!in(secOff, (size_t)nSec * sizeof(IMAGE_SECTION_HEADER)))
        return r.str() + L"Truncated: section table is cut off.";
    auto sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(base + secOff);

    static const FlagName kSec[] = {
        { IMAGE_SCN_CNT_CODE,               L"CODE" },
        { IMAGE_SCN_CNT_INITIALIZED_DATA,   L"IDATA" },
        { IMAGE_SCN_CNT_UNINITIALIZED_DATA, L"UDATA" },
        { IMAGE_SCN_MEM_EXECUTE,            L"EXEC" },
        { IMAGE_SCN_MEM_READ,               L"READ" },
        { IMAGE_SCN_MEM_WRITE,              L"WRITE" },
    };
    r << L"== Sections (" << nSec << L") ==\r\n";
    r << L"  Name       VirtAddr    VirtSize    RawSize     Entropy  Flags\r\n";
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
          << DecodeFlags(sec[i].Characteristics, kSec, 6) << std::right << L"\r\n";
    }
    r << L"  (* entropy > 7.0 — section looks compressed or encrypted)\r\n\r\n";

    // Imported DLLs (data directory 1).
    r << L"== Imported DLLs ==\r\n";
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
            if (++count > 256) { r << L"  ...(truncated)\r\n"; break; }
        }
        if (count == 0) r << L"  (none resolved)\r\n";
    } else {
        r << L"  (no import directory)\r\n";
    }

    // Raw header bytes — handy for eyeballing the MZ stub and PE structures.
    size_t dumpN = size < 240 ? size : 240;
    r << L"\r\n== Header hex (first " << dumpN << L" bytes) ==\r\n";
    AppendHexDump(r, base, dumpN);

    return r.str();
}

// ---- UI ------------------------------------------------------------------
static std::wstring BrowseForExe(HWND owner) {
    wchar_t file[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = owner;
    ofn.lpstrFilter = L"Executable files (*.exe)\0*.exe\0All files (*.*)\0*.*\0";
    ofn.lpstrFile   = file;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrTitle  = L"Select an executable to inspect";
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    if (GetOpenFileNameW(&ofn)) return file;
    return L"";
}

static void LayoutChildren(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    const int pad = 10, btnW = 90, rowH = 26;
    int w = rc.right - rc.left, h = rc.bottom - rc.top;
    MoveWindow(g_hPath, pad, pad, w - btnW - 3 * pad, rowH, TRUE);
    MoveWindow(GetDlgItem(hwnd, IDC_BROWSE), w - btnW - pad, pad, btnW, rowH, TRUE);
    MoveWindow(g_hInfo, pad, pad + rowH + pad, w - 2 * pad,
               h - (pad + rowH + pad) - pad, TRUE);
}

static void LoadAndShow(const std::wstring& path) {
    SetWindowTextW(g_hPath, path.c_str());
    std::wstring report = AnalyzePE(path);
    SetWindowTextW(g_hInfo, report.c_str());
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_uiFont   = CreateFontW(-16, 0,0,0, FW_NORMAL, 0,0,0, DEFAULT_CHARSET,
                                 0,0,0,0, L"Segoe UI");
        g_monoFont = CreateFontW(-14, 0,0,0, FW_NORMAL, 0,0,0, DEFAULT_CHARSET,
                                 0,0, PROOF_QUALITY, FIXED_PITCH|FF_MODERN, L"Consolas");

        g_hPath = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL|ES_READONLY,
            0,0,0,0, hwnd, (HMENU)IDC_PATH, nullptr, nullptr);
        CreateWindowExW(0, L"BUTTON", L"Browse…",
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            0,0,0,0, hwnd, (HMENU)IDC_BROWSE, nullptr, nullptr);
        g_hInfo = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT",
            L"Click “Browse…”, or drag an .exe onto this window, to see its PE structure.",
            WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL,
            0,0,0,0, hwnd, (HMENU)IDC_INFO, nullptr, nullptr);

        SendMessageW(g_hPath, WM_SETFONT, (WPARAM)g_uiFont, TRUE);
        SendMessageW(GetDlgItem(hwnd, IDC_BROWSE), WM_SETFONT, (WPARAM)g_uiFont, TRUE);
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

    const wchar_t* kClass = L"ExeProtectorWindow";
    WNDCLASSEXW wc = {0};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = kClass;
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(0, kClass, L"exe-protector — PE inspector (stage 1)",
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
