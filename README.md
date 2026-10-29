# Anti-Reverse

A small, self-contained **executable-protection toolset** for native Windows PE
binaries — the same category of tool as UPX / VMProtect / Themida, built for
learning and for protecting software **you own**. It raises the cost of *static*
reverse engineering (a hex editor, `strings`, IDA/Ghidra on the file at rest) and
adds a user-mode anti-debug speed bump, then hands control to your original
program unchanged.

> **Scope & honesty.** These passes defeat *static* analysis and make casual
> dynamic analysis harder. They are **not** a wall: a debugger that hides the PEB
> or attaches late, or a memory dump taken after startup, still recovers
> everything. There is no code virtualization here. Use this on software you own
> or are authorized to protect, and **always test the output** before shipping.

## What's in the box

| Component | Kind | What it does |
|-----------|------|--------------|
| `obfuscate.h` | header | Compile-time string encryption. Wrap literals in `OBF("...")`; the plaintext never lands in `.rdata`, and each use decrypts into a wiped stack buffer at run time. |
| `strcrypt` | CLI (x64) | Post-compile: encrypts ASCII/UTF-16 string runs in `.rdata`/`.data`, appends a `.pak` decryptor stub at the entry point. |
| `codeenc` | CLI (x64) | Encrypts the `.text` code section; stub decrypts in memory via a TLS callback (ahead of the program's own) or the entry point. Static disassembly sees garbage. |
| `pack` | CLI (x64 + x86) | Compresses (LZSS) **and** encrypts (PAKP, a ChaCha-derived stream cipher with a fresh random 256-bit key per run) the non-loader-critical sections; appends a `.pakp` anti-debug + decrypt + decompress stub. Output is smaller and statically looks like high-entropy noise. |
| `exe-protector` | Win32 GUI | Point-and-click front end: inspect a PE (headers, sections, entropy, imports) and run the string / code / pack passes. Its own strings are `OBF`-encrypted. |

The passes **compose** — each leaves the others' stub section alone (`.pak` /
`.pakc` / `.pakp`) and chains to whatever entry point it finds:

```
strcrypt app.exe a.exe  &&  codeenc a.exe b.exe  &&  pack b.exe app-protected.exe
```

## Protection layers

- **Static string hiding** — `obfuscate.h` (source level) and `strcrypt`
  (post-compile). `strings` / a hex dump reveal nothing.
- **Static code hiding** — `codeenc` and `pack` leave only ciphertext / high-
  entropy data on disk where the code used to be.
- **Polymorphic output** — `strcrypt`/`codeenc` draw a fresh CSPRNG seed per run,
  and `pack` a fresh 256-bit key, so re-protecting the same input yields
  different bytes every time (no fixed signature, and the seeds are *not*
  derivable from the plaintext PE header).
- **Anti-debug** — every stub reads the PEB directly (no API) and **folds** the
  `BeingDebugged` / `NtGlobalFlag` result into the decryption key/seed. In a
  clean process this is a no-op; under a user-mode debugger the data decrypts to
  garbage and the program fails. Because the check is folded into the key rather
  than gated by a branch, NOP-ing a jump does not recover the code.
- **ASLR pinned** — `DYNAMIC_BASE` is cleared so the stub can use fixed VAs
  (safe for EXEs, which load at their preferred base).

## Build

Requires a MinGW-w64 GCC with C++17.

```sh
# Windows, MSYS2 UCRT64:
make                 # builds strcrypt.exe, codeenc.exe, pack.exe, exe-protector.exe

# Cross-compile from Linux:
make CXX=x86_64-w64-mingw32-g++ WINDRES=x86_64-w64-mingw32-windres cli
```

Each binary is built `-static`, so it runs with no extra runtime DLLs.

## Usage

```
strcrypt <input.exe> <output.exe>     # encrypt strings
codeenc  <input.exe> <output.exe>     # encrypt .text
pack     <input.exe> <output.exe>     # compress + encrypt + anti-debug
```

Refuses DLLs, .NET assemblies, already-processed files, and (for the x64-only
tools) non-AMD64 inputs, with a clear message. `pack` handles both x64 and x86.

## Layout

```
pe_core.h      shared PE plumbing: parse/validate, RVA->offset, the loader-
               critical exclusion list (data dirs + import walk), section layout.
               Single-sourced; used by strcrypt, codeenc, pack.
str_core.h     the string/code decryptor cores (plain + anti-debug) and the
               x64/x86 entry & TLS stub framings.
pak_core.h     the pack stub: PAKP cipher, LZSS (de)compressor, decrypt/decompress
               machine code and its framings.
strdec_src.c       annotated source of the plain string/code decryptor.
strdec_ad_src.c    annotated source of the anti-debug string/code decryptor.
stub_src.c         annotated source of the pack anti-debug+decrypt+decompress stub.
main.cpp           the GUI (exe-protector).
test/              a wine-based end-to-end test harness (see test/run_tests.sh).
```

### Regenerating a stub

The stubs are relocation-free machine code extracted from the `*_src.c` files.
Compile with a **MinGW** gcc (so the argument registers and non-volatile saves
match the Windows ABI), verify there are no relocations, then embed the bytes:

```sh
x86_64-w64-mingw32-gcc -O2 -c -fno-stack-protector -fno-asynchronous-unwind-tables \
    -fcf-protection=none -fno-builtin -fomit-frame-pointer strdec_ad_src.c -o d.o
x86_64-w64-mingw32-objdump -dr d.o            # must show one `decrypt`, zero relocations
x86_64-w64-mingw32-objcopy -O binary --only-section=.text d.o d.bin
```

## Testing

`test/run_tests.sh` builds sample exes, runs each pass on them under **wine**, and
checks the protected binaries still produce the right output and exit code (x64
end-to-end; x86 is compile-checked). `test/dbg.c` is a tiny debugger used to
confirm the anti-debug path triggers (protected binaries garble/crash under a
debug port, run clean without one).

## License / intent

For education and for protecting software you own or are authorized to protect.
Not for evading detection of malware or circumventing anyone else's protections.
