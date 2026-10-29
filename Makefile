# Anti-Reverse — build all tools.
#
# On Windows (MSYS2 UCRT64):   make
# Cross-build (Linux/mingw):    make CXX=x86_64-w64-mingw32-g++ WINDRES=x86_64-w64-mingw32-windres
#
# -static makes each .exe self-contained (no libstdc++/libgcc/libwinpthread
# DLLs needed to run it); the GUI additionally uses -s to strip symbols.

CXX      ?= g++
WINDRES  ?= windres
CXXFLAGS ?= -O2 -std=c++17 -static
GUIFLAGS ?= -O2 -std=c++17 -municode -mwindows -static -s

CLI   = strcrypt.exe codeenc.exe pack.exe
GUI   = exe-protector.exe

all: $(CLI) $(GUI)
cli: $(CLI)

strcrypt.exe: strcrypt.cpp pe_core.h str_core.h pak_core.h
	$(CXX) $(CXXFLAGS) -o $@ strcrypt.cpp
codeenc.exe:  codeenc.cpp  pe_core.h str_core.h pak_core.h
	$(CXX) $(CXXFLAGS) -o $@ codeenc.cpp
pack.exe:     pack.cpp     pe_core.h pak_core.h
	$(CXX) $(CXXFLAGS) -o $@ pack.cpp

resource.o: resource.rc app.manifest
	$(WINDRES) resource.rc resource.o
$(GUI): main.cpp resource.o obfuscate.h pak_core.h str_core.h
	$(CXX) $(GUIFLAGS) -o $@ main.cpp resource.o -lcomdlg32 -lgdi32 -lcomctl32

clean:
	rm -f $(CLI) $(GUI) resource.o

.PHONY: all cli clean
