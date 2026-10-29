#!/usr/bin/env bash
# End-to-end test harness.
#   x64: build sample exes, protect them with each tool under wine, run the
#        protected output, check stdout + exit code are preserved.
#   x86: compile-only (the container's wine can't run 32-bit PEs).
# Usage: run_tests.sh <dir-with-strcrypt.exe-codeenc.exe-pack.exe>
set -u
export WINEPREFIX=$HOME/.wineprefix WINEDEBUG=-all
TOOLS="${1:?usage: run_tests.sh <tooldir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
run(){ timeout 90 wine "$@" 2>/dev/null; }
PASS=0; FAIL=0
ok(){ echo "    PASS $1"; PASS=$((PASS+1)); }
no(){ echo "    FAIL $1"; FAIL=$((FAIL+1)); }

# --- build x64 samples ---
x86_64-w64-mingw32-gcc -O2 -o hello64.exe hello.c
x86_64-w64-mingw32-gcc -O2 -o tls64.exe  tls.c

# expected (stdout without CR, exit code)
declare -A EOUT=( [hello64]="HELLO_FROM_TEST_EXE_12345" [tls64]=$'TLS_RAN\nHELLO_TLS_11' )
declare -A ERC=(  [hello64]=7 [tls64]=3 )
# which (tool,sample) pairs should run+match cleanly
PAIRS="strcrypt:hello64 codeenc:hello64 codeenc:tls64 pack:hello64 pack:tls64"

runcheck(){ # file expected_out expected_rc label
  local out rc
  out=$(run "./$1"); rc=$?
  out=$(printf '%s' "$out" | tr -d '\r')
  if [ "$out" = "$2" ] && [ "$rc" = "$3" ]; then ok "$4"; else
    no "$4 (out='$out' rc=$rc want out='$2' rc=$3)"; fi
}

echo "=== unprotected baselines (x64) ==="
for s in hello64 tls64; do runcheck $s.exe "${EOUT[$s]}" "${ERC[$s]}" "unprotected $s"; done

echo "=== protected (x64) ==="
for pair in $PAIRS; do
  pass=${pair%%:*}; s=${pair##*:}
  cp $s.exe in.exe
  msg=$(run "$TOOLS/$pass.exe" in.exe o_${pass}_$s.exe 2>&1 | tr -d '\r' | head -1)
  if [ -f o_${pass}_$s.exe ]; then
    runcheck o_${pass}_$s.exe "${EOUT[$s]}" "${ERC[$s]}" "$pass on $s"
    echo "        [$msg]"
  else no "$pass on $s (no output; $msg)"; fi
  rm -f in.exe
done

echo "=== known limitation: strcrypt + TLS-string target (informational) ==="
cp tls64.exe in.exe; run "$TOOLS/strcrypt.exe" in.exe o_strcrypt_tls64.exe >/dev/null 2>&1; rm -f in.exe
if [ -f o_strcrypt_tls64.exe ]; then
  o=$(run ./o_strcrypt_tls64.exe | tr -d '\r')
  [ "$o" != "${EOUT[tls64]}" ] && echo "    (as documented) TLS-time string not yet decrypted: '$(printf '%s' "$o" | head -1)'" \
                               || echo "    note: strcrypt now also handles TLS-time strings"
fi

echo "=== strings leak check (x64 hello, strcrypt) — want 0 ==="
echo -n "  original marker count: "; strings -n 8 hello64.exe | grep -c HELLO_FROM_TEST_EXE
[ -f o_strcrypt_hello64.exe ] && { echo -n "  after strcrypt: "; strings -n 8 o_strcrypt_hello64.exe | grep -c HELLO_FROM_TEST_EXE; }

echo "=== x86 compile-only check ==="
for t in strcrypt codeenc pack; do
  i686-w64-mingw32-g++ -O2 -std=c++17 -static -o /tmp/x86_$t.exe "$HERE/../$t.cpp" 2>/tmp/x86_$t.err \
    && echo "    PASS x86 compile $t" && PASS=$((PASS+1)) \
    || { echo "    FAIL x86 compile $t"; head -15 /tmp/x86_$t.err; FAIL=$((FAIL+1)); }
done

echo "=== TOTAL: PASS=$PASS FAIL=$FAIL ==="
