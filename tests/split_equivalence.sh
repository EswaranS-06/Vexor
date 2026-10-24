#!/usr/bin/env bash
# =============================================================================
#  tests/split_equivalence.sh [REF]
#
#  Proves that the modular vexor (./vexor + lib/*.sh in the working tree) is the
#  single-file vexor of REF (default: main) cut into pieces, and nothing else:
#    a) text:      ./vexor with every `. "$ROOT/lib/X.sh"` line replaced by lib/X.sh
#                  (minus its 3-line header) reproduces REF:vexor line for line; the only
#                  differences allowed are the loader lines of ./vexor and the edits
#                  listed in ALLOWED_EDITS below
#    b) functions: sourcing both (with the final `main "$@"` left out) defines the same
#                  functions with identical bodies (declare -f) and the same globals (declare -p)
#    c) syntax:    bash -n on every file, LF endings, file modes, module headers
#    d) behavior:  offline commands give byte-identical output and exit codes
#    e) CI:        the "Generated compose files match the committed ones" step of
#                  .github/workflows/ci.yml passes on the new layout
#  REF must be the last single-file commit (main until the split is merged; after that
#  pass the commit before the merge). Runs as an ordinary user, needs git, bash, python3.
#  Touches nothing outside a temp dir.
# =============================================================================
set -uo pipefail
REPO="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
REF="${1:-main}"
T="$(mktemp -d /tmp/vexor-eq.XXXXXX)"; trap 'rm -rf "$T"' EXIT
R="$T/root"            # both trees are run from this same path, so $ROOT is identical
FAIL=0
pass() { printf '  PASS  %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; FAIL=1; }
skip() { printf '  SKIP  %s\n' "$*"; }
hdr()  { printf '\n== %s\n' "$*"; }

# Lines of REF:vexor that were changed on purpose to make the code work with lib/
# (pairs: one "-<old line>" then one "+<new line>", whitespace exact).
ALLOWED_EDITS="$T/allowed"
cat > "$ALLOWED_EDITS" <<'EDITS'
-  tar czf "$dir/config/stack-config-${stamp}.tar.gz" -C "$ROOT" config .env docker-compose.yml generate-indexer-certs.yml vexor "${extra[@]}" 2>/dev/null \
+  tar czf "$dir/config/stack-config-${stamp}.tar.gz" -C "$ROOT" config .env docker-compose.yml generate-indexer-certs.yml vexor lib "${extra[@]}" 2>/dev/null \
-      tar xzf "$file" -C "$ROOT" --exclude=vexor && ok "config restored - apply with: vexor restart" ;;
+      tar xzf "$file" -C "$ROOT" --exclude=vexor --exclude=lib && ok "config restored - apply with: vexor restart" ;;
EDITS

git -C "$REPO" rev-parse --verify -q "$REF^{commit}" >/dev/null || { echo "unknown ref: $REF"; exit 2; }
git -C "$REPO" show "$REF:vexor" > "$T/orig.vexor" || exit 2
git -C "$REPO" cat-file -e "$REF:lib" 2>/dev/null && { echo "$REF already has lib/ - pass the last single-file commit as REF"; exit 2; }
echo "comparing $REPO (working tree) against $REF:vexor ($(git -C "$REPO" rev-parse --short "$REF"), $(wc -l < "$T/orig.vexor") lines)"

populate() {           # populate orig|new: the tree to run from $R
  rm -rf "$R"; mkdir -p "$R"
  if [ "$1" = orig ]; then
    git -C "$REPO" archive "$REF" | tar -x -C "$R"
  else
    (cd "$REPO" && git ls-files -co --exclude-standard -z | tar --null -T - --ignore-failed-read -cf - 2>/dev/null) | tar -x -C "$R"
  fi
}

# ---------------------------------------------------------------------------- a) text
hdr "a) text: entry + modules in source order == $REF:vexor"
python3 - "$T/orig.vexor" "$REPO" "$ALLOWED_EDITS" <<'PY' || FAIL=1
import difflib, glob, os, re, sys
orig_path, repo, allowed_path = sys.argv[1:4]
def lines(p):
    s = open(p, newline="").read()
    assert "\r" not in s, f"{p}: CR found"
    assert s.endswith("\n"), f"{p}: no final newline"
    return s.split("\n")[:-1]
orig, entry = lines(orig_path), lines(os.path.join(repo, "vexor"))
al = open(allowed_path).read().split("\n")[:-1]
allowed = [(al[i][1:], al[i + 1][1:]) for i in range(0, len(al), 2)]
src = re.compile(r'^\. "\$ROOT/lib/([0-9A-Za-z_.-]+\.sh)"$')
HDR2 = "# Sourced by ./vexor in a fixed order (see the loader there); not executable on its own."
bad = 0
expanded, origin, sourced = [], [], []
for l in entry:
    m = src.match(l)
    if not m:
        expanded.append(l); origin.append("vexor"); continue
    f = m.group(1); sourced.append(f)
    ml = lines(os.path.join(repo, "lib", f))
    h = ml[:3]
    if h[0] != "# shellcheck shell=bash" or not h[1].startswith(f"# vexor lib/{f} - ") or h[2] != HDR2:
        print(f"  FAIL  lib/{f}: unexpected header {h!r}"); bad = 1
    expanded += ml[3:]; origin += [f] * (len(ml) - 3)
on_disk = sorted(os.path.basename(p) for p in glob.glob(os.path.join(repo, "lib", "*.sh")))
if sorted(sourced) != on_disk or len(set(sourced)) != len(sourced):
    print(f"  FAIL  sourced modules {sourced} != lib/*.sh {on_disk}"); bad = 1
if sourced != sorted(sourced):
    print("  FAIL  modules are not sourced in file-name order"); bad = 1
loop = [l for l in entry if l.startswith("for _vexor_mod in ")]
if not loop or loop[0][len("for _vexor_mod in "):].split(";")[0].split() != sourced:
    print("  FAIL  the missing-module check lists other modules than the source lines"); bad = 1
sm = difflib.SequenceMatcher(None, orig, expanded, autojunk=False)
same = inserted_loader = 0; used = []
for op, i1, i2, j1, j2 in sm.get_opcodes():
    if op == "equal":
        same += i2 - i1; continue
    if op == "insert" and all(origin[j] == "vexor" for j in range(j1, j2)):
        inserted_loader += j2 - j1
        print(f"        + {j2 - j1} loader line(s) of ./vexor after original line {i1}")
        continue
    if op == "replace" and i2 - i1 == j2 - j1 and all((orig[i1 + k], expanded[j1 + k]) in allowed for k in range(i2 - i1)):
        for k in range(i2 - i1):
            used.append((orig[i1 + k], expanded[j1 + k]))
            print(f"        ~ allowed edit: original line {i1 + k + 1} -> lib/{origin[j1 + k]}: {expanded[j1 + k].strip()[:90]}")
        continue
    bad = 1
    print(f"  FAIL  unexpected {op}: original {i1 + 1}-{i2} vs expanded {j1 + 1}-{j2}")
    for l in orig[i1:i2]: print(f"        - {l}")
    for j in range(j1, j2): print(f"        + [{origin[j]}] {expanded[j]}")
for a in allowed:
    if a not in used: print(f"  FAIL  allowed edit not found (stale ALLOWED_EDITS?): {a[0].strip()[:80]}"); bad = 1
if not bad:
    print(f"  PASS  {len(orig)} original lines: {same} identical and in order, {len(used)} allowed edit(s), "
          f"0 deleted; {inserted_loader} loader line(s) added in ./vexor; {len(sourced)} modules, headers verified")
sys.exit(bad)
PY

# ---------------------------------------------------------------------------- b) functions + globals
hdr "b) functions and globals (sourced with the final main call left out)"
dump() {               # dump <tag>: functions, globals and some in-process calls after sourcing $R/vexor
  local tag="$1" e="$R/vexor"
  [ "$(tail -n 1 "$e")" = 'main "$@"' ] || { fail "$tag: last line of vexor is not main \"\$@\""; return 1; }
  head -n -1 "$e" > "$R/vexor-nomain"
  # shellcheck disable=SC2016
  (cd "$R" && env -i PATH="$PATH" HOME="$T" LANG=C.UTF-8 bash --noprofile --norc -c '
      . ./vexor-nomain || exit 9
      declare -F | sed "s/^declare -f //" > "$1.names"
      declare -f > "$1.funcs"
      declare -p | grep -vE "^declare -[-a-zA-Z]* (BASH_[A-Z_]+|BASHPID|EPOCHREALTIME|EPOCHSECONDS|FUNCNAME|PIPESTATUS|RANDOM|SRANDOM|SECONDS|LINENO|SHLVL|_)=" > "$1.vars"
      { setup_colors; for w in instal stauts backpu updat xyzzy; do printf "%s:%s\n" "$w" "$(suggest_command "$w")"; done
        USE_COLOR=0; setup_colors; cmd_help; completion_script; layout_desc; } > "$1.calls" 2>&1' _ "$T/$tag")
}
populate orig; dump orig
# the original with ALLOWED_EDITS applied as plain text: the new code must match it exactly
python3 - "$T/orig.vexor" "$ALLOWED_EDITS" "$R/vexor" <<'PY'
import sys
s = open(sys.argv[1], newline="").read()
al = open(sys.argv[2]).read().split("\n")[:-1]
for i in range(0, len(al), 2):
    a, b = al[i][1:] + "\n", al[i + 1][1:] + "\n"
    assert s.count(a) == 1, a
    s = s.replace(a, b)
open(sys.argv[3], "w", newline="").write(s)
PY
dump patched
populate new;  dump new
n_o=$(wc -l < "$T/orig.names"); n_n=$(wc -l < "$T/new.names")
if cmp -s "$T/orig.names" "$T/new.names"; then pass "function names identical ($n_n functions)"; else fail "function names differ ($n_o vs $n_n)"; diff "$T/orig.names" "$T/new.names" | head -20; fi
if cmp -s "$T/patched.funcs" "$T/new.funcs"; then pass "function bodies identical to the original + ALLOWED_EDITS (declare -f, $(wc -c < "$T/new.funcs") bytes)"
else fail "function bodies differ"; diff "$T/patched.funcs" "$T/new.funcs" | head -40; fi
python3 - "$T/orig.funcs" "$T/new.funcs" <<'PY'
import re, sys
def funcs(p):
    d, cur = {}, None
    for l in open(p).read().split("\n"):
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*) \(\) $", l)
        if m: cur = m.group(1); d[cur] = []
        elif cur: d[cur].append(l)
    return d
o, n = funcs(sys.argv[1]), funcs(sys.argv[2])
ch = sorted(k for k in o if o[k] != n.get(k))
print(f"  info  functions whose body differs from the untouched original (the allowed edits): {', '.join(ch) or 'none'}; "
      f"{len(o) - len(ch)} of {len(o)} byte-identical")
PY
if cmp -s "$T/orig.vars" "$T/new.vars"; then pass "global variables identical after load ($(wc -l < "$T/new.vars") declare -p lines)"; else fail "globals differ"; diff "$T/orig.vars" "$T/new.vars" | head -20; fi
if cmp -s "$T/orig.calls" "$T/new.calls"; then pass "suggest_command / cmd_help / completion_script / layout_desc called in-process: identical"; else fail "in-process calls differ"; diff "$T/orig.calls" "$T/new.calls" | head -20; fi
python3 - "$T/orig.vexor" "$T/orig.names" <<'PY'
import collections, re, sys
names = [m.group(1) for m in re.finditer(r"^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{", open(sys.argv[1]).read(), re.M)]
d = [n for n, c in collections.Counter(names).items() if c > 1]
loaded = set(open(sys.argv[2]).read().split())
extra = sorted(set(names) - loaded)
print(f"  info  {len(names)} 'name() {{' lines at column 0 in the original text"
      + (f"; defined more than once: {', '.join(d)}" if d else "; none defined twice")
      + (f"; not real functions (inside a heredoc): {', '.join(extra)}" if extra else ""))
PY

# ---------------------------------------------------------------------------- c) syntax + files
hdr "c) bash -n, line endings, modes, headers"
c_fail=0
for f in "$REPO/vexor" "$REPO"/lib/*.sh; do
  out="$(bash -n "$f" 2>&1)"; rel="${f#"$REPO"/}"
  if [ -n "$out" ]; then fail "bash -n $rel: $out"; c_fail=1; continue; fi
  if grep -q $'\r' "$f"; then fail "$rel has CR line endings"; c_fail=1; continue; fi
  if [ "$rel" != vexor ]; then
    if head -c 2 "$f" | grep -q '#!'; then fail "$rel has a shebang (modules are sourced)"; c_fail=1; fi
    if [ -x "$f" ]; then fail "$rel is executable (modules are sourced)"; c_fail=1; fi
  fi
done
[ "$c_fail" = 0 ] && pass "bash -n clean (no errors, no warnings) on vexor + $(ls "$REPO"/lib/*.sh | wc -l) modules; LF only; modules not executable, no shebang"
m="$(git -C "$REPO" ls-files -s vexor | cut -d' ' -f1)"
[ "$m" = 100755 ] && pass "vexor is mode 100755 in git" || fail "vexor mode in git: ${m:-untracked}"
bad="$(git -C "$REPO" ls-files -s lib | awk '$1 != "100644" {print $4}')"
n_lib="$(git -C "$REPO" ls-files lib | wc -l)"
[ -z "$bad" ] && [ "$n_lib" -gt 0 ] && pass "lib/*.sh tracked with mode 100644 ($n_lib files)" || fail "lib files untracked or not 100644: $bad"
a="$(git -C "$REPO" check-attr eol -- vexor lib/01-core.sh | awk '{print $NF}' | sort -u)"
[ "$a" = lf ] && pass ".gitattributes: eol=lf for vexor and lib/*.sh" || fail ".gitattributes eol: $a"

# ---------------------------------------------------------------------------- d) behavior
hdr "d) offline commands: output + exit code"
CASES=("--no-color help" "help" "-h" "--no-color --help" "--no-color version" "version" "--version" "-v" "completion" "--no-color completion" "-q --no-color help")
run_cases() {          # run_cases <tag>
  local c i=0
  mkdir -p "$T/bin"; ln -sfn "$R/vexor" "$T/bin/vexor"
  for c in "${CASES[@]}"; do
    # shellcheck disable=SC2086
    (cd "$T" && env -i PATH="$PATH" HOME="$T" LANG=C.UTF-8 TERM=dumb "$R/vexor" $c > "$T/$1.case$i" 2>&1; echo "exit=$?" >> "$T/$1.case$i")
    i=$((i + 1))
  done
  # through a symlink on PATH (how `daemon install` exposes it), from another cwd
  (cd / && env -i PATH="$T/bin:$PATH" HOME="$T" LANG=C.UTF-8 vexor --no-color help > "$T/$1.symlink" 2>&1; echo "exit=$?" >> "$T/$1.symlink")
}
populate orig; run_cases orig
populate new;  run_cases new
i=0; for c in "${CASES[@]}"; do
  if cmp -s "$T/orig.case$i" "$T/new.case$i"; then pass "vexor $c  ($(wc -c < "$T/new.case$i") bytes, $(tail -n 1 "$T/new.case$i"))"
  else fail "vexor $c differs"; diff "$T/orig.case$i" "$T/new.case$i" | head -10; fi
  i=$((i + 1)); done
if cmp -s "$T/orig.symlink" "$T/new.symlink"; then pass "vexor --no-color help through a symlink on PATH, cwd=/ (lib/ found via the resolved ROOT)"
else fail "symlinked run differs"; diff "$T/orig.symlink" "$T/new.symlink" | head; fi
for t in orig new; do grep -q "^Console " "$T/$t.case0" || fail "$t help lacks the Console section"; done
if [ "$(id -u)" -ne 0 ]; then
  skip "plan --json / config / status / doctor: vexor re-execs them with sudo and they read .env and docker - not run"
fi
# a missing module stops with a clear message instead of running half-loaded code
mv "$R/lib/05-install.sh" "$T/moved.sh"
out="$(env -i PATH="$PATH" HOME="$T" "$R/vexor" help 2>&1)"; rc=$?
mv "$T/moved.sh" "$R/lib/05-install.sh"
if [ "$rc" = 1 ] && [[ "$out" == *"lib/05-install.sh is missing"* ]]; then pass "missing lib/05-install.sh: exit 1 + clear message (new; the single file had no modules)"
else fail "missing module: rc=$rc out=$out"; fi
for t in console/test_complete.py .github/console_allowlist_test.py; do
  [ -f "$R/$t" ] || continue
  if (cd "$R" && python3 "$t" > "$T/py.out" 2>&1); then pass "python3 $t (new layout)"; else fail "python3 $t"; tail -n 15 "$T/py.out"; fi
done

# ---------------------------------------------------------------------------- e) CI compose check
hdr "e) CI step: Generated compose files match the committed ones"
python3 - "$REPO/.github/workflows/ci.yml" > "$T/ci_compose.py" <<'PY'
import re, sys, textwrap
y = open(sys.argv[1]).read()
step = y[y.index("name: Generated compose files match the committed ones"):]
m = re.search(r"python3 - <<'EOF'\n(.*?)\n\s*EOF\n", step, re.S)
print(textwrap.dedent(m.group(1)))
PY
if (cd "$R" && python3 "$T/ci_compose.py"); then pass "the step's script, taken from ci.yml, passes on the new layout"; else fail "CI compose step"; fi
# negative control: the check must notice a generator/committed-file mismatch
sed -i '0,/^    image: /s//    image: CHANGED-/' "$R/docker-compose.tools.yml"
out="$(cd "$R" && python3 "$T/ci_compose.py" 2>&1)"; rc=$?
if [ "$rc" = 1 ] && [[ "$out" == "docker-compose.tools.yml differs from what vexor generates"* ]]; then pass "negative control: a changed docker-compose.tools.yml is reported"
else fail "negative control: rc=$rc $out"; fi

echo
if [ "$FAIL" = 0 ]; then echo "RESULT: equivalent"; exit 0; fi
echo "RESULT: NOT equivalent (see FAIL lines)"; exit 1
