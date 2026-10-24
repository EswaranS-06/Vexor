#!/usr/bin/env bash
# =============================================================================
#  tests/split_equivalence.sh [REF]
#
#  Proves that the modular vexor (./vexor + lib/*.sh in the working tree) is the
#  single-file vexor of REF (default: main) cut into pieces, and nothing else:
#    a) text:      ./vexor with every `. "$ROOT/lib/X.sh"` line replaced by lib/X.sh
#                  (minus its 3-line header) reproduces REF:vexor line for line; the only
#                  differences allowed are the loader lines of ./vexor and the edits
#                  listed in SPLIT_EDITS (needed for the lib/ layout) and CLEANUP_EDITS
#                  (the behavior-preserving cleanup, stage cleanup-edits) below. Every edit
#                  must match exactly once in REF:vexor, and the result of applying all of
#                  them to REF:vexor must equal the expanded modules exactly: any other
#                  change, and any edit that no longer matches, fails the run
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

# Edit lists. Format: "@@ <name>" starts an edit; the lines after it are the text block of
# REF:vexor ("-<line>" removed, " <line>" kept as context) and its replacement ("+<line>" added,
# " <line>" kept). The old block (context + removed lines, in order) must occur exactly once in the
# text it is applied to, whitespace exact; no "+" lines means a pure removal.

# 1) Lines of REF:vexor that were changed on purpose to make the code work with lib/.
SPLIT_EDITS="$T/split.edits"
cat > "$SPLIT_EDITS" <<'EDITS'
@@ split: stack-config backup also saves lib/
-  tar czf "$dir/config/stack-config-${stamp}.tar.gz" -C "$ROOT" config .env docker-compose.yml generate-indexer-certs.yml vexor "${extra[@]}" 2>/dev/null \
+  tar czf "$dir/config/stack-config-${stamp}.tar.gz" -C "$ROOT" config .env docker-compose.yml generate-indexer-certs.yml vexor lib "${extra[@]}" 2>/dev/null \
@@ split: restore-config does not overwrite the running lib/
-      tar xzf "$file" -C "$ROOT" --exclude=vexor && ok "config restored - apply with: vexor restart" ;;
+      tar xzf "$file" -C "$ROOT" --exclude=vexor --exclude=lib && ok "config restored - apply with: vexor restart" ;;
EDITS

# 2) The cleanup-edits stage: behavior-preserving cleanup on top of the split (applied after SPLIT_EDITS,
#    so "old" is the text as split). Intentional output changes, all in `vexor completion` (checked in
#    stages b and d): the `volumes` arm gains the word `all`, the shadowed second `volumes` arm is gone.
#    Other observable changes: restore-config's tar excludes are anchored (only the top-level vexor and
#    lib are skipped, not same-named paths deeper in the archive), the support bundle's inner directory is
#    vexor-support-<stamp> instead of wazuh-support-<stamp>. New functions: is_info_cmd, sync_ossec_flag.
#    Removed function: proxy_key_path.
CLEANUP_EDITS="$T/cleanup.edits"
cat > "$CLEANUP_EDITS" <<'EDITS'
@@ item1: remove the unreferenced proxy_key_path (lib/04)
-proxy_key_path() { local p; p="$(env_get PROXY_KEY)"; abspath "${p:-./config/wazuh_indexer_ssl_certs/wazuh.dashboard-key.pem}"; }
@@ item2a: completion volumes arm: offer `all` (volumes backup all) in the arm that is actually used
-      volumes) words="ls orphans backup restore rm prune --stop --out --yes" ;;
+      volumes) words="ls orphans backup restore rm prune all --stop --out --yes" ;;
@@ item2b: completion: drop the unreachable second volumes arm
-      volumes) words="ls backup restore rm prune all --stop --out" ;;
@@ item3a: cmd_install: -y|--yes is stripped by main before dispatch
-      -y|--yes) ASSUME_YES=1 ;;
@@ item3b: cmd_uninstall: -y|--yes is stripped by main before dispatch
-      -y|--yes)    ASSUME_YES=1 ;;
@@ item3c: cmd_migrate: --yes|-y is stripped by main before dispatch
-  case "${1:-}" in ""|--yes|-y) ;; *) die "usage: vexor migrate [--yes]" ;; esac
+  case "${1:-}" in "") ;; *) die "usage: vexor migrate [--yes]" ;; esac
@@ item4a: is_info_cmd defined once (the commands that need no root and are never logged)
-main() {
-  local args=() a cmd=""
+is_info_cmd() {                # help/version/completion: no root needed, nothing logged (used twice in main)
+  case "$1" in help|version|--version|-v|completion) return 0 ;; esac
+  return 1
+}
+
+main() {
+  local args=() a cmd=""
@@ item4b: main: root check through is_info_cmd
-  case "$cmd" in
-    help|version|--version|-v|completion) ;;
-    *)
-      if [ "$(id -u)" -ne 0 ]; then
-        command -v sudo >/dev/null || die "run as root"
-        exec sudo -E "$SELF" "$@"
-      fi ;;
-  esac
+  if ! is_info_cmd "$cmd" && [ "$(id -u)" -ne 0 ]; then
+    command -v sudo >/dev/null || die "run as root"
+    exec sudo -E "$SELF" "$@"
+  fi
@@ item4c: main: action-history list through is_info_cmd
-    case "$cmd" in   # action history (feeds ai-context); read-only commands are not logged
-      help|version|--version|-v|completion|status|st|ps|health|info|urls|logs|log|motd|reminders|ai-context|indexer|ix|api|cluster|watchdog|autoheal|health-check|suricata|zeek|json|plan|login|logins|creds|disk|uninstall) ;;
+    is_info_cmd "$cmd" || case "$cmd" in   # action history (feeds ai-context); read-only commands are not logged
+      status|st|ps|health|info|urls|logs|log|motd|reminders|ai-context|indexer|ix|api|cluster|watchdog|autoheal|health-check|suricata|zeek|json|plan|login|logins|creds|disk|uninstall) ;;
@@ item5: sync_vuln_detection / sync_sca share sync_ossec_flag (same python, regex passed as argument)
-sync_vuln_detection() {        # WAZUH_VULN_DETECTION -> <enabled> of <vulnerability-detection> in every manager ossec.conf; prints "changed"
-  python3 -I - "$(env_def WAZUH_VULN_DETECTION false)" "$CLUSTER_DIR"/wazuh_*.conf <<'PY'
+sync_ossec_flag() {            # sync_ossec_flag <ENV_KEY> <regex up to the <enabled> tag>: env flag -> <enabled> in every manager ossec.conf; prints "changed"
+  python3 -I - "$(env_def "$1" false)" "$2" "$CLUSTER_DIR"/wazuh_*.conf <<'PY'
 import re, sys
 want = "yes" if sys.argv[1].strip().lower() in ("true", "yes", "1", "on") else "no"
-pat = re.compile(r"(<vulnerability-detection>.*?<enabled>)(yes|no)(</enabled>)", re.S)
+pat = re.compile(r"(" + sys.argv[2] + r")(yes|no)(</enabled>)", re.S)
 changed = False
-for path in sys.argv[2:]:
+for path in sys.argv[3:]:
     s = open(path).read()
     n = pat.sub(lambda m: m.group(1) + want + m.group(3), s, count=1)
     if n != s:
         open(path, "w").write(n)          # in-place write keeps the bind-mounted inode
         changed = True
 if changed:
     print("changed")
 PY
 }
-sync_sca() {                   # WAZUH_SCA -> <enabled> of <sca> in every manager ossec.conf; prints "changed"
-  python3 -I - "$(env_def WAZUH_SCA false)" "$CLUSTER_DIR"/wazuh_*.conf <<'PY'
-import re, sys
-want = "yes" if sys.argv[1].strip().lower() in ("true", "yes", "1", "on") else "no"
-pat = re.compile(r"(<sca>\s*<enabled>)(yes|no)(</enabled>)", re.S)
-changed = False
-for path in sys.argv[2:]:
-    s = open(path).read()
-    n = pat.sub(lambda m: m.group(1) + want + m.group(3), s, count=1)
-    if n != s:
-        open(path, "w").write(n)          # in-place write keeps the bind-mounted inode
-        changed = True
-if changed:
-    print("changed")
-PY
-}
+sync_vuln_detection() { sync_ossec_flag WAZUH_VULN_DETECTION '<vulnerability-detection>.*?<enabled>'; }   # <enabled> of <vulnerability-detection>
+sync_sca() { sync_ossec_flag WAZUH_SCA '<sca>\s*<enabled>'; }                                             # <enabled> of <sca>
@@ item6a: render_nginx: profiles was never read
-  local n conns ups i profiles=""
+  local n conns ups i
@@ item6b: cmd_doctor: dr, dp were never read
-  local dr dp warn_pct v
+  local warn_pct v
@@ item6c: cmd_doctor: miss was never read
-    local cl want got miss
+    local cl want got
@@ item6d: agents_enroll_cmd: a was never used
-  local os="all" name="" group="" a
+  local os="all" name="" group=""
@@ item6e: node_type_verify: i was never used
-  local want got i svc
+  local want got svc
@@ item6f: elk_post: i was never used
-  local i c=""
+  local c=""
@@ item6g: show_due_reminders: line was never used
-  local line
@@ item7a: banner of the password helpers in lib/04 (was "passwords", same as lib/09)
-# ============================================================== passwords
-gen_pw() { echo "$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 20)Aa1.-"; }
+# ============================================================== password generation / hashing / internal users
+gen_pw() { echo "$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 20)Aa1.-"; }
@@ item7b: banner of lib/04's second section (it also holds compose profiles, override file and layout migration)
-# ============================================================== cluster key / nginx
+# ============================================================== cluster key / nginx / compose profiles, override and layout migration
@@ item7c: banner of the vexor passwd command in lib/09 (was "passwords")
-# ============================================================== passwords
-cmd_passwd() {
+# ============================================================== vexor passwd
+cmd_passwd() {
@@ item7d: restore-config: anchor the exclude patterns so only the top-level vexor and lib are skipped
-      tar xzf "$file" -C "$ROOT" --exclude=vexor --exclude=lib && ok "config restored - apply with: vexor restart" ;;
+      tar xzf "$file" -C "$ROOT" --anchored --exclude=vexor --exclude=lib && ok "config restored - apply with: vexor restart" ;;
@@ item7e: support bundle: directory prefix wazuh-support- -> vexor-support- (nothing else refers to it)
-  local stamp dir out; stamp="$(date +%Y%m%d-%H%M%S)"; dir="$RUN_TMP/wazuh-support-$stamp"; mkdir -p "$dir/logs"
+  local stamp dir out; stamp="$(date +%Y%m%d-%H%M%S)"; dir="$RUN_TMP/vexor-support-$stamp"; mkdir -p "$dir/logs"
@@ item7f: support bundle: same prefix in the tar call
-  tar czf "$out" -C "$RUN_TMP" "wazuh-support-$stamp" && chmod 600 "$out"
+  tar czf "$out" -C "$RUN_TMP" "vexor-support-$stamp" && chmod 600 "$out"
EDITS
EXPECT_ADDED="is_info_cmd sync_ossec_flag"       # functions that exist only after the cleanup
EXPECT_REMOVED="proxy_key_path"                 # functions that only exist in REF
# `vexor completion` after the cleanup == REF's output with this sed applied (the only intended output change)
expected_completion() {
  sed -e 's/^\(      volumes) words="ls orphans backup restore rm prune\) --stop --out --yes" ;;$/\1 all --stop --out --yes" ;;/' \
      -e '/^      volumes) words="ls backup restore rm prune all --stop --out" ;;$/d'
}
# apply_edits.py <edits-file> <in> <out>: applies the blocks one after the other, each exactly once
APPLY_PY="$T/apply_edits.py"
cat > "$APPLY_PY" <<'PYEOF'
import sys
def parse(path):
    blocks, cur = [], None
    for l in open(path).read().split("\n")[:-1]:
        if l.startswith("@@ "):
            cur = [l[3:], [], []]; blocks.append(cur)
        else:
            tag, body = l[:1], l[1:]
            assert tag in ("-", "+", " "), l
            if tag in "- ": cur[1].append(body)
            if tag in "+ ": cur[2].append(body)
    return blocks
def apply(text, blocks, verbose=False):
    for name, old, new in blocks:
        o = "\n".join(old) + "\n"; n = "\n".join(new) + ("\n" if new else "")
        c = text.count(o)
        if c != 1:
            sys.exit(f"  FAIL  edit '{name}': old block found {c} times (expected exactly 1): {old[0].strip()[:80]!r}")
        text = text.replace(o, n)
        if verbose:
            print(f"        ~ {name}  ({len(o.splitlines())} line(s) -> {len(n.splitlines())})")
    return text
if __name__ == "__main__":      # apply_edits.py <in> <out> <edits-file>...  (verbose when <out> is -)
    text = open(sys.argv[1], newline="").read()
    for ef in sys.argv[3:]:
        text = apply(text, parse(ef), verbose=sys.argv[2] == "-")
    if sys.argv[2] != "-":
        open(sys.argv[2], "w", newline="").write(text)
PYEOF

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
python3 - "$T/orig.vexor" "$REPO" "$SPLIT_EDITS" "$CLEANUP_EDITS" "$T" <<'PY' || FAIL=1
import difflib, glob, os, re, sys
orig_path, repo, split_path, cleanup_path, tmp = sys.argv[1:6]
sys.path.insert(0, tmp)
import apply_edits
def lines(p):
    s = open(p, newline="").read()
    assert "\r" not in s, f"{p}: CR found"
    assert s.endswith("\n"), f"{p}: no final newline"
    return s.split("\n")[:-1]
entry = lines(os.path.join(repo, "vexor"))
orig_text = open(orig_path, newline="").read()
print("  split edits (lib/ layout):")
patched = apply_edits.apply(orig_text, apply_edits.parse(split_path), verbose=True)
print("  cleanup-edits (behavior-preserving cleanup):")
patched = apply_edits.apply(patched, apply_edits.parse(cleanup_path), verbose=True)
orig = patched.split("\n")[:-1]          # REF:vexor + SPLIT_EDITS + CLEANUP_EDITS
n_edits = len(apply_edits.parse(split_path)) + len(apply_edits.parse(cleanup_path))
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
    bad = 1
    print(f"  FAIL  unexpected {op}: original {i1 + 1}-{i2} vs expanded {j1 + 1}-{j2}")
    for l in orig[i1:i2]: print(f"        - {l}")
    for j in range(j1, j2): print(f"        + [{origin[j]}] {expanded[j]}")
if not bad:
    print(f"  PASS  entry + modules == {os.path.basename(orig_path)} with {n_edits} documented edit(s) applied: {same} lines identical and in order, "
          f"nothing else added or removed; {inserted_loader} loader line(s) added in ./vexor; {len(sourced)} modules, headers verified")
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
# the original with SPLIT_EDITS + CLEANUP_EDITS applied as plain text: the new code must match it exactly
python3 "$APPLY_PY" "$T/orig.vexor" "$R/vexor" "$SPLIT_EDITS" "$CLEANUP_EDITS" || { fail "applying the edit lists to $REF:vexor"; }
dump patched
populate new;  dump new
n_o=$(wc -l < "$T/orig.names"); n_n=$(wc -l < "$T/new.names")
if cmp -s "$T/patched.names" "$T/new.names"; then pass "function names identical to the original + edits ($n_n functions)"; else fail "function names differ from the original + edits"; diff "$T/patched.names" "$T/new.names" | head -20; fi
added="$(comm -13 <(sort "$T/orig.names") <(sort "$T/new.names") | paste -sd' ')"; removed="$(comm -23 <(sort "$T/orig.names") <(sort "$T/new.names") | paste -sd' ')"
if [ "$added" = "$EXPECT_ADDED" ] && [ "$removed" = "$EXPECT_REMOVED" ]; then pass "function set vs $REF: added '$added', removed '$removed' (exactly as documented; $n_o -> $n_n functions)"
else fail "function set vs $REF: added '$added' (expected '$EXPECT_ADDED'), removed '$removed' (expected '$EXPECT_REMOVED')"; fi
if cmp -s "$T/patched.funcs" "$T/new.funcs"; then pass "function bodies identical to the original + edits (declare -f, $(wc -c < "$T/new.funcs") bytes)"
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
if cmp -s "$T/patched.calls" "$T/new.calls"; then pass "suggest_command / cmd_help / completion_script / layout_desc called in-process: identical to the original + edits"; else fail "in-process calls differ"; diff "$T/patched.calls" "$T/new.calls" | head -20; fi
expected_completion < "$T/orig.calls" > "$T/orig.calls.expected"
if cmp -s "$T/orig.calls.expected" "$T/new.calls"; then pass "...and vs $REF the only output change is the completion's volumes arm ($(diff "$T/orig.calls" "$T/new.calls" | grep -c '^[<>]') changed lines: +all, second arm removed)"
else fail "in-process output differs from $REF by more than the documented completion change"; diff "$T/orig.calls.expected" "$T/new.calls" | head -20; fi
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
  expected_completion < "$T/orig.case$i" > "$T/orig.case$i.expected"       # no-op except for `completion`
  if cmp -s "$T/orig.case$i" "$T/new.case$i"; then pass "vexor $c  ($(wc -c < "$T/new.case$i") bytes, $(tail -n 1 "$T/new.case$i"))"
  elif cmp -s "$T/orig.case$i.expected" "$T/new.case$i"; then pass "vexor $c  (identical to $REF except the documented volumes arm of the completion)"
  else fail "vexor $c differs"; diff "$T/orig.case$i.expected" "$T/new.case$i" | head -10; fi
  i=$((i + 1)); done
if cmp -s "$T/orig.symlink" "$T/new.symlink"; then pass "vexor --no-color help through a symlink on PATH, cwd=/ (lib/ found via the resolved ROOT)"
else fail "symlinked run differs"; diff "$T/orig.symlink" "$T/new.symlink" | head; fi
# main strips -y/--yes before dispatch, so the per-command -y arms removed from install/uninstall/migrate were unreachable:
# the real main with the three commands stubbed (root faked, no .env) must hand them no flag and set ASSUME_YES=1
head -n -1 "$R/vexor" > "$R/vexor-nomain"
cat > "$T/yes.sh" <<'EOT'
. ./vexor-nomain
id() { echo 0; }; ENV_FILE=/nonexistent
cmd_install() { echo "install[$*] yes=$ASSUME_YES"; }; cmd_uninstall() { echo "uninstall[$*] yes=$ASSUME_YES"; }; cmd_migrate() { echo "migrate[$*] yes=$ASSUME_YES"; }
for a in "install --yes" "install -y --fresh" "-y install" "uninstall -y --keep-data" "uninstall --yes" "migrate -y" "migrate --yes" "migrate"; do ASSUME_YES=0; ( main $a ) 2>&1; done
EOT
got="$(cd "$R" && env -i PATH="$PATH" HOME="$T" bash --norc "$T/yes.sh" 2>&1 | paste -sd' ')"
want="install[] yes=1 install[--fresh] yes=1 install[] yes=1 uninstall[--keep-data] yes=1 uninstall[] yes=1 migrate[] yes=1 migrate[] yes=1 migrate[] yes=0"
[ "$got" = "$want" ] && pass "main strips -y/--yes for install/uninstall/migrate (ASSUME_YES=1, flag not passed on)" || fail "yes handling: $got"
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
