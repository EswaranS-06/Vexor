# shellcheck shell=bash
# vexor lib/15-detection.sh - vexor wazuh: rules, decoders, CDB lists, integrations, manager config (det_*, DET_PY)
# Sourced by ./vexor in a fixed order (see the loader there); not executable on its own.
# ============================================================== Wazuh (SIEM / XDR)
wazuh_alerts() {               # [-n N] [--level N] [--grep TEXT]: newest alerts of every manager
  local n=20 lvl=0 grep_="" m
  while [ $# -gt 0 ]; do case "$1" in -n) n="${2:?}"; shift ;; --level) lvl="${2:?}"; shift ;; --grep) grep_="${2:?}"; shift ;; esac; shift; done
  soc_wazuh || die "Wazuh is off (SOC=$(soc))"
  for m in $(enabled_managers); do
    is_running "$m" || continue
    dc exec -T "$m" tail -n 3000 /var/ossec/logs/alerts/alerts.json 2>/dev/null
  done | python3 -I -c '
import datetime, json, sys
n, lvl, needle = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3].lower()
rows = []
for line in sys.stdin:
    if needle and needle not in line.lower():
        continue
    try:
        a = json.loads(line)
    except ValueError:
        continue
    r = a.get("rule", {})
    if int(r.get("level", 0)) < lvl:
        continue
    try:
        t = datetime.datetime.strptime(a["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").astimezone()
    except (KeyError, ValueError):
        continue
    rows.append((t, "%s  lvl %-2s  rule %-6s %-16s %s" % (t.strftime("%Y-%m-%d %H:%M:%S"), r.get("level"), r.get("id"),
                 (a.get("agent") or {}).get("name", "-")[:16], r.get("description", ""))))
rows.sort()
print("\n".join(r for _, r in rows[-n:]) if rows else "  no matching alerts")' "$n" "$lvl" "$grep_"
}
cmd_wazuh() {
  local sub="${1:-status}"; shift || true
  case "$sub" in
    status) soc_wazuh || die "Wazuh is off (SOC=$(soc)) - vexor soc wazuh|both"; cmd_health ;;
    alerts) wazuh_alerts "$@" ;;
    logtest) det_logtest "$@" ;;
    rules|decoders|lists) det_files "$sub" "$@" ;;
    integrations|integration) det_integrations "$@" ;;
    config) det_config "$@" ;;
    detection) case "${1:-status}" in status) shift || true; det_status "$@" ;; *) die "usage: vexor wazuh detection status [--json]" ;; esac ;;
    agents) cmd_agents "$@" ;;
    cluster) cmd_cluster ;;
    *) die "usage: vexor wazuh [status] | alerts [-n N] [--level N] [--grep TEXT] | logtest [\"line\"] | rules|decoders|lists ... | integrations ... | config ... | detection status | agents ... | cluster" ;;
  esac
}

# ============================================================== Detection: custom rules, decoders, CDB lists, integrations, manager config
# Source of truth: config/wazuh_custom/{rules,decoders,lists}/ on the host (git-ignored, in every backup). A save is
# checked locally, pushed to the master (Wazuh API, else docker exec), checked by Wazuh itself (wazuh-analysisd -t:
# a failure or a NEW warning such as a duplicated rule id restores the previous version), then copied to the running
# workers and loaded with the API ruleset reload (no restart). ossec.conf changes (integrations, curated settings,
# the raw custom block, the <list> declarations) are checked with the Wazuh daemons' -t -c on a candidate file,
# written to config/wazuh_cluster/*.conf between vexor:<name> begin/end markers, and the managers are recreated
# (rolled back if one does not come up). Versions: .state/detection-history/<kind>/<name>/<UTC stamp>, last 20.
# Built-in Wazuh files (source "wazuh") are edited the same way: the first save records <kind>/<name> in
# config/wazuh_custom/.overrides (the shipped original becomes the first version) and the edited copy lives in
# config/wazuh_custom/<kind>/<name> like a custom file. Rules/decoders: /var/ossec/ruleset is in the image (lost
# when a manager is recreated), so the copy goes to etc/rules|decoders under the SAME name and the original is
# excluded with a path-qualified <rule_exclude>ruleset/rules/<name></rule_exclude> (<decoder_exclude> likewise) in
# the vexor:excludes block. Checked with wazuh-analysisd -t -d (4.14): a bare file name is matched against every
# rule_dir, so it would drop the copy too; the ruleset/... form drops only the shipped file. overwrite="yes" is no
# substitute: it replaces single rules, not a whole file (removed rules, decoders, group changes). A copy loaded next
# to its original is caught by the -t check (duplicated rule ids are new WARNINGs, duplicated decoders are errors).
# Lists already live in the persistent etc/lists and are declared by the shipped ossec.conf: the copy overwrites
# the file in place (no exclude, no extra <list>); the original is kept in config/wazuh_custom/.originals for reset.
DET_DIR="$ROOT/config/wazuh_custom"
DET_OVR="$DET_DIR/.overrides"
DET_TPL_DIR="$ROOT/config/detection-templates"
DET_HIST="$ROOT/.state/detection-history"
DET_STATUS="$ROOT/.state/detection-status.json"
DET_KEEP=20
DET_ERR=""
read -r -d '' DET_PY <<'PY' || true
import hashlib, json, os, re, sys, time
from xml.sax.saxutils import escape

TAG = re.compile(r"<!--.*?-->|<!\[CDATA\[.*?\]\]>|<\?.*?\?>|<(/?)([A-Za-z_][\w.:-]*)((?:\s+[^<>]*?)?)\s*(/?)>", re.S)
ATTR = re.compile(r"([\w.:-]+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)')")


def lineno(s, pos):
    return s.count("\n", 0, pos) + 1


def scan(s):
    """Wazuh's XML reader is lenient (bare & and < inside regexes are fine), so check the tag structure only:
    -> (elements [(name, attrs, depth, parent, line)], error or None)"""
    stack, out = [], []
    for m in TAG.finditer(s):
        if not m.group(2):
            continue
        close, name, attrs, selfclose = m.group(1), m.group(2), m.group(3) or "", m.group(4)
        if close:
            if not stack:
                return out, f"line {lineno(s, m.start())}: </{name}> closes nothing"
            if stack[-1][0] != name:
                return out, f"line {lineno(s, m.start())}: </{name}> found, </{stack[-1][0]}> expected (opened on line {stack[-1][1]})"
            stack.pop()
            continue
        a = {k: v1 or v2 for k, v1, v2 in ATTR.findall(attrs)}
        out.append((name, a, len(stack), stack[-1][0] if stack else None, lineno(s, m.start())))
        if not selfclose:
            stack.append((name, lineno(s, m.start())))
    if stack:
        return out, f"line {stack[-1][1]}: <{stack[-1][0]}> is never closed"
    return out, None


def rule_ids(s):
    els, err = scan(s)
    ids = []
    for name, a, depth, parent, ln in els:
        if name == "rule" and "id" in a:
            ids.append((a["id"], a.get("overwrite", "").lower() == "yes", ln, a.get("level")))
    return ids, els, err


def read(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def list_lines(s):
    return [ln for ln in s.splitlines() if ln.strip()]


LIST_LINE = re.compile(r'^(?:"[^"]+"|[^":][^:]*)(?::.*)?$')


def check(kind, path, name, custom_dir, extra):
    """Local validation before anything is pushed. Prints one problem per line; exit 1 when there is one."""
    errs = []
    try:
        raw = open(path, "rb").read()
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        print("the file is not UTF-8 text"); sys.exit(1)
    if "\x00" in s:
        errs.append("the file contains NUL bytes")
    if kind == "lists":
        for i, ln in enumerate(s.splitlines(), 1):
            if not ln.strip():
                continue
            if ln.lstrip().startswith("#"):
                errs.append(f"line {i}: CDB lists cannot hold comments"); continue
            if not LIST_LINE.match(ln.strip()):
                errs.append(f"line {i}: '{ln[:80]}' is not key[:value] (quote a key that contains ':')")
        if not list_lines(s):
            errs.append("the list is empty")
    else:
        if not s.strip():
            errs.append("the file is empty")
        ids, els, err = rule_ids(s)
        if err:
            errs.append("XML: " + err)
        if kind == "rules":
            for name_, a, depth, parent, ln in els:
                if name_ == "rule" and depth == 0:
                    errs.append(f"line {ln}: <rule> must be inside <group name=\"...\">")
                if name_ == "group" and depth == 0 and "name" not in a:
                    errs.append(f"line {ln}: <group> needs a name attribute")
            if not ids and not err:
                errs.append("no <rule id=\"...\"> found")
            seen = {}
            others = {}
            builtin = os.environ.get("DET_SOURCE") == "wazuh"     # an edited built-in file keeps Wazuh's own ids
            files = [os.path.join(custom_dir, f) for f in sorted(os.listdir(custom_dir))] if os.path.isdir(custom_dir) else []
            for f in files + [x for x in extra if x]:
                if not f.endswith(".xml") or os.path.basename(f) == name or not os.path.isfile(f):
                    continue
                for rid, ow, _, _ in rule_ids(read(f))[0]:
                    if not (builtin and ow):                      # an overwrite="yes" elsewhere replaces the rule defined here
                        others.setdefault(rid, os.path.basename(f))
            for rid, ow, ln, lvl in ids:
                if not rid.isdigit():
                    errs.append(f"line {ln}: rule id '{rid}' is not a number"); continue
                n = int(rid)
                if not ow and not builtin and not 100000 <= n <= 199999:
                    errs.append(f"line {ln}: rule id {n} is outside 100000-199999 (custom rules; use overwrite=\"yes\" to replace a built-in rule)")
                if rid in seen:
                    errs.append(f"line {ln}: rule id {n} is used twice in this file (line {seen[rid]})")
                seen.setdefault(rid, ln)
                if rid in others and not ow:
                    errs.append(f"line {ln}: rule id {n} is already used in {others[rid]}")
                if lvl is not None and (not lvl.isdigit() or int(lvl) > 16):
                    errs.append(f"line {ln}: level '{lvl}' must be 0-16")
        if kind == "decoders":
            if not any(e[0] == "decoder" for e in els) and not err:
                errs.append("no <decoder name=\"...\"> found")
            for name_, a, depth, parent, ln in els:
                if name_ == "decoder" and "name" not in a:
                    errs.append(f"line {ln}: <decoder> needs a name attribute")
                if name_ == "decoder" and depth != 0:
                    errs.append(f"line {ln}: <decoder> cannot be nested")
    for e in errs:
        print(e)
    sys.exit(1 if errs else 0)


def summary(kind, path, name, source, editable):
    try:
        st = os.stat(path)
        s = read(path)
    except OSError as e:
        return {"name": name, "editable": editable, "source": source, "rules": 0, "ids": None, "size": 0, "mtime": 0, "error": str(e)}
    err = None
    ids = None
    if kind == "lists":
        n = len(list_lines(s))
    else:
        rid, els, err = rule_ids(s)
        if kind == "rules":
            nums = [int(r[0]) for r in rid if r[0].isdigit()]
            n = len(rid)
            ids = [min(nums), max(nums)] if nums else None
        else:
            n = sum(1 for e in els if e[0] == "decoder")
    return {"name": name, "editable": editable, "source": source, "rules": n, "ids": ids, "size": st.st_size,
            "mtime": int(st.st_mtime), "error": err}


def overrides(path, kind):
    """Built-in files edited in config/wazuh_custom (the .overrides manifest: kind/name per line) -> {name}"""
    try:
        return {ln.strip().split("/", 1)[1] for ln in read(path).splitlines() if ln.strip().startswith(kind + "/")}
    except OSError:
        return set()


def ls(kind, custom_dir, builtin_dir, vexor_file, cache, ovr_file="", hist_dir="", conf=""):
    files = []
    ovr = overrides(ovr_file, kind) if ovr_file else set()
    edited = {}                                  # overridden built-ins: listed in place of the shipped file
    if os.path.isdir(custom_dir):
        for dp, dn, fn in os.walk(custom_dir):
            dn[:] = sorted(d for d in dn if not d.startswith(".")) if kind == "lists" and dp == custom_dir else []
            for f in sorted(fn):
                p = os.path.join(dp, f)
                rel = os.path.relpath(p, custom_dir)
                if f.startswith(".") or not (kind == "lists" or f.endswith(".xml")):
                    continue
                if rel in ovr:
                    edited[rel] = dict(summary(kind, p, rel, "wazuh", True), modified=True)
                elif dp == custom_dir:
                    files.append(summary(kind, p, f, "custom", True))
    if vexor_file and os.path.isfile(vexor_file):
        files.append(summary(kind, vexor_file, os.path.basename(vexor_file), "vexor", False))
    hist, shipped = set(), set()
    if kind == "lists":                          # a list with history is ours (maybe deleted) unless Wazuh ships it
        if hist_dir and os.path.isdir(hist_dir):
            hist = {os.path.relpath(dp, hist_dir) for dp, dn, fn in os.walk(hist_dir) if fn}
        if conf and os.path.isfile(conf):
            shipped = set(re.findall(r"<list>etc/lists/([^<]+)</list>", strip_blocks(read(conf))))
    built = None
    if builtin_dir and os.path.isdir(builtin_dir):
        built = []
        for dp, dn, fn in os.walk(builtin_dir):
            for f in sorted(fn):
                p = os.path.join(dp, f)
                rel = os.path.relpath(p, builtin_dir)
                if kind == "lists":
                    if f.endswith(".cdb") or f.startswith(".") or rel in [x["name"] for x in files]:
                        continue
                    if rel in hist and rel not in ovr and rel not in shipped:
                        continue
                elif not f.endswith(".xml"):
                    continue
                built.append(summary(kind, p, rel, "wazuh", True))
        built.sort(key=lambda x: x["name"])
        if cache:
            with open(cache, "w") as fh:
                json.dump(built, fh)
    elif cache and os.path.isfile(cache):
        try:
            built = json.load(open(cache))
        except ValueError:
            built = None
    custom = {x["name"] for x in files}
    built = [dict(edited.pop(b["name"], b), editable=True) for b in (built or []) if b["name"] not in custom]
    built = [dict(b, modified=b.get("modified", False)) for b in built]
    files += sorted(built + list(edited.values()), key=lambda x: x["name"])
    print(json.dumps({"files": files, "builtin": built is not None}))


def history(d):
    vs = []
    if os.path.isdir(d):
        for f in sorted(os.listdir(d), reverse=True):
            p = os.path.join(d, f)
            st = os.stat(p)
            when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(st.st_mtime))
            vs.append({"id": f, "size": st.st_size, "when": when})
    print(json.dumps({"versions": vs}))


def templates(d, kind):
    out = []
    sub = os.path.join(d, kind)
    if os.path.isdir(sub):
        for f in sorted(os.listdir(sub)):
            p = os.path.join(sub, f)
            if not os.path.isfile(p):
                continue
            s = read(p)
            m = re.search(r"<!--\s*vexor-template:\s*id=(.*?);\s*title=(.*?);\s*description=(.*?)\s*-->", s, re.S)
            if m:
                tid, title, desc = (x.strip() for x in m.groups())
            elif kind == "lists":
                tid = re.sub(r"\.example$", "", f); title = tid; desc = "sample list (one key[:value] per line)"
            else:
                continue
            out.append({"id": tid, "title": title, "description": desc, "kind": kind,
                        "file": os.path.relpath(p, os.path.dirname(os.path.dirname(d))), "content": s})
    print(json.dumps({"templates": out}))


# ---------------------------------------------------------------- ossec.conf blocks
def block_re(tag):
    return re.compile(r"[ \t]*<!-- vexor:" + tag + r" begin[^>]*-->.*?<!-- vexor:" + tag + r" end -->\n?", re.S)


def set_block(s, tag, body, where="</ossec_config>"):
    """Replace the vexor:<tag> block (keeps its place) or add it before `where`; empty body removes it."""
    pat = block_re(tag)
    blk = ""
    if body:
        blk = f"  <!-- vexor:{tag} begin -->\n{body}  <!-- vexor:{tag} end -->\n"
    if pat.search(s):
        first = [True]
        return pat.sub(lambda m: (blk if first.pop() else "") if first else "", s)
    if not blk:
        return s
    i = s.find(where)
    if i < 0:
        i = s.find("</ossec_config>")
    line_start = s.rfind("\n", 0, i) + 1
    if s[line_start:i].strip() == "":
        i = line_start
    return s[:i] + blk + s[i:]


def block_body(s, tag):
    m = block_re(tag).search(s)
    if not m:
        return None
    body = m.group(0)
    body = body[body.index("-->") + 3:]
    body = body[: body.rindex("<!-- vexor:" + tag + " end -->")]
    return body.strip("\n")


def strip_blocks(s):
    """The config without any vexor-managed block (n8n, sensors, integrations, ...)."""
    return re.sub(r"[ \t]*<!-- (?:vexor|wazuhctl):([\w-]+)[: ]begin.*?<!-- (?:vexor|wazuhctl):\1[: ]end -->\n?", "", s, flags=re.S)


def child(xml, tag):
    m = re.search(r"<" + tag + r"(?:\s[^>]*)?>(.*?)</" + tag + r">", xml, re.S)
    return m.group(1).strip() if m else None


N8N_NOTE = "<!-- custom-n8n is managed by vexor n8n: hook_url, level and group can be changed here; the API key is created automatically and is not shown. Remove this block to disconnect n8n. -->"


def integrations(path):
    s = read(path)
    out = []
    managed = block_body(s, "integrations") or ""
    for src, text in (("managed", managed), ("other", strip_blocks(s)), ("n8n", "\n".join(
            m.group(0) for m in re.finditer(r"<!-- (?:vexor|wazuhctl):n8n:begin.*?<!-- (?:vexor|wazuhctl):n8n:end -->", s, re.S)))):
        for m in re.finditer(r"<integration>(.*?)</integration>", text, re.S):
            b = m.group(1)
            lvl = child(b, "level")
            out.append({"name": child(b, "name") or "", "hook_url": child(b, "hook_url") or "",
                        "api_key_set": bool(child(b, "api_key")), "level": int(lvl) if lvl and lvl.isdigit() else None,
                        "group": child(b, "group") or "", "rule_id": child(b, "rule_id") or "",
                        "alert_format": child(b, "alert_format") or "", "managed": src == "managed", "n8n": src == "n8n",
                        "_api_key": child(b, "api_key") or "", "_options": child(b, "options") or ""})
    return out


def integ_body(items):
    body = ""
    for it in items:
        body += "  <integration>\n    <name>%s</name>\n" % escape(it["name"])
        for k in ("hook_url", "api_key", "level", "group", "rule_id", "alert_format"):
            v = it.get(k)
            if v not in (None, ""):
                body += "    <%s>%s</%s>\n" % (k, escape(str(v)), k)
        body += "  </integration>\n"
    return body


def write_cands(outdir, files, fn):
    """Candidate files in outdir (only the changed ones); a candidate already there is edited further."""
    for f in files:
        c = os.path.join(outdir, os.path.basename(f))
        orig = read(f)
        s = read(c) if os.path.isfile(c) else orig
        n = fn(f, s)
        if n != orig:
            with open(c, "w") as fh:
                fh.write(n)
        elif os.path.isfile(c):
            os.remove(c)


CONFIG = [
    # key, section, element, kind, choices, help, scope
    ("log_alert_level", "alerts", "log_alert_level", "int", None, "Lowest rule level that is stored as an alert (1-16)", "all"),
    ("email_notification", "global", "email_notification", "bool", ["yes", "no"], "Send alerts by email (needs smtp_server, email_from, email_to)", "all"),
    ("smtp_server", "global", "smtp_server", "str", None, "SMTP server for alert emails", "all"),
    ("email_from", "global", "email_from", "str", None, "Sender address of alert emails", "all"),
    ("email_to", "global", "email_to", "str", None, "Recipient of alert emails", "all"),
    ("email_alert_level", "alerts", "email_alert_level", "int", None, "Lowest rule level that is emailed (1-16)", "all"),
    ("logall", "global", "logall", "bool", ["yes", "no"], "Store every event in archives.log, also the ones that raise no alert (uses disk)", "all"),
    ("logall_json", "global", "logall_json", "bool", ["yes", "no"], "Store every event in archives.json (uses disk)", "all"),
    ("syscheck_frequency", "syscheck", "frequency", "int", None, "Seconds between file integrity scans of the managers themselves", "all"),
    ("syscheck_directories", "syscheck", "directories", "list", None, "Directories the managers watch for file changes (one entry per <directories>)", "all"),
    ("localfiles", None, None, "list", None, "Log files the master reads, as format:location (e.g. syslog:/var/log/app.log)", "master"),
    ("active_response", None, None, "bool", ["yes", "no"], "Active response (automatic blocking) on or off", "all"),
    ("enrollment_password", None, None, "bool", ["on", "off"], "Agents need a password to enroll (vexor agents password)", "master"),
]
CFG = {c[0]: c for c in CONFIG}


def first_section(s, sec, elem=None):
    """(start, end) of the inner text of the first <sec> that has <elem> (or the first <sec>), outside managed blocks."""
    free = strip_blocks(s)
    cands = list(re.finditer(r"<" + sec + r">(.*?)</" + sec + r">", s, re.S))
    for m in cands:
        if m.group(0) not in free:
            continue
        if elem is None or re.search(r"<" + elem + r"[\s>]", m.group(1)):
            return m.start(1), m.end(1)
    for m in cands:
        if m.group(0) in free:
            return m.start(1), m.end(1)
    return None


def localfile_entries(s):
    out = []
    for m in re.finditer(r"[ \t]*<localfile>(.*?)</localfile>\n?", strip_blocks(s), re.S):
        loc, fmt = child(m.group(1), "location"), child(m.group(1), "log_format")
        if loc and fmt:
            out.append((f"{fmt}:{loc}", m.group(0)))
    return out


def cfg_get(s, key):
    c = CFG[key]
    if key == "localfiles":
        return [e for e, _ in localfile_entries(s)]
    if key == "active_response":
        return "no" if block_body(s, "active-response") else "yes"
    if key == "enrollment_password":
        return "on" if re.search(r"<use_password>yes</use_password>", s) else "off"
    span = first_section(s, c[1], c[2])
    if not span:
        return [] if c[3] == "list" else None
    inner = s[span[0]:span[1]]
    if c[3] == "list":
        return [x.strip() for x in re.findall(r"<" + c[2] + r"(?:\s[^>]*)?>(.*?)</" + c[2] + ">", inner, re.S)]
    return child(inner, c[2])


def cfg_ls(master, worker):
    sm = read(master)
    out = []
    for key, sec, el, kind, choices, help_, scope in CONFIG:
        out.append({"key": key, "value": cfg_get(sm, key), "choices": choices, "help": help_, "scope": scope, "type": kind})
    print(json.dumps({"settings": out}))


def parse_list(v):
    v = v.strip()
    if v.startswith("["):
        items = json.loads(v)
        if not isinstance(items, list) or not all(isinstance(x, str) for x in items):
            raise ValueError("a JSON list of strings is expected")
    elif "\n" in v:
        items = v.split("\n")
    elif ";" in v:
        items = v.split(";")
    else:
        items = v.split(",")          # the console joins list rows with commas
    return [x.strip() for x in items if x.strip()]


def cfg_set(outdir, key, value, files):
    if key not in CFG:
        print(f"unknown setting '{key}' - see: vexor wazuh config ls"); sys.exit(2)
    key_, sec, el, kind, choices, help_, scope = CFG[key]
    if scope == "master":
        files = files[:1]
    if kind == "bool":
        value = value.strip().lower()
        value = {"true": choices[0], "on": choices[0], "1": choices[0], "false": choices[1], "off": choices[1], "0": choices[1]}.get(value, value)
        if value not in choices:
            print(f"{key} must be {' or '.join(choices)}"); sys.exit(2)
    if kind == "int":
        if not value.strip().isdigit():
            print(f"{key} must be a number"); sys.exit(2)
        value = str(int(value))
        if key.endswith("level") and not 1 <= int(value) <= 16:
            print(f"{key} must be 1-16"); sys.exit(2)
    if kind == "str":
        if not re.fullmatch(r"[^<>&\x00-\x1f]{1,256}", value):
            print(f"{key}: 1-256 characters, no < > &"); sys.exit(2)
    if kind == "list":
        try:
            items = parse_list(value)
        except ValueError as e:
            print(f"{key}: {e}"); sys.exit(2)
        for it in items:
            if not re.fullmatch(r"[^<>&\x00-\x1f]{1,512}", it):
                print(f"{key}: '{it[:60]}' has characters a config value cannot hold (< > &)"); sys.exit(2)

    def edit(path, s):
        if key == "active_response":
            body = "  <active-response>\n    <disabled>yes</disabled>\n  </active-response>\n" if value == "no" else ""
            return set_block(s, "active-response", body)
        if key == "localfiles":
            fmts = {"syslog", "json", "snort-full", "squid", "eventlog", "eventchannel", "audit", "mysql_log",
                    "postgresql_log", "nmapg", "iis", "djb-multilog", "multi-line", "apache", "journald", "macos"}
            new = []
            for it in items:
                fmt, sep, loc = it.partition(":")
                if not sep or not loc.strip() or not (fmt in fmts or fmt.startswith("multi-line")):
                    print(f"localfiles: '{it}' must be format:location with a format from: {', '.join(sorted(fmts))}"); sys.exit(2)
                new.append((fmt.strip(), loc.strip()))
            cur = localfile_entries(s)
            keep = {e: blk for e, blk in cur}
            for e, blk in cur:
                s = s.replace(blk, "", 1)
            body = ""
            for fmt, loc in new:
                e = f"{fmt}:{loc}"
                body += keep.get(e) or f"  <localfile>\n    <log_format>{escape(fmt)}</log_format>\n    <location>{escape(loc)}</location>\n  </localfile>\n"
            i = s.find("</ossec_config>")
            ls_ = s.rfind("\n", 0, i) + 1
            if s[ls_:i].strip() == "":
                i = ls_
            return s[:i] + body + s[i:]
        span = first_section(s, sec, el)
        if not span:
            body = f"  <{sec}>\n" + (("".join(f"    <{el}>{escape(x)}</{el}>\n" for x in items)) if kind == "list" else f"    <{el}>{escape(value)}</{el}>\n") + f"  </{sec}>\n"
            return s.replace("</ossec_config>", body + "</ossec_config>", 1)
        inner = s[span[0]:span[1]]
        if kind == "list":
            olds = list(re.finditer(r"([ \t]*)<" + el + r"((?:\s[^>]*)?)>(.*?)</" + el + r">\n?", inner, re.S))
            attrs = {m.group(3).strip(): m.group(2) for m in olds}
            ind = olds[0].group(1) if olds else "    "
            lines = "".join(f"{ind}<{el}{attrs.get(x, '')}>{escape(x)}</{el}>\n" for x in items)
            if olds:
                new_inner = inner[:olds[0].start()] + lines + "".join(
                    inner[olds[i].end():olds[i + 1].start()] for i in range(len(olds) - 1)) + inner[olds[-1].end():]
            else:
                new_inner = inner.rstrip(" ") + lines + "  "
        else:
            if re.search(r"<" + el + r"(?:\s[^>]*)?>.*?</" + el + ">", inner, re.S):
                new_inner = re.sub(r"(<" + el + r"(?:\s[^>]*)?>).*?(</" + el + ">)", lambda m: m.group(1) + escape(value) + m.group(2), inner, count=1, flags=re.S)
            else:
                new_inner = inner.rstrip(" ") + f"  <{el}>{escape(value)}</{el}>\n  "
        return s[:span[0]] + new_inner + s[span[1]:]
    write_cands(outdir, files, edit)


def main():
    op, a = sys.argv[1], sys.argv[2:]
    if op == "check":
        check(a[0], a[1], a[2], a[3], a[4:])
    elif op == "ls":                   # ls <kind> <custom dir> <built-in dir> <vexor file> <cache> [<overrides> <history dir> <master conf>]
        ls(*a[:8])
    elif op == "history":
        history(a[0])
    elif op == "templates":
        templates(a[0], a[1])
    elif op == "integ-ls":
        items = integrations(a[0])
        print(json.dumps({"integrations": [{k: v for k, v in i.items() if not k.startswith("_")} for i in items]}))
    elif op == "integ-get":            # integ-get <conf> <name> -> the managed integration as JSON (with the key), or {}
        items = [i for i in integrations(a[0]) if i["managed"] and i["name"] == a[1]]
        print(json.dumps(items[0] if items else {}))
    elif op == "integ-raw-show":       # integ-raw-show <conf> -> custom-n8n first (when connected), then the managed integrations block
        # custom-n8n lives in its own vexor:n8n block (vexor n8n connect/disconnect owns it). It is listed here so the code shows
        # every card; its <api_key> line is deliberately NOT printed (the token stays N8N_HOOK_TOKEN and is never shown).
        import textwrap
        out = ""
        for i in integrations(a[0]):
            if i["n8n"]:
                out += ("" if out else N8N_NOTE + "\n") + "<integration>\n  <name>custom-n8n</name>\n"
                for k, v in (("hook_url", i["hook_url"]), ("level", "" if i["level"] is None else str(i["level"])), ("group", i["group"]),
                             ("rule_id", i["rule_id"]), ("alert_format", i["alert_format"])):
                    if v:
                        out += "  <%s>%s</%s>\n" % (k, v, k)      # the values are already XML-escaped (read as they are in ossec.conf)
                out += "</integration>\n"
        rest = textwrap.dedent(block_body(read(a[0]), "integrations") or "").strip("\n")
        print((out + ("\n" if out and rest else "") + rest).rstrip("\n"))
    elif op == "integ-raw-split":      # integ-raw-split <xml> <rest out> <n8n out (json)> <current n8n hook url>: custom-n8n apart from the other blocks
        from urllib.parse import urlsplit
        from xml.sax.saxutils import unescape
        body = read(a[0])
        if body.strip():
            els, err = scan(body)
            if err:
                print("XML: " + err); sys.exit(1)
        pat = re.compile(r"(<!--\s*custom-n8n is managed.*?-->\s*)?<integration>(.*?)</integration>[ \t]*\n?", re.S)
        found, spans = [], []
        for m in pat.finditer(body):
            nm = child(m.group(2), "name") or ""
            if nm == "custom-n8n":
                found.append(m.group(2)); spans.append(m.span())
            elif m.group(1):
                print("the name of the n8n block must stay custom-n8n (found: %s)" % (nm or "none")); sys.exit(1)
        rest = body
        for s0, e0 in reversed(spans):
            rest = rest[:s0] + rest[e0:]
        rest = re.sub(r"<!--\s*custom-n8n is managed.*?-->[ \t]*\n?", "", rest, flags=re.S)       # a leftover note (its block was deleted)
        open(a[1], "w").write(rest)
        info = {"present": False}
        def n8n_check(b, first):
            tags = set(re.findall(r"<([A-Za-z_][\w-]*)", re.sub(r"<!--.*?-->", "", b, flags=re.S)))
            bad = sorted(tags - {"name", "hook_url", "api_key", "level", "group", "alert_format"})
            if bad:
                print("custom-n8n: <%s> is not supported (use hook_url, level and group; the API key and format are managed)" % bad[0]); sys.exit(1)
            hook = unescape(child(b, "hook_url") or "")
            cur = unescape(a[3]) if len(a) > 3 and first else ""
            if not hook:
                print("custom-n8n needs <hook_url>"); sys.exit(1)
            if hook != cur:
                if "://" in hook:
                    u = urlsplit(hook)
                    ok = (u.scheme == "http" and u.hostname == "n8n" and u.port == 5678 and not u.query and not u.fragment
                          and re.fullmatch(r"/webhook(-test)?/[A-Za-z0-9._~/%-]{1,200}", u.path or ""))
                else:
                    ok = re.fullmatch(r"/?[A-Za-z0-9][A-Za-z0-9._~/%-]{0,200}/?", hook)
                if not ok:
                    print("custom-n8n <hook_url> must be the n8n webhook of this stack (http://n8n:5678/webhook/<path>) or just the path (found: %s)" % hook[:80])
                    sys.exit(1)
            lvl = (child(b, "level") or "").strip() or "0"     # <level> is optional: without it every alert goes to n8n (same as 0)
            if not re.fullmatch(r"\d{1,2}", lvl) or int(lvl) > 15:
                print("custom-n8n <level> must be a number from 0 to 15 (found: %s)" % lvl); sys.exit(1)
            grp = unescape(child(b, "group") or "").strip()
            if grp and not re.fullmatch(r"[A-Za-z0-9_.,-]{1,256}", grp):
                print("custom-n8n <group>: rule groups separated by commas (letters, digits, _ . -)"); sys.exit(1)
            return {"hook": hook, "level": int(lvl), "groups": grp}
        seen_hooks = set()
        for i, b in enumerate(found):
            h = n8n_check(b, i == 0)
            key = (h["hook"], h["level"], h["groups"])
            if key in seen_hooks:
                print("custom-n8n is configured twice with the same hook_url, level and group"); sys.exit(1)
            seen_hooks.add(key)
            if i == 0:
                info = dict(h, present=True, extra=[])
            else:
                info["extra"].append(h)
        json.dump(info, open(a[2], "w"))
    elif op == "integ-raw-set":        # integ-raw-set <outdir> <xml file or ''> <conf..>: replace the managed block by hand-written XML
        body = read(a[1]) if a[1] else ""
        if body.strip():
            els, err = scan(body)
            if err:
                print("XML: " + err); sys.exit(1)
            if re.search(r"<!--\s*vexor:|</?ossec_config", body):
                print("the block may not contain <ossec_config> or vexor: markers"); sys.exit(1)
            rest = re.sub(r"<integration>.*?</integration>|<!--.*?-->", "", body, flags=re.S)
            if rest.strip():
                print("only <integration> blocks (and comments) belong here; found: " + rest.strip()[:60]); sys.exit(1)
            conf = read(a[2])
            elsewhere = [i["name"] for i in integrations(a[2]) if not i["managed"]]
            seen = []
            for b in re.findall(r"<integration>(.*?)</integration>", body, re.S):
                nm = child(b, "name") or ""
                if not re.fullmatch(r"slack|pagerduty|virustotal|shuffle|maltiverse|custom-[A-Za-z0-9_-]{1,40}", nm):
                    print("<name> must be slack, pagerduty, virustotal, shuffle, maltiverse or custom-<id> (found: %s)" % (nm or "none")); sys.exit(1)
                if nm == "custom-n8n":
                    print("custom-n8n is set up with the n8n form (Add integration > n8n), not by hand"); sys.exit(1)
                if nm in seen or nm in elsewhere:
                    print("%s is configured twice" % nm); sys.exit(1)
                if nm.startswith("custom-") or nm in ("slack", "shuffle", "maltiverse"):
                    if not child(b, "hook_url"):
                        print("%s needs <hook_url>" % nm); sys.exit(1)
                seen.append(nm)
            import textwrap
            body = "".join("  " + ln + "\n" if ln.strip() else "\n" for ln in textwrap.dedent(body).strip("\n").splitlines())
        else:
            body = ""
        write_cands(a[0], a[2:], lambda f, s: set_block(s, "integrations", body))
    elif op == "integ-names":          # every integration name in the config (managed or not)
        print("\n".join(i["name"] for i in integrations(a[0])))
    elif op == "integ-write":          # integ-write <outdir> <json list of managed integrations> <conf..>
        items = json.load(open(a[1]))
        body = integ_body(items)
        write_cands(a[0], a[2:], lambda f, s: set_block(s, "integrations", body))
    elif op == "lists-block":          # lists-block <outdir> <names (comma)> <conf..>: <list> lines in <ruleset>
        names = [n for n in a[1].split(",") if n]
        body = "".join(f"    <list>etc/lists/{escape(n)}</list>\n" for n in names)

        def ed(f, s):
            if not names:
                return set_block(s, "lists", "")
            pat = block_re("lists")
            if pat.search(s):
                return set_block(s, "lists", body.replace("    <list>", "  <list>"))
            return set_block(s, "lists", body.replace("    <list>", "  <list>"), where="</ruleset>")
        write_cands(a[0], a[2:], ed)
    elif op == "excl-block":           # excl-block <outdir> <rule files (comma)> <decoder files (comma)> <conf..>: path-qualified excludes in <ruleset>
        body = "".join(f"    <rule_exclude>ruleset/rules/{escape(n)}</rule_exclude>\n" for n in a[1].split(",") if n)
        body += "".join(f"    <decoder_exclude>ruleset/decoders/{escape(n)}</decoder_exclude>\n" for n in a[2].split(",") if n)
        write_cands(a[0], a[3:], lambda f, s: set_block(s, "excludes", body, where="</ruleset>"))
    elif op == "lists-declared":
        b = block_body(read(a[0]), "lists") or ""
        print("\n".join(re.findall(r"<list>etc/lists/([^<]+)</list>", b)))
    elif op == "cfg-ls":
        cfg_ls(a[0], a[1] if len(a) > 1 else None)
    elif op == "cfg-get":
        v = cfg_get(read(a[0]), a[1])
        print(json.dumps(v) if isinstance(v, list) else (v or ""))
    elif op == "cfg-set":              # cfg-set <outdir> <key> <value> <master conf> <worker conf..>
        cfg_set(a[0], a[1], a[2], a[3:])
    elif op == "custom-show":
        print(block_body(read(a[0]), "custom") or "")
    elif op == "custom-set":           # custom-set <outdir> <xml file or ''> <conf..>
        body = read(a[1]) if a[1] else ""
        if body.strip():
            els, err = scan(body)
            if err:
                print("XML: " + err); sys.exit(1)
            if re.search(r"<!--\s*vexor:|</?ossec_config", body):
                print("the block may not contain <ossec_config> or vexor: markers"); sys.exit(1)
            import textwrap
            body = "".join("  " + ln + "\n" if ln.strip() else "\n" for ln in textwrap.dedent(body).strip("\n").splitlines())
        else:
            body = ""
        write_cands(a[0], a[2:], lambda f, s: set_block(s, "custom", body))
    elif op == "logtest":              # API answer -> {decoder, fields, rule, alert, messages}
        try:
            d = json.load(open(a[0]))
        except ValueError:
            print(json.dumps({"error": "no answer from the Wazuh API"})); sys.exit(1)
        if d.get("error"):
            print(json.dumps({"error": d.get("detail") or d.get("message") or "logtest failed", "messages": []})); sys.exit(1)
        data = d.get("data") or {}
        o = data.get("output") or {}
        r = o.get("rule")
        fields = {}

        def flat(prefix, v):
            if isinstance(v, dict):
                for k2, v2 in v.items():
                    flat(f"{prefix}.{k2}" if prefix else k2, v2)
            else:
                fields[prefix] = v if isinstance(v, (str, int, float, bool)) or v is None else json.dumps(v)
        flat("", o.get("data") or {})
        pre = o.get("predecoder") or {}
        res = {"decoder": o.get("decoder") or {}, "predecoder": pre, "fields": fields,
               "rule": {"id": str(r.get("id")), "level": r.get("level"), "description": r.get("description"),
                        "groups": r.get("groups") or [], "firedtimes": r.get("firedtimes"), "mitre": r.get("mitre")} if r else None,
               "alert": bool(data.get("alert")), "messages": data.get("messages") or [], "full_log": o.get("full_log"),
               "location": o.get("location")}
        print(json.dumps(res))
    elif op == "status-rec":           # status-rec <file> <kind> <name> <action> <ok 0|1> <message>
        p = a[0]
        try:
            st = json.load(open(p))
        except (OSError, ValueError):
            st = {}
        ev = {"when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kind": a[1], "name": a[2], "action": a[3],
              "ok": a[4] == "1", "message": a[5][-2000:]}
        st["last_change" if a[4] == "1" else "last_error"] = ev
        if a[4] == "1" and st.get("last_error") and st["last_error"].get("kind") == a[1] and st["last_error"].get("name") == a[2]:
            st["last_error"] = None          # the same file saved fine after a failed try
        tmp = p + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(st, fh)
        os.replace(tmp, p)
    elif op == "status":               # status <status file> <rules ls> <decoders ls> <lists ls> <integ ls> <master running 0|1>
        try:
            st = json.load(open(a[0]))
        except (OSError, ValueError):
            st = {}
        counts = {}
        for kind, f in (("rules", a[1]), ("decoders", a[2]), ("lists", a[3])):
            try:
                files = json.load(open(f))["files"]
            except (OSError, ValueError, KeyError):
                files = []
            cu = [x for x in files if x["source"] == "custom"]
            counts[kind] = {"files": len(cu), "entries": sum(x["rules"] for x in cu), "total_files": len(files)}
        try:
            ints = json.load(open(a[4]))["integrations"]
        except (OSError, ValueError, KeyError):
            ints = []
        counts["integrations"] = {"files": len(ints), "managed": sum(1 for i in ints if i["managed"])}
        print(json.dumps({"counts": counts, "last_change": st.get("last_change"), "last_error": st.get("last_error"),
                          "master_running": a[5] == "1"}))
    elif op == "md5":
        for f in a:
            print(hashlib.md5(open(f, "rb").read()).hexdigest() if os.path.isfile(f) else "-")
    else:
        print("unknown op " + op); sys.exit(2)


main()
PY
det_py() { python3 -I -c "$DET_PY" "$@"; }
det_rec() { mkdir -p "$STATE_DIR"; det_py status-rec "$DET_STATUS" "$1" "$2" "$3" "$4" "${5:-}" 2>/dev/null || true; }
det_master() {                 # changes need a running master: Wazuh checks every change before it stays
  soc_wazuh || die "Wazuh is off (SOC=$(soc)) - vexor soc wazuh|both"
  is_running wazuh.master || die "wazuh.master is not running - start it first: vexor start"
}
det_name() {                   # det_name <kind> <name>: the file name (rules/decoders get .xml) or exit; a built-in keeps its own name
  local k="$1" n="${2:-}"
  [ -n "$n" ] || die "usage: vexor wazuh $k <verb> <name>"
  [ "$k" = lists ] || n="${n%.xml}.xml"
  [ "$k:$n" = rules:vexor_tools_rules.xml ] && die "$n is generated by vexor (vexor tools) - read-only"
  det_custom_ok "$k" "$n" && { echo "$n"; return 0; }
  # not a custom name: only an existing built-in Wazuh file (the real listing, or one already edited) - no paths
  if [[ "$n" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}(/[A-Za-z0-9][A-Za-z0-9_.-]{0,80})?$ ]] && [[ "$n" != *..* ]] \
     && { [ "$k" = lists ] || [[ "$n" != */* ]]; } \
     && { det_ovr_has "$k" "$n" || det_builtin_names "$k" | has -xF -- "$n"; }; then
    echo "$n"; return 0
  fi
  [[ "$n" =~ ^[0-9]{4}- ]] && die "$n is not a built-in Wazuh file (vexor wazuh $k ls) - a custom file cannot use a built-in name (NNNN-...)"
  case "$k:$n" in lists:audit-keys|lists:security-eventchannel|lists:amazon|lists:malicious-ioc) die "$n is not a Wazuh list file (vexor wazuh lists ls)" ;; esac
  die "invalid name '$2': 1-64 letters, digits, _ or -, starting with a letter or digit (or a built-in file: vexor wazuh $k ls)"
}
det_custom_ok() {              # det_custom_ok <kind> <file name>: a custom file name (else it can only be a built-in Wazuh file)
  local k="$1" n="$2"
  [ "$k" = lists ] || { [[ "$n" == *.xml ]] || return 1; n="${n%.xml}"; }
  [[ "$n" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ ]] && [[ ! "$n" =~ ^[0-9]{4}- ]] || return 1
  case "$k:$n" in lists:audit-keys|lists:security-eventchannel|lists:amazon|lists:malicious-ioc) return 1 ;; esac
  return 0
}
det_builtin_names() {          # det_builtin_names <kind>: names of the built-in (source wazuh) files, edited or not
  det_ls_json "$1" 2>/dev/null | python3 -I -c 'import json, sys
print("\n".join(f["name"] for f in json.load(sys.stdin).get("files", []) if f.get("source") == "wazuh"))' 2>/dev/null
  return 0
}
det_ovr_has() { grep -qxF -- "$1/$2" "$DET_OVR" 2>/dev/null; }
det_ovr_list() { [ -f "$DET_OVR" ] && grep -E "^$1/" "$DET_OVR" | cut -d/ -f2-; return 0; }
det_ovr_add() { det_ovr_has "$1" "$2" || { mkdir -p "$DET_DIR"; echo "$1/$2" >> "$DET_OVR"; }; }
det_ovr_del() { [ -f "$DET_OVR" ] || return 0; grep -vxF -- "$1/$2" "$DET_OVR" > "$DET_OVR.tmp"; mv -f "$DET_OVR.tmp" "$DET_OVR"; }
det_wazuh_orig() {             # det_wazuh_orig <kind> <name> <out>: the shipped file as the master has it now
  local p="/var/ossec/ruleset/$1/$2"; [ "$1" = lists ] && p="/var/ossec/etc/lists/$2"
  dc exec -T wazuh.master cat "$p" > "$3" 2>/dev/null && [ -s "$3" ]
}
det_conf_svc() {               # ossec.conf file -> manager service
  case "$1" in
    wazuh_manager.conf) echo wazuh.master ;; wazuh_worker.conf) echo wazuh.worker ;;
    wazuh_worker2.conf) echo wazuh2.worker ;; wazuh_worker3.conf) echo wazuh3.worker ;;
  esac
}
det_running_managers() { local m; for m in $(enabled_managers); do is_running "$m" && echo "$m"; done; return 0; }
det_import() {                 # first use: the files already in the master's etc/rules and etc/decoders (local_rules.xml ...) become custom files
  [ -f "$DET_DIR/.imported" ] && return 0
  soc_wazuh && is_running wazuh.master || return 0
  mkdir -p "$DET_DIR/rules" "$DET_DIR/decoders" "$DET_DIR/lists"
  local k f
  for k in rules decoders; do
    for f in $(dc exec -T wazuh.master sh -c "cd /var/ossec/etc/$k 2>/dev/null && ls" 2>/dev/null | tr -d '\r'); do
      [[ "$f" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.xml$ ]] && [ "$f" != vexor_tools_rules.xml ] && [ ! -e "$DET_DIR/$k/$f" ] || continue
      dc exec -T wazuh.master cat "/var/ossec/etc/$k/$f" > "$DET_DIR/$k/.$f.tmp" 2>/dev/null && mv -f "$DET_DIR/$k/.$f.tmp" "$DET_DIR/$k/$f" \
        && say "imported $k/$f from the master into config/wazuh_custom/$k/"
      rm -f "$DET_DIR/$k/.$f.tmp"
    done
  done
  touch "$DET_DIR/.imported"
}
det_hist_add() {               # det_hist_add <kind> <name> <file>: keep a version (skipped when equal to the newest), last DET_KEEP
  local d="$DET_HIST/$1/$2" st n=0 last
  mkdir -p "$d"; chmod 700 "$DET_HIST" 2>/dev/null
  last="$(ls -1 "$d" 2>/dev/null | sort | tail -1)"
  [ -n "$last" ] && cmp -s "$3" "$d/$last" && return 0
  st="$(date -u +%Y%m%dT%H%M%SZ)"
  while [ -e "$d/$st$([ "$n" -gt 0 ] && echo "-$n")" ]; do n=$((n + 1)); done
  [ "$n" -gt 0 ] && st="$st-$n"
  cp "$3" "$d/$st"
  ls -1 "$d" | sort | head -n -"$DET_KEEP" | while read -r x; do rm -f "${d:?}/$x"; done
}
det_api_upload() {             # det_api_upload <kind> <name> <file>: PUT /<kind>/files/<name>?overwrite=true -> the API answer
  api_login || return 1
  curl -sk --connect-timeout 5 --max-time 60 -X PUT -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/octet-stream' \
       --data-binary @"$3" "https://$(local_ip):$(api_port)/$1/files/$2?overwrite=true"
}
det_exec_write() {             # det_exec_write <svc> <kind> <name> <file>: write a file into /var/ossec/etc/<kind> of a manager (name may be dir/file for lists)
  dc exec -T "$1" sh -c "f=/var/ossec/etc/$2/$3; t=\"\${f%/*}/.\${f##*/}.tmp\"; cat > \"\$t\" && chown wazuh:wazuh \"\$t\" && chmod 660 \"\$t\" \
    && mv -f \"\$t\" \"\$f\"" < "$4"
}
det_push_master() {            # Wazuh API first (it is what the contract with the dashboard uses), docker exec when the API cannot
  local r
  det_custom_ok "$1" "$2" || { det_exec_write wazuh.master "$1" "$2" "$3"; return; }   # built-in names: straight into etc/<kind> (the API resolves names across the shipped ruleset too)
  r="$(det_api_upload "$1" "$2" "$3" 2>/dev/null)"
  has -E '"error": ?0[,}]' <<<"$r" && return 0
  det_exec_write wazuh.master "$1" "$2" "$3"
}
det_push_workers() {           # lists: wazuh-analysisd -t compiles a CDB whose text is newer, so the reload finds it current (the master's runs in det_verify)
  local m; for m in $(det_running_managers); do
    [ "$m" = wazuh.master ] && continue
    det_exec_write "$m" "$1" "$2" "$3" || { warn "$m: could not write $1/$2 (the cluster sync copies it)"; continue; }
    [ "$1" = lists ] && dc exec -T "$m" /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1
  done; return 0
}
det_rm_remote() {              # det_rm_remote <kind> <name> [workers]: delete from the master (API, then rm for leftovers like .cdb) [and workers]
  det_custom_ok "$1" "$2" && api DELETE "/$1/files/$2" >/dev/null 2>&1   # a built-in name: only the copy in etc/<kind>, never the API (it could pick the shipped file)
  local m; for m in wazuh.master ${3:+$(det_running_managers)}; do
    is_running "$m" && dc exec -T "$m" rm -f "/var/ossec/etc/$1/$2" "/var/ossec/etc/$1/$2.cdb" >/dev/null 2>&1
  done
  return 0
}
det_norm() { sed -E 's#^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9:]{8} ##' | grep -E 'WARNING|ERROR|CRITICAL' | grep -v 'Could not set resource limit'; return 0; }
det_rtest() {                  # det_rtest [conf in the master]: wazuh-analysisd -t -> its problem lines; status = analysisd's
  local out rc
  out="$(dc exec -T wazuh.master /var/ossec/bin/wazuh-analysisd -t ${1:+-c "$1"} 2>&1)"; rc=$?
  printf '%s\n' "$out" | det_norm
  return "$rc"
}
det_verify() {                 # det_verify <baseline> [conf]: analysisd accepts it and reports nothing new (a duplicated id is only a WARNING)
  local out rc
  out="$(det_rtest "${2:-}")"; rc=$?
  DET_ERR="$(printf '%s\n' "$out" | grep -vxF -f "$1" | grep -v '^$')"   # new lines only, in Wazuh's order
  [ "$rc" -eq 0 ] && [ -z "$DET_ERR" ] && return 0
  [ -n "$DET_ERR" ] || DET_ERR="${out:-wazuh-analysisd -t failed (exit $rc)}"
  return 1
}
det_daemons_test() {           # the other daemons' own config check on /tmp/vexor-check/ossec.conf (integratord has no -c)
  DET_ERR="$(dc exec -T wazuh.master sh -c 'for d in remoted logcollector syscheckd maild execd csyslogd monitord agentlessd; do
      o="$(/var/ossec/bin/wazuh-$d -t -c /tmp/vexor-check/ossec.conf 2>&1)" || printf "%s\n" "$o"; done' 2>&1 | det_norm)"
  [ -z "$DET_ERR" ]
}
det_problem() {                # det_problem <kind> <name> <action> <title>: print DET_ERR, record it, exit 1
  bad "$4"
  printf '%s\n' "$DET_ERR" | head -20 | sed 's/^/      /'
  det_rec "$1" "$2" "$3" 0 "$4: $DET_ERR"
  exit 1
}
det_reload() {                 # load the ruleset everywhere: API reload (4.14), else recreate the managers
  local r m run
  r="$(api PUT /cluster/analysisd/reload 2>/dev/null)"
  has -E '"error": ?0[,}]' <<<"$r" && has -E '"total_failed_items": ?0[,}]' <<<"$r" || r="$(api PUT /manager/analysisd/reload 2>/dev/null)"
  if has -E '"error": ?0[,}]' <<<"$r" && has -E '"total_failed_items": ?0[,}]' <<<"$r"; then
    ok "ruleset reloaded ($(pj 'print(", ".join(i.get("name", "?") for i in d["data"]["affected_items"]))' <<<"$r" 2>/dev/null))"
    return 0
  fi
  run="$(det_running_managers | tr '\n' ' ')"
  warn "the Wazuh API did not reload the ruleset - recreating $run"
  dc_restart $run >/dev/null 2>&1; API_TOKEN=""
  for m in $run; do wait_daemon "$m" wazuh-analysisd 240 || { bad "$m: wazuh-analysisd not running - vexor logs ossec $m"; return 1; }; done
  ok "managers restarted with the new ruleset"
}
det_conf_apply() {             # det_conf_apply <candidate dir> <kind> <name> <action>: Wazuh checks the new ossec.conf files, then they are
  local cd="$1" k="$2" n="$3" act="$4" f b svc fail="" bak="$RUN_TMP/det-confbak" changed=() svcs=()   # written and the managers recreated
  for f in "$cd"/*.conf; do [ -f "$f" ] && changed+=("$(basename "$f")"); done
  [ ${#changed[@]} -gt 0 ] || return 0
  det_master
  dc exec -T wazuh.master mkdir -p /tmp/vexor-check
  for b in "${changed[@]}"; do
    dc exec -T wazuh.master sh -c 'cat > /tmp/vexor-check/base.conf' < "$CLUSTER_DIR/$b"
    dc exec -T wazuh.master sh -c 'cat > /tmp/vexor-check/ossec.conf' < "$cd/$b"
    if [ -n "${DET_CBASE:-}" ]; then cp "$DET_CBASE" "$RUN_TMP/det-cbase"; else det_rtest /tmp/vexor-check/base.conf > "$RUN_TMP/det-cbase"; fi   # DET_CBASE: state before a file change
    det_verify "$RUN_TMP/det-cbase" /tmp/vexor-check/ossec.conf || det_problem "$k" "$n" "$act" "refused - Wazuh rejects the new $b (nothing changed):"
    det_daemons_test || det_problem "$k" "$n" "$act" "refused - Wazuh rejects the new $b (nothing changed):"
  done
  dc exec -T wazuh.master rm -rf /tmp/vexor-check >/dev/null 2>&1
  mkdir -p "$bak"
  for b in "${changed[@]}"; do
    cp "$CLUSTER_DIR/$b" "$bak/$b"
    cat "$cd/$b" > "$CLUSTER_DIR/$b"           # in-place write keeps the bind-mounted inode
    svc="$(det_conf_svc "$b")"
    [ -n "$svc" ] && is_running "$svc" && svcs+=("$svc")
  done
  [ ${#svcs[@]} -gt 0 ] || { ok "config/wazuh_cluster: ${changed[*]} updated (no running manager to load it)"; return 0; }
  say "recreating ${svcs[*]} to load the new ossec.conf (agents reconnect by themselves) ..."
  dc_restart "${svcs[@]}" >/dev/null 2>&1; API_TOKEN=""
  for svc in "${svcs[@]}"; do
    wait_daemon "$svc" wazuh-analysisd 240 || { fail="$svc"; break; }
    if [ "${DET_WANT_INTEGRATORD:-0}" = 1 ]; then wait_daemon "$svc" wazuh-integratord 90 || { fail="$svc"; break; }; fi
  done
  if [ -n "$fail" ]; then
    DET_ERR="$(dc exec -T "$fail" sh -c 'tail -n 300 /var/ossec/logs/ossec.log' 2>/dev/null | det_norm | tail -8)"
    for b in "${changed[@]}"; do cat "$bak/$b" > "$CLUSTER_DIR/$b"; done
    [ -n "${DET_UNDO:-}" ] && eval "$DET_UNDO"   # the detection files that belong to the previous ossec.conf, back before it is loaded
    say "rolling back: recreating ${svcs[*]} with the previous ossec.conf ..."
    dc_restart "${svcs[@]}" >/dev/null 2>&1; API_TOKEN=""
    for svc in "${svcs[@]}"; do wait_daemon "$svc" wazuh-analysisd 240 || warn "$svc: still not running after the rollback - vexor logs ossec $svc"; done
    det_problem "$k" "$n" "$act" "$fail did not come up with the new ossec.conf - previous config restored:"
  fi
  ok "${svcs[*]} running with the new ossec.conf"
}
det_lists_sync_conf() {        # the <list> declarations (vexor:lists block in <ruleset>) follow config/wazuh_custom/lists -> candidates in $1
  local names x                # edited built-in lists are declared by the shipped ossec.conf already: not here
  names="$(ls -1 "$DET_DIR/lists" 2>/dev/null | grep -E '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$' \
    | while read -r x; do [ -f "$DET_DIR/lists/$x" ] && ! det_ovr_has lists "$x" && echo "$x"; done | paste -sd, -)"
  det_py lists-block "$1" "$names" $(n8n_conf_files)
}
det_excl_sync_conf() {         # the excludes of the edited built-in rules/decoders (vexor:excludes block in <ruleset>) follow .overrides -> candidates in $1
  det_py excl-block "$1" "$(det_ovr_list rules | paste -sd, -)" "$(det_ovr_list decoders | paste -sd, -)" $(n8n_conf_files)
}
det_save() {                   # det_save <kind> <name> <new file | ""> <action>: check, push, let Wazuh check, roll back or load, record
  local k="$1" n="$2" new="$3" act="$4" host="$DET_DIR/$1/$2" prev="" base="$RUN_TMP/det-base" errs cd="$RUN_TMP/det-cand" wz=""
  det_master; take_lock; det_import
  mkdir -p "$DET_DIR/$k"
  det_custom_ok "$k" "$n" || { wz=wazuh; mkdir -p "$(dirname "$host")"; }   # a built-in Wazuh file (det_name checked it against the listing)
  if [ -n "$new" ]; then
    errs="$(DET_SOURCE="$wz" det_py check "$k" "$new" "$n" "$DET_DIR/$k" "$([ "$k" = rules ] && echo "$TOOL_RULES")")" || {
      DET_ERR="$errs"; det_problem "$k" "$n" "$act" "$k/$n refused (nothing changed):"; }
  else
    [ -f "$host" ] || die "$k/$n does not exist (vexor wazuh $k ls)"
  fi
  if [ -f "$host" ]; then prev="$RUN_TMP/det-prev"; cp "$host" "$prev"
  elif [ -n "$wz" ]; then      # first change of a built-in: the override is recorded (the shipped file becomes the first version once saved)
    det_wazuh_orig "$k" "$n" "$RUN_TMP/det-orig" || die "could not read the built-in $k/$n from wazuh.master"
    if [ "$k" = lists ]; then   # the list file itself is replaced in etc/lists: keep the shipped one for reset (rollback writes it back)
      mkdir -p "$(dirname "$DET_DIR/.originals/lists/$n")"; cp "$RUN_TMP/det-orig" "$DET_DIR/.originals/lists/$n"; prev="$RUN_TMP/det-orig"
    fi
    det_ovr_add "$k" "$n"; DET_OVR_NEW=1
  fi
  [ -n "$prev" ] && [ -z "${DET_OVR_NEW:-}" ] && [ -z "$(ls -A "$DET_HIST/$k/$n" 2>/dev/null)" ] && det_hist_add "$k" "$n" "$prev"   # what was there before the first change
  [ -n "$wz" ] && DET_UNDO="$(printf 'det_rollback %q %q %q workers' "$k" "$n" "$prev")"
  det_rtest > "$base"
  if [ -n "$new" ]; then cp "$new" "$host.tmp" && chmod 644 "$host.tmp" && mv -f "$host.tmp" "$host"; det_push_master "$k" "$n" "$host" || { DET_ERR="could not write the file into wazuh.master"; det_rollback "$k" "$n" "$prev"; det_problem "$k" "$n" "$act" "$k/$n not saved:"; }
  else rm -f "$host"; [ -n "$wz" ] && det_ovr_del "$k" "$n"; det_rm_remote "$k" "$n"; fi
  rm -rf "$cd"; mkdir -p "$cd"
  if [ "$k" = lists ]; then det_lists_sync_conf "$cd"; else det_excl_sync_conf "$cd"; fi
  if [ -n "$(ls -A "$cd")" ]; then           # a list was added or removed, a built-in rules/decoders file was (un)excluded: ossec.conf changes, the managers are recreated
    [ -n "$new" ] && det_push_workers "$k" "$n" "$host"
    ( DET_CBASE="$base" det_conf_apply "$cd" "$k" "$n" "$act" ) || { say "rolling back $k/$n ..."; det_rollback "$k" "$n" "$prev" workers; exit 1; }
    [ -z "$new" ] && det_rm_remote "$k" "$n" workers
  else
    if ! det_verify "$base"; then
      det_rollback "$k" "$n" "$prev"
      det_problem "$k" "$n" "$act" "Wazuh rejected $k/$n - $([ -n "$prev" ] && echo "the previous version is back" || echo "the new file was removed"), the running ruleset is unchanged:"
    fi
    if [ -n "$new" ]; then det_push_workers "$k" "$n" "$host"; else det_rm_remote "$k" "$n" workers; fi
    det_reload || { det_rec "$k" "$n" "$act" 0 "saved, but the reload failed"; exit 1; }
  fi
  [ -n "${DET_OVR_NEW:-}" ] && [ -z "$(ls -A "$DET_HIST/$k/$n" 2>/dev/null)" ] && det_hist_add "$k" "$n" "$RUN_TMP/det-orig"   # the shipped file, before the first change
  [ -n "$new" ] && [ "$act" != reset ] && det_hist_add "$k" "$n" "$host"
  if [ "$act" = reset ] && [ -n "$new" ]; then   # a list's shipped content is back in etc/lists: forget the override
    rm -f "$host" "$DET_DIR/.originals/$k/$n"; det_ovr_del "$k" "$n"
    [[ "$n" == */* ]] && rmdir "${host%/*}" "$DET_DIR/.originals/$k/${n%/*}" 2>/dev/null   # amazon/, malicious-ioc/ when empty
  fi
  det_rec "$k" "$n" "$act" 1 "$k/$n ${act}"
  if [ "$act" = reset ]; then ok "$k/$n: reset done - the shipped Wazuh file is active again (history kept)"
  else ok "$k/$n: $act done$([ -n "$new" ] && echo " ($(det_count "$k" "$host"))")"; fi
}
det_count() { case "$1" in rules) echo "$(grep -c '<rule ' "$2") rules" ;; decoders) echo "$(grep -c '<decoder ' "$2") decoders" ;; *) echo "$(grep -c . "$2") entries" ;; esac; }
det_rollback() {               # det_rollback <kind> <name> <previous file | ""> [workers]: host + master (+ workers) as before
  local k="$1" n="$2" host="$DET_DIR/$1/$2"
  if [ -n "$3" ]; then
    cp "$3" "$host"; det_push_master "$k" "$n" "$host" >/dev/null 2>&1; [ -n "${4:-}" ] && det_push_workers "$k" "$n" "$host"
    det_custom_ok "$k" "$n" || [ -n "${DET_OVR_NEW:-}" ] || det_ovr_add "$k" "$n"   # a failed reset: the override stays
  else
    rm -f "$host"; det_rm_remote "$k" "$n" ${4:+workers}
  fi
  if [ -n "${DET_OVR_NEW:-}" ]; then          # a failed first change of a built-in: no override (a list got its shipped content back above)
    rm -f "$host" "$DET_DIR/.originals/$k/$n"; det_ovr_del "$k" "$n"
    [[ "$n" == */* ]] && rmdir "${host%/*}" "$DET_DIR/.originals/$k/${n%/*}" 2>/dev/null
  fi
  return 0
}
det_reset() {                  # det_reset <kind> <name>: drop the override of a built-in file, Wazuh's shipped file is loaded again
  local k="$1" n="$2" o
  det_custom_ok "$k" "$n" && die "$k/$n is a custom file - reset is for built-in Wazuh files (remove a custom file: vexor wazuh $k rm $n)"
  if [ ! -f "$DET_DIR/$k/$n" ]; then
    det_ovr_has "$k" "$n" || { ok "$k/$n is the shipped Wazuh file - nothing to reset"; return 0; }
    det_master; take_lock; det_ovr_del "$k" "$n"   # a manifest entry without its file: only the exclude has to go
    [ "$k" = lists ] && { ok "$k/$n: reset done"; return 0; }
    rm -rf "$RUN_TMP/det-cand"; mkdir -p "$RUN_TMP/det-cand"; det_excl_sync_conf "$RUN_TMP/det-cand"
    det_conf_apply "$RUN_TMP/det-cand" "$k" "$n" reset; det_rm_remote "$k" "$n" workers
    det_rec "$k" "$n" reset 1 "$k/$n reset"; ok "$k/$n: reset done"; return 0
  fi
  if [ "$k" = lists ]; then    # the shipped content goes back through a normal save (checked, pushed, CDB rebuilt, reloaded)
    o="$DET_DIR/.originals/lists/$n"
    [ -f "$o" ] || o="$DET_HIST/lists/$n/$(ls -1 "$DET_HIST/lists/$n" 2>/dev/null | sort | head -1)"
    [ -f "$o" ] || die "the shipped content of lists/$n is not known (config/wazuh_custom/.originals) - put it back by hand or restore a version (vexor wazuh lists history $n)"
    cp "$o" "$RUN_TMP/det-reset"
    det_save lists "$n" "$RUN_TMP/det-reset" reset
  else                         # the copy in etc/<kind> and its exclude go, the managers are recreated
    det_save "$k" "$n" "" reset
  fi
}
det_read_from() {              # det_read_from <path|->: copy into a temp file, print its path
  local src="${1:-}" t="$RUN_TMP/det-new"
  [ -n "$src" ] || die "--from <path|-> is required"
  if [ "$src" = - ]; then cat > "$t"; else [ -f "$src" ] && [ -r "$src" ] || die "cannot read $src"; cp "$src" "$t"; fi
  [ "$(stat -c %s "$t")" -le 1048576 ] || die "file larger than 1 MB"
  echo "$t"
}
det_list_norm() {              # CDB list lines: CRLF and blank lines dropped, "key" -> "key:"
  sed -i -e 's/\r$//' -e '/^[[:space:]]*$/d' -e '/:/!s/$/:/' "$1"
}
det_ls_json() {                # det_ls_json <kind>: {"files":[...]} (built-in files cached per Wazuh version)
  local k="$1" bdir="" cache="" vf=""
  soc_wazuh && is_running wazuh.master && det_import >&2
  [ "$k" = rules ] && [ -f "$TOOL_RULES" ] && vf="$TOOL_RULES"
  if [ "$k" != lists ]; then cache="$STATE_DIR/detection-builtin-$k-$(cur_version).json"; fi
  if { [ -z "$cache" ] || [ ! -s "$cache" ]; } && soc_wazuh && is_running wazuh.master; then
    bdir="$RUN_TMP/det-builtin-$k"; mkdir -p "$bdir"
    case "$k" in rules|decoders) dc exec -T wazuh.master tar -C "/var/ossec/ruleset/$k" -cf - . 2>/dev/null | tar -C "$bdir" -xf - 2>/dev/null ;;
                 lists) dc exec -T wazuh.master tar -C /var/ossec/etc/lists -cf - . 2>/dev/null | tar -C "$bdir" -xf - 2>/dev/null ;;   # ours (with history) are dropped in ls
    esac
    mkdir -p "$STATE_DIR"
  fi
  det_py ls "$k" "$DET_DIR/$k" "$bdir" "$vf" "$cache" "$DET_OVR" "$DET_HIST/$k" "$CLUSTER_DIR/wazuh_manager.conf"
}
det_files() {                  # vexor wazuh rules|decoders|lists <verb> ...
  local k="$1"; shift
  local verb="${1:-ls}"; shift || true
  local json=0 a rest=() from="" n t
  for a in "$@"; do [ "$a" = --json ] && json=1 || rest+=("$a"); done
  set -- "${rest[@]}"
  case "$verb" in
    ls|list)
      soc_wazuh || die "Wazuh is off (SOC=$(soc))"
      t="$(det_ls_json "$k")"
      if [ "$json" = 1 ]; then printf '%s\n' "$t"; return 0; fi
      pj '
rows = d["files"]
w = max([len(r["name"]) for r in rows] + [4])
print("  %-*s %-7s %6s  %-13s %8s  %s" % (w, "NAME", "SOURCE", "COUNT", "IDS", "SIZE", "CHANGED"))
import time
for r in rows:
    ids = "%s-%s" % tuple(r["ids"]) if r.get("ids") else "-"
    print("  %-*s %-7s %6s  %-13s %8s  %s%s" % (w, r["name"], r["source"] + ("*" if r.get("modified") else ""), r["rules"], ids, r["size"],
          time.strftime("%Y-%m-%d %H:%M", time.localtime(r["mtime"])) if r["mtime"] else "-", "  ERROR " + r["error"] if r.get("error") else ""))
if any(r.get("modified") for r in rows):
    print("  wazuh* = built-in file edited here (vexor wazuh %s reset <name> brings back the shipped one)" % sys.argv[1])
if not d.get("builtin"):
    print("  (built-in files not shown: wazuh.master is not running)")' "$k" <<<"$t" ;;
    show|cat)
      n="${1:-}"; [ -n "$n" ] || die "usage: vexor wazuh $k show <name>"
      [ "$k" = lists ] || [[ "$n" == *.xml ]] || n="$n.xml"
      [[ "$n" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}(/[A-Za-z0-9][A-Za-z0-9_.-]{0,80})?$ ]] && [[ "$n" != *..* ]] || die "invalid name '$1'"
      if [ -f "$DET_DIR/$k/$n" ]; then cat "$DET_DIR/$k/$n"
      elif [ "$k" = rules ] && [ "$n" = vexor_tools_rules.xml ] && [ -f "$TOOL_RULES" ]; then cat "$TOOL_RULES"
      else
        soc_wazuh && is_running wazuh.master || die "$k/$n is not a custom file and wazuh.master is not running"
        case "$k" in lists) t="/var/ossec/etc/lists/$n" ;; *) t="/var/ossec/ruleset/$k/$n" ;; esac
        dc exec -T wazuh.master cat "$t" 2>/dev/null || die "no such file: $k/$n"
      fi ;;
    put|save)
      n="$(det_name "$k" "${1:-}")" || exit 1; shift || true
      while [ $# -gt 0 ]; do case "$1" in --from) from="${2:-}"; shift ;; *) die "unknown option $1" ;; esac; shift; done
      t="$(det_read_from "$from")" || exit 1
      [ "$k" = lists ] && det_list_norm "$t"
      det_save "$k" "$n" "$t" put ;;
    rm|remove|delete)
      n="$(det_name "$k" "${1:-}")" || exit 1
      det_custom_ok "$k" "$n" || die "$k/$n is a built-in Wazuh file - it cannot be removed; undo your changes with: vexor wazuh $k reset $n"
      det_save "$k" "$n" "" rm ;;
    reset)
      n="$(det_name "$k" "${1:-}")" || exit 1
      det_reset "$k" "$n" ;;
    history)
      n="$(det_name "$k" "${1:-}")" || exit 1
      t="$(det_py history "$DET_HIST/$k/$n")"
      if [ "$json" = 1 ]; then printf '%s\n' "$t"; return 0; fi
      pj 'print("\n".join("  %s  %s  %6s bytes" % (v["id"], v["when"], v["size"]) for v in d["versions"]) or "  no versions yet")' <<<"$t" ;;
    restore)
      n="$(det_name "$k" "${1:-}")" || exit 1
      [[ "${2:-}" =~ ^[0-9]{8}T[0-9]{6}Z(-[0-9]+)?$ ]] && [ -f "$DET_HIST/$k/$n/$2" ] || die "no version '${2:-}' of $k/$n (vexor wazuh $k history $n)"
      cp "$DET_HIST/$k/$n/$2" "$RUN_TMP/det-new"
      det_save "$k" "$n" "$RUN_TMP/det-new" restore ;;
    templates)
      t="$(det_py templates "$DET_TPL_DIR" "$k")"
      if [ "$json" = 1 ]; then printf '%s\n' "$t"; return 0; fi
      pj 'print("\n".join("  %-34s %s\n  %-34s %s  ->  %s" % (t["id"], t["title"], "", t["description"], t["file"]) for t in d["templates"]) or "  no templates")' <<<"$t" ;;
    add|del)
      [ "$k" = lists ] || die "usage: vexor wazuh lists add <name> <key>[:<value>] | del <name> <key>"
      n="$(det_name lists "${1:-}")" || exit 1
      local e="${2:-}"; [ -n "$e" ] || die "usage: vexor wazuh lists $verb <name> <key>[:<value>]"
      [[ "$e" =~ [[:cntrl:]] ]] && die "control characters are not allowed"
      t="$RUN_TMP/det-new"; : > "$t"
      if [ -f "$DET_DIR/lists/$n" ]; then cp "$DET_DIR/lists/$n" "$t"
      elif ! det_custom_ok lists "$n"; then det_master; det_wazuh_orig lists "$n" "$t" || die "could not read the built-in lists/$n from wazuh.master"; fi   # first edit of a built-in list
      python3 -I - "$t" "$verb" "$e" <<'PY' || exit 1
import re, sys
path, verb, entry = sys.argv[1:4]
def key(line):
    line = line.strip()
    m = re.match(r'^("[^"]*")', line)
    return m.group(1) if m else line.split(":", 1)[0]
lines = [l.rstrip("\r\n") for l in open(path) if l.strip()]
k = key(entry)
if verb == "add":
    if ":" not in entry[len(k):]:
        entry += ":"
    lines = [l for l in lines if key(l) != k] + [entry]
else:
    if not any(key(l) == k for l in lines):
        print(f"  {k} is not in the list"); sys.exit(1)
    lines = [l for l in lines if key(l) != k]
    if not lines:
        print("  that is the last entry - remove the list with: vexor wazuh lists rm <name>"); sys.exit(1)
open(path, "w").write("".join(l + "\n" for l in lines))
PY
      det_save lists "$n" "$t" "$verb" ;;
    *) die "usage: vexor wazuh $k ls|show|put|rm|reset|history|restore|templates$([ "$k" = lists ] && echo '|add|del') ..." ;;
  esac
}
det_integ_script_missing() {   # det_integ_script_missing <custom-id>: prints the first running manager that lacks its script (a missing one stops integratord, and the change is rolled back)
  local m
  for m in $(enabled_managers); do
    is_running "$m" || continue
    dc exec -T "$m" test -x "/var/ossec/integrations/$1" || { echo "$m"; return 0; }
  done
  return 1
}
det_integ_n8n() {              # det_integ_n8n add|edit|rm [--hook-url PATH|URL] [--level N] [--group G]: custom-n8n is owned by vexor n8n
  local act="$1"; shift
  if [ "$act" = rm ] || [ "$act" = remove ]; then cmd_n8n disconnect; det_rec integrations custom-n8n rm 1 "n8n disconnected"; return; fi
  local hook="" lvl="" grp="" have=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --hook-url) hook="${2-}"; shift ;; --level) lvl="${2-}"; shift ;; --group|--groups) grp="${2-}"; have=1; shift ;;
      --api-key|--api-key-file) shift ;;                 # the token is generated (N8N_HOOK_TOKEN)
      --rule-id|--rule-ids|--format) shift ;;
      *) die "unknown option $1" ;;
    esac; shift
  done
  if [ "$act" = add ] && [ -n "$(n8n_hook)" ]; then die "n8n is already connected - change it with: vexor wazuh integrations edit custom-n8n"; fi
  if [ "$act" = edit ] && [ -z "$(n8n_hook)" ]; then die "n8n is not connected - add it: vexor wazuh integrations add custom-n8n"; fi
  local args=()
  if [ "$act" = edit ]; then args=("${hook:-$(n8n_hook)}"); else args=("${hook:-vexor-alerts}"); fi
  [ -n "$lvl" ] && args+=(--level "$lvl")
  if [ "$have" = 1 ]; then args+=(--groups "$grp"); else args+=(--groups "$(env_get N8N_ALERT_GROUPS)"); fi
  cmd_n8n connect "${args[@]}" || return 1
  det_rec integrations custom-n8n "$act" 1 "n8n connected: $(n8n_hook)"
}
det_integrations() {           # vexor wazuh integrations ls|add|edit|rm|raw|test
  local verb="${1:-ls}"; shift || true
  local json=0 a rest=() t
  for a in "$@"; do [ "$a" = --json ] && json=1 || rest+=("$a"); done
  set -- "${rest[@]}"
  soc_wazuh || die "Wazuh is off (SOC=$(soc))"
  local conf="$CLUSTER_DIR/wazuh_manager.conf"
  case "$verb" in
    ls|list)
      t="$(det_py integ-ls "$conf")"
      if [ "$json" = 1 ]; then printf '%s\n' "$t"; return 0; fi
      pj '
rows = d["integrations"]
print("  %-18s %-6s %-8s %-14s %-10s %s" % ("NAME", "LEVEL", "API KEY", "GROUP", "RULE IDS", "HOOK URL"))
for r in rows:
    print("  %-18s %-6s %-8s %-14s %-10s %s%s" % (r["name"], r["level"] if r["level"] is not None else "-", "set" if r["api_key_set"] else "-",
          r["group"] or "-", r["rule_id"] or "-", r["hook_url"] or "-", "" if r["managed"] else "   (not managed here)"))
if not rows:
    print("  no integrations - add one: vexor wazuh integrations add slack --hook-url https://hooks.slack.com/...")' <<<"$t" ;;
    add|edit|rm|remove)
      local n="${1:-}"; shift || true
      [[ "$n" =~ ^(slack|pagerduty|virustotal|shuffle|maltiverse|custom-[A-Za-z0-9_-]{1,40})$ ]] \
        || die "usage: vexor wazuh integrations $verb <slack|pagerduty|virustotal|shuffle|maltiverse|custom-<id>> [options]"
      if [ "$n" = custom-n8n ]; then det_integ_n8n "$verb" "$@"; return; fi     # same thing as vexor n8n connect / disconnect
      local hook="-" key="-" lvl="-" grp="-" rid="-" fmt="-"
      while [ $# -gt 0 ]; do
        case "$1" in
          --hook-url) hook="${2-}"; shift ;; --api-key) key="${2-}"; shift ;; --level) lvl="${2-}"; shift ;;
          --api-key-file) [ -r "${2:-}" ] || die "cannot read ${2:-}"; key="$(head -c 4096 "$2" | tr -d '\r\n')"; shift ;;   # keeps the key out of argv
          --group|--groups) grp="${2-}"; shift ;; --rule-id|--rule-ids) rid="${2-}"; shift ;; --format) fmt="${2-}"; shift ;;
          *) die "unknown option $1" ;;
        esac; shift
      done
      det_master; take_lock
      local js="$RUN_TMP/det-integ.json" cd="$RUN_TMP/det-cand" act="$verb"; [ "$act" = remove ] && act=rm
      rm -rf "$cd"; mkdir -p "$cd"
      python3 -I - "$conf" "$js" "$act" "$n" "$hook" "$key" "$lvl" "$grp" "$rid" "$fmt" <<'PY' || exit 1
import json, re, subprocess, sys
conf, out, act, name, hook, key, lvl, grp, rid, fmt = sys.argv[1:11]
src = open(conf).read()
# the managed block only; parsed the same way det_py does
m = re.search(r"<!-- vexor:integrations begin[^>]*-->(.*?)<!-- vexor:integrations end -->", src, re.S)
def child(x, t):
    r = re.search(r"<" + t + r"(?:\s[^>]*)?>(.*?)</" + t + ">", x, re.S)
    return r.group(1).strip() if r else ""
from xml.sax.saxutils import unescape
items = [{k: unescape(child(b, k)) for k in ("name", "hook_url", "api_key", "level", "group", "rule_id", "alert_format")}
         for b in re.findall(r"<integration>(.*?)</integration>", m.group(1) if m else "", re.S)]
others = [unescape(child(b, "name")) for b in re.findall(r"<integration>(.*?)</integration>", src.replace(m.group(0), "") if m else src, re.S)]
cur = next((i for i in items if i["name"] == name), None)
def die(msg):
    print("  ✘ " + msg); sys.exit(1)
if act == "add":
    if cur or name in others:
        die(f"{name} is already configured - change it with: vexor wazuh integrations edit {name}")
    cur = {"name": name, "hook_url": "", "api_key": "", "level": "", "group": "", "rule_id": "", "alert_format": "json"}
    items.append(cur)
elif not cur:
    die(f"{name} is not a Vexor-managed integration (vexor wazuh integrations ls)" + (" - it is written by hand in ossec.conf" if name in others else ""))
if act == "rm":
    items = [i for i in items if i["name"] != name]
else:
    for k, v in (("hook_url", hook), ("api_key", key), ("level", lvl), ("group", grp), ("rule_id", rid), ("alert_format", fmt)):
        if v != "-":
            cur[k] = v.strip()
    if cur["hook_url"] and not re.fullmatch(r"https?://[^\s<>&\"']{3,500}", cur["hook_url"]):
        die("--hook-url must be an http(s):// URL without spaces, quotes, < > &")
    if cur["api_key"] and not re.fullmatch(r"[^\s<>&]{1,512}", cur["api_key"]):
        die("--api-key may not contain spaces or < > &")
    if cur["level"] and (not cur["level"].isdigit() or int(cur["level"]) > 16):
        die("--level must be 0-16")
    if cur["group"] and not re.fullmatch(r"[A-Za-z0-9_.,-]{1,256}", cur["group"]):
        die("--group: rule groups separated by commas (letters, digits, _ . -)")
    if cur["rule_id"] and not re.fullmatch(r"\d+(,\d+)*", cur["rule_id"]):
        die("--rule-id: rule ids separated by commas")
    if cur["alert_format"] not in ("", "json"):
        die("--format: only json is supported")
    need_hook = name in ("slack", "shuffle", "maltiverse") or name.startswith("custom-")
    need_key = name in ("pagerduty", "virustotal", "maltiverse")
    if need_hook and not cur["hook_url"]:
        die(f"{name} needs --hook-url")
    if need_key and not cur["api_key"]:
        die(f"{name} needs --api-key")
    if name == "virustotal" and not (cur["group"] or cur["rule_id"]):
        cur["group"] = "syscheck"            # VirusTotal only understands file integrity alerts
json.dump(items, open(out, "w"))
PY
      local miss; miss="$([ "$act" != rm ] && [[ "$n" == custom-* ]] && det_integ_script_missing "$n")"
      if [ -n "$miss" ]; then
        bad "$miss has no integration script /var/ossec/integrations/$n"
        hint "copy it into every manager: docker cp $n <container>:/var/ossec/integrations/$n, then chown root:wazuh and chmod 750 it"
        det_rec integrations "$n" "$act" 0 "no script /var/ossec/integrations/$n in $miss"; exit 1
      fi
      det_py integ-write "$cd" "$js" $(n8n_conf_files)
      DET_WANT_INTEGRATORD=0; { [ "$(pj 'print(len(d))' < "$js")" -gt 0 ] || [ -n "$(n8n_hook)" ]; } && DET_WANT_INTEGRATORD=1
      if [ -z "$(ls -A "$cd")" ]; then ok "$n: nothing changed"; return 0; fi
      det_conf_apply "$cd" integrations "$n" "$act"
      det_rec integrations "$n" "$act" 1 "integration $n: $act"
      ok "integration $n: $act done" ;;
    raw)                         # raw show | raw put --from <path|->: the managed integrations as XML, edited by hand
      local rv="${1:-show}"; shift || true
      case "$rv" in
        show) det_py integ-raw-show "$conf" ;;
        put)
          # custom-n8n is owned by vexor n8n (its own marker block, the token in .env): it is split off here and applied with
          # cmd_n8n connect / disconnect; everything else goes through integ-raw-set + det_conf_apply as before.
          # Every check runs before the first change ("refused (nothing changed)").
          local from="" f cd miss rest="$RUN_TMP/det-rest" nj="$RUN_TMP/det-n8n.json" conf_has=0 was=0 want=0 n8n_do="" nurl="" nlvl="" ngrp="" nextra="" rest_changed=0
          while [ $# -gt 0 ]; do case "$1" in --from) from="${2:-}"; shift ;; *) die "unknown option $1" ;; esac; shift; done
          t="$(det_read_from "$from")" || exit 1
          det_master; take_lock
          rm -rf "$RUN_TMP/det-cand"; mkdir -p "$RUN_TMP/det-cand"; cd="$RUN_TMP/det-cand"; rm -f "$rest" "$nj"
          grep -q 'vexor:n8n:begin' "$conf" && conf_has=1
          [ "$conf_has" = 1 ] && [ -n "$(n8n_hook)" ] && was=1
          DET_ERR="$(det_py integ-raw-split "$t" "$rest" "$nj" "$(n8n_hook)" 2>&1)" || det_problem integrations raw put "the integrations were refused (nothing changed):"
          [ "$(pj 'print(1 if d.get("present") else 0)' < "$nj")" = 1 ] && want=1
          if [ "$want" = 1 ]; then
            nurl="$(n8n_hook_url "$(pj 'print(d["hook"])' < "$nj")")"; nlvl="$(pj 'print(d["level"])' < "$nj")"; ngrp="$(pj 'print(d["groups"])' < "$nj")"
            local eh el eg; nextra=""
            while IFS='|' read -r eh el eg; do
              [ -n "$eh" ] && nextra+="${nextra:+;}$(n8n_hook_url "$eh")|$el|$eg"
            done < <(pj 'print("\n".join("%s|%s|%s" % (e["hook"], e["level"], e["groups"]) for e in d.get("extra", [])))' < "$nj")
            if [ "$was" = 0 ] || [ "$nurl" != "$(n8n_hook)" ] || [ "$nlvl" != "$(n8n_level)" ] || [ "$ngrp" != "$(env_get N8N_ALERT_GROUPS)" ] || [ "$nextra" != "$(env_get N8N_EXTRA_HOOKS)" ]; then
              n8n_do=connect
              [[ "$nurl" == http://n8n:5678/* ]] && ! tool_on n8n && { DET_ERR="N8N is not enabled: vexor n8n enable"; det_problem integrations raw put "the integrations were refused (nothing changed):"; }
            fi
          elif [ "$was" = 1 ]; then n8n_do=disconnect; fi
          DET_ERR="$(det_py integ-raw-set "$cd" "$rest" $(n8n_conf_files) 2>&1)" || det_problem integrations raw put "the integrations were refused (nothing changed):"
          for f in $(grep -o '<name>custom-[A-Za-z0-9_-]*</name>' "$rest" | sed -E 's/<[^>]*>//g'); do
            miss="$(det_integ_script_missing "$f")" && { DET_ERR="no script /var/ossec/integrations/$f in $miss"; det_problem integrations raw put "refused (nothing changed):"; }
          done
          [ -n "$(ls -A "$cd")" ] && rest_changed=1
          if [ "$rest_changed" = 0 ] && [ -z "$n8n_do" ]; then ok "integrations unchanged"; return 0; fi
          # 1) the other integrations (Wazuh checks the new ossec.conf, rolls back on failure)
          if [ "$rest_changed" = 1 ]; then
            DET_WANT_INTEGRATORD=0; { grep -q '<integration>' "$rest" || [ "$want" = 1 ]; } && DET_WANT_INTEGRATORD=1
            det_conf_apply "$cd" integrations raw put
            det_rec integrations raw put 1 "integrations edited by hand"
            ok "integrations: saved"
          fi
          # 2) n8n: same code as the n8n card / vexor n8n (an own manager recreate only if its block changes)
          case "$n8n_do" in
            connect)
              if ( cmd_n8n connect "$nurl" --level "$nlvl" --groups "$ngrp" --extra "$nextra" ); then det_rec integrations custom-n8n raw 1 "n8n connected by hand: $nurl"
              else det_rec integrations custom-n8n raw 0 "n8n change failed"; bad "n8n was not changed$([ "$rest_changed" = 1 ] && echo " (the other integrations are saved)")"; return 1; fi ;;
            disconnect)
              if ( cmd_n8n disconnect ); then det_rec integrations custom-n8n raw 1 "n8n disconnected by hand"
              else det_rec integrations custom-n8n raw 0 "n8n disconnect failed"; bad "n8n was not disconnected$([ "$rest_changed" = 1 ] && echo " (the other integrations are saved)")"; return 1; fi ;;
          esac ;;
        *) die "usage: vexor wazuh integrations raw show | put --from <path|->" ;;
      esac ;;
    test)
      local n="${1:-}"; [ -n "$n" ] || die "usage: vexor wazuh integrations test <name>"
      [ "$n" = custom-n8n ] && { n8n_test; return; }
      det_master
      t="$(det_py integ-get "$conf" "$n")"
      [ "$t" != "{}" ] || die "$n is not a Vexor-managed integration (vexor wazuh integrations ls; n8n: vexor n8n test)"
      dc exec -T wazuh.master test -x "/var/ossec/integrations/$n" || die "wazuh.master has no script /var/ossec/integrations/$n"
      local hook key alert; hook="$(pj 'print(d["hook_url"])' <<<"$t")"; key="$(pj 'print(d["_api_key"])' <<<"$t")"
      alert="$(python3 -I -c 'import json, time
print(json.dumps({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000+0000", time.gmtime()), "id": "%d.0" % time.time(),
  "rule": {"level": 12, "description": "Vexor test alert - integrations test", "id": "100999", "groups": ["vexor", "test"], "firedtimes": 1},
  "agent": {"id": "000", "name": "wazuh.master"}, "manager": {"name": "wazuh.master"}, "location": "vexor",
  "full_log": "Vexor test alert sent by: vexor wazuh integrations test", "decoder": {"name": "vexor"},
  "data": {"srcip": "192.0.2.10"}}))')"
      say "sending a sample alert (level 12, rule 100999) through $n ..."
      dc exec -T wazuh.master sh -c 'mkdir -p /tmp/vexor-check && cat > /tmp/vexor-check/alert.json' <<<"$alert"
      local rc out
      out="$(dc exec -T wazuh.master timeout 60 "/var/ossec/integrations/$n" /tmp/vexor-check/alert.json "$key" "$hook" debug 2>&1)"; rc=$?
      dc exec -T wazuh.master rm -rf /tmp/vexor-check >/dev/null 2>&1
      [ -n "$key" ] && out="${out//"$key"/****}"
      [ -n "$out" ] && printf '%s\n' "$out" | tail -n 15 | sed 's/^/      /'
      if [ "$rc" = 0 ]; then ok "$n accepted the sample alert (exit 0) - check the target"
      else bad "$n failed (exit $rc) - see above and: vexor exec master tail /var/ossec/logs/integrations.log"; return 1; fi ;;
    *) die "usage: vexor wazuh integrations ls [--json] | add|edit <name> [--hook-url URL] [--api-key K] [--level N] [--group G] [--rule-id IDS] [--format json] | rm <name> | test <name> | raw show|put" ;;
  esac
}
det_config() {                 # vexor wazuh config ls|set|custom
  local verb="${1:-ls}"; shift || true
  local json=0 a rest=() t cd="$RUN_TMP/det-cand"
  for a in "$@"; do [ "$a" = --json ] && json=1 || rest+=("$a"); done
  set -- "${rest[@]}"
  soc_wazuh || die "Wazuh is off (SOC=$(soc))"
  local master="$CLUSTER_DIR/wazuh_manager.conf"
  case "$verb" in
    ls|list|show)
      t="$(det_py cfg-ls "$master")"
      if [ "$json" = 1 ]; then printf '%s\n' "$t"; return 0; fi
      pj '
for s in d["settings"]:
    v = s["value"]
    v = "; ".join(v) if isinstance(v, list) else (v if v not in (None, "") else "-")
    print("  %-21s %-7s %s" % (s["key"], s["scope"], v))
    print("  %-21s %-7s   %s" % ("", "", s["help"] + (" (" + "|".join(s["choices"]) + ")" if s["choices"] else "")))' <<<"$t" ;;
    set)                         # set <key> <value> [<key> <value> ..]: one check + one recreate for all of them
      [ $# -ge 2 ] && [ $(( $# % 2 )) = 0 ] || die "usage: vexor wazuh config set <key> <value> [<key> <value> ..]   (keys: vexor wazuh config ls; list values comma-separated or a JSON array)"
      local keys=() enroll=""
      det_master; take_lock
      rm -rf "$cd"; mkdir -p "$cd"
      while [ $# -ge 2 ]; do
        if [ "$1" = enrollment_password ]; then
          case "${2,,}" in on|yes|true) enroll=on ;; off|no|false) enroll=off ;; *) die "enrollment_password must be on or off" ;; esac
        else
          det_py cfg-set "$cd" "$1" "$2" $(n8n_conf_files) || exit 1
          keys+=("$1")
        fi
        shift 2
      done
      if [ -n "$(ls -A "$cd")" ]; then
        det_conf_apply "$cd" config "${keys[*]}" set
        det_rec config "$(echo "${keys[*]}" | tr ' ' ,)" set 1 "set ${keys[*]}"
        local kk; for kk in "${keys[@]}"; do ok "$kk = $(det_py cfg-get "$master" "$kk")"; done
      elif [ ${#keys[@]} -gt 0 ]; then ok "${keys[*]}: unchanged"; fi
      if [ -n "$enroll" ]; then
        if [ "$(det_py cfg-get "$master" enrollment_password)" = "$enroll" ]; then ok "enrollment_password: unchanged"
        else agents_password "$enroll"; det_rec config enrollment_password set 1 "enrollment_password=$enroll"; fi
      fi ;;
    custom)
      local cv="${1:-show}"; shift || true
      case "$cv" in
        show) det_py custom-show "$master" ;;
        put|rm)
          local from="" scope=all f files=()
          while [ $# -gt 0 ]; do case "$1" in --from) from="${2:-}"; shift ;; --scope) scope="${2:-}"; shift ;; *) die "unknown option $1" ;; esac; shift; done
          [[ "$scope" =~ ^(all|master)$ ]] || die "--scope master|all"
          t=""; [ "$cv" = put ] && { t="$(det_read_from "$from")" || exit 1; }
          det_master; take_lock
          rm -rf "$cd"; mkdir -p "$cd"
          DET_ERR="$(det_py custom-set "$cd" "$t" "$master" 2>&1)" || det_problem config custom "$cv" "the custom block was refused (nothing changed):"
          for f in $(n8n_conf_files); do [ "$f" = "$master" ] || files+=("$f"); done
          if [ ${#files[@]} -gt 0 ]; then
            if [ "$scope" = all ]; then det_py custom-set "$cd" "$t" "${files[@]}"; else det_py custom-set "$cd" "" "${files[@]}"; fi
          fi
          if [ -z "$(ls -A "$cd")" ]; then ok "custom block unchanged"; return 0; fi
          det_conf_apply "$cd" config custom "$cv"
          det_rec config custom "$cv" 1 "custom block $cv (scope $scope)"
          ok "custom ossec.conf block: $cv done (scope $scope)" ;;
        *) die "usage: vexor wazuh config custom show | put --from <path|-> [--scope master|all] | rm" ;;
      esac ;;
    *) die "usage: vexor wazuh config ls [--json] | set <key> <value> | custom show|put|rm" ;;
  esac
}
det_logtest() {                # vexor wazuh logtest ["line"] [--format F] [--location L] [--json]
  local line="" fmt=syslog loc=vexor-logtest json=0 have=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --format) fmt="${2:-}"; shift ;; --location) loc="${2:-}"; shift ;; --json) json=1 ;;
      *) line="$1"; have=1 ;;
    esac; shift
  done
  if [ "$have" = 0 ]; then
    is_running wazuh.master || die "wazuh.master is not running"
    say "paste a log line, see which decoder/rule matches (Ctrl+C to quit)"; dc exec wazuh.master /var/ossec/bin/wazuh-logtest; return
  fi
  [[ "$fmt" =~ ^(syslog|json|snort-full|squid|eventlog|eventchannel|audit|mysql_log|postgresql_log|nmapg|iis|command|full_command|djb-multilog|multi-line)$ ]] \
    || die "--format: syslog json snort-full squid eventlog eventchannel audit mysql_log postgresql_log nmapg iis command full_command djb-multilog multi-line"
  local err=""
  if ! soc_wazuh || ! is_running wazuh.master; then err="wazuh.master is not running"; fi
  local body="$RUN_TMP/det-lt.json" resp="$RUN_TMP/det-lt-resp.json" out
  if [ -z "$err" ]; then
    python3 -I -c 'import json, sys; print(json.dumps({"event": sys.argv[1], "log_format": sys.argv[2], "location": sys.argv[3]}))' "$line" "$fmt" "$loc" > "$body"
    api PUT /logtest --data-binary @"$body" > "$resp" 2>/dev/null || err="Wazuh API not answering (vexor doctor)"
  fi
  if [ -n "$err" ]; then
    [ "$json" = 1 ] && { python3 -I -c 'import json, sys; print(json.dumps({"error": sys.argv[1]}))' "$err"; exit 1; }
    die "$err"
  fi
  local tok; tok="$(pj 'print(d["data"]["token"])' < "$resp" 2>/dev/null)"
  [[ "$tok" =~ ^[A-Za-z0-9]+$ ]] && api DELETE "/logtest/sessions/$tok" >/dev/null 2>&1
  out="$(det_py logtest "$resp")"; local rc=$?
  if [ "$json" = 1 ]; then printf '%s\n' "$out"; return "$rc"; fi
  [ "$rc" = 0 ] || die "logtest failed: $(pj 'print(d.get("error"))' <<<"$out")"
  pj '
dec = d["decoder"] or {}
print("  decoder   %s" % ((dec.get("name") or "-") + (" (parent %s)" % dec["parent"] if dec.get("parent") and dec.get("parent") != dec.get("name") else "")))
for k, v in sorted(d["fields"].items()):
    print("  field     %s = %s" % (k, v))
r = d["rule"]
if r:
    print("  rule      %s  level %s  %s" % (r["id"], r["level"], r["description"]))
    print("  groups    %s" % ", ".join(r["groups"]))
else:
    print("  rule      none matched")
print("  alert     %s" % ("yes" if d["alert"] else "no"))' <<<"$out"
}
det_status() {                 # vexor wazuh detection status [--json]
  local t="$RUN_TMP/det-st" k run=0
  mkdir -p "$t"
  for k in rules decoders lists; do det_ls_json "$k" > "$t/$k.json" 2>/dev/null; done
  det_py integ-ls "$CLUSTER_DIR/wazuh_manager.conf" > "$t/int.json" 2>/dev/null
  soc_wazuh && is_running wazuh.master && run=1
  local out; out="$(det_py status "$DET_STATUS" "$t/rules.json" "$t/decoders.json" "$t/lists.json" "$t/int.json" "$run")"
  if [ "${1:-}" = --all ]; then                # the console's Detection page in one call: status + every file list + templates
    printf '%s\n' "$out" > "$t/status.json"
    for k in rules decoders lists; do det_py templates "$DET_TPL_DIR" "$k" > "$t/tpl-$k.json"; done
    python3 -I - "$t" <<'PY'
import json, sys
t = sys.argv[1]
st = json.load(open(f"{t}/status.json"))
out = {"status": st, "last_error": st.get("last_error"), "templates": []}
for k in ("rules", "decoders", "lists"):
    try:
        out[k] = json.load(open(f"{t}/{k}.json"))
    except (OSError, ValueError):
        out[k] = {"files": []}
    out["templates"] += json.load(open(f"{t}/tpl-{k}.json")).get("templates", [])
print(json.dumps(out))
PY
    return 0
  fi
  if [ "${1:-}" = --json ]; then printf '%s\n' "$out"; return 0; fi
  pj '
c = d["counts"]
print("  custom rules: %d files (%d rules), decoders: %d files, lists: %d, integrations: %d" % (c["rules"]["files"], c["rules"]["entries"],
      c["decoders"]["files"], c["lists"]["files"], c["integrations"]["files"]))
lc, le = d.get("last_change"), d.get("last_error")
print("  last change: " + ("%s %s/%s %s" % (lc["when"], lc["kind"], lc["name"], lc["action"]) if lc else "-"))
if le:
    print("  last error:  %s %s/%s %s - %s" % (le["when"], le["kind"], le["name"], le["action"], le["message"][:300]))
if not d["master_running"]:
    print("  wazuh.master is not running")' <<<"$out"
}
det_sums() {                   # det_sums <svc>: "md5  kind/name" of the files in /var/ossec/etc/{rules,decoders,lists}
  dc exec -T "$1" sh -c 'cd /var/ossec/etc && md5sum rules/*.xml decoders/*.xml lists/* lists/*/* 2>/dev/null' 2>/dev/null | tr -d '\r'
}
det_out_of_sync() {            # det_out_of_sync <svc>: custom files (kind/name) whose copy in <svc> is missing or different
  [ -d "$DET_DIR" ] || return 0  # edited built-ins too: same name in etc/<kind> (lists/<dir>/<file> for the shipped sub directories)
  local remote; remote="$(det_sums "$1")"
  (cd "$DET_DIR" && md5sum rules/*.xml decoders/*.xml lists/* lists/*/* 2>/dev/null) | while read -r sum f; do
    grep -qxF "$sum  $f" <<<"$remote" || echo "$f"
  done
}
detection_sync() {             # start / config apply: custom files back into managers that lost them (fresh volume), then reload
  soc_wazuh && is_running wazuh.master || return 0
  det_import
  [ -d "$DET_DIR" ] || return 0
  wait_daemon wazuh.master wazuh-analysisd 240 || { warn "wazuh-analysisd not running on the master - custom detection files not checked"; return 0; }
  local miss f m out
  miss="$(det_out_of_sync wazuh.master)"
  for m in $(det_running_managers); do [ "$m" = wazuh.master ] || miss="$miss"$'\n'"$(det_out_of_sync "$m")"; done
  miss="$(grep -v '^$' <<<"$miss" | sort -u)"
  [ -n "$miss" ] || return 0
  for f in $miss; do
    det_push_master "${f%%/*}" "${f#*/}" "$DET_DIR/$f" >/dev/null 2>&1 || warn "could not push $f to wazuh.master"
    det_push_workers "${f%%/*}" "${f#*/}" "$DET_DIR/$f"
  done
  if ! out="$(det_rtest)"; then
    warn "custom detection files pushed, but wazuh-analysisd -t reports errors:"; printf '%s\n' "$out" | head -5 | sed 's/^/      /'
    det_rec sync all push 0 "$out"; return 0
  fi
  det_reload >/dev/null 2>&1 && ok "custom detection files restored in the managers: $(echo $miss)"
  return 0
}
det_doctor() {                 # doctor (Managers): custom detection files in every manager, custom-* integration scripts present
  local m miss n
  [ -d "$DET_DIR" ] || return 0
  n="$(find "$DET_DIR/rules" "$DET_DIR/decoders" -maxdepth 1 -type f ! -name '.*' 2>/dev/null | wc -l)"
  n=$((n + $(find "$DET_DIR/lists" -maxdepth 2 -type f ! -name '.*' 2>/dev/null | wc -l)))   # edited built-in lists can sit in a sub directory
  [ "$n" -gt 0 ] || return 0
  for m in $(det_running_managers); do
    miss="$(det_out_of_sync "$m" | tr '\n' ' ')"
    if [ -z "${miss// /}" ]; then d_pass "$m has the $n custom detection files (config/wazuh_custom)"
    else d_warn "$m misses or runs older custom detection files: $miss" "vexor doctor --fix   (pushes config/wazuh_custom and reloads)"
         d_fix "push the custom detection files + reload" && detection_sync; fi
  done
  if [ -s "$DET_OVR" ]; then   # edited built-in rules/decoders need their path-qualified exclude in every ossec.conf (vexor:excludes)
    local cd="$RUN_TMP/det-doc"; rm -rf "$cd"; mkdir -p "$cd"; det_excl_sync_conf "$cd" 2>/dev/null
    if [ -z "$(ls -A "$cd" 2>/dev/null)" ]; then d_pass "edited built-in Wazuh files (rules/decoders/lists): $(det_ovr_list rules | wc -l)/$(det_ovr_list decoders | wc -l)/$(det_ovr_list lists | wc -l), ossec.conf excludes match"
    else d_warn "the vexor:excludes block in $(ls "$cd" | paste -sd' ' -) does not match config/wazuh_custom/.overrides (a built-in file and its edited copy may both load, or neither)" \
           "save the file again (vexor wazuh <kind> put <name>) or drop the edit (vexor wazuh <kind> reset <name>)"; fi
  fi
  local i
  for i in $(det_py integ-names "$CLUSTER_DIR/wazuh_manager.conf" 2>/dev/null | grep '^custom-' | grep -vx custom-n8n); do
    for m in $(det_running_managers); do
      dc exec -T "$m" test -x "/var/ossec/integrations/$i" || d_fail "$m: integration $i has no script /var/ossec/integrations/$i (alerts are not sent)" \
        "copy the script into the manager (docker cp), chown root:wazuh, chmod 750"
    done
  done
  return 0
}

