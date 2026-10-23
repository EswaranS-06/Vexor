#!/usr/bin/env python3
"""Vexor Console - a web UI for the vexor CLI.

Runs on the Vexor host as root (systemd unit vexor-console.service), serves HTTPS on CONSOLE_PORT with the
dashboard certificate, and lets an authenticated admin see and change the stack. Every change goes through
`vexor` itself (an allowlist of commands, run without a shell), so the console and the CLI behave identically.
Standard library only.
"""
import difflib
import email.utils
import gzip
import hashlib
import hmac
import http.server
import json
import os
import re
import secrets
import shlex
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VEXOR = ROOT / "vexor"
ENV_FILE = ROOT / ".env"
UI_DIR = ROOT / "console" / "ui"
SITE_ASSETS = ROOT / "docs" / "assets"
STATE = ROOT / ".state"
AUDIT = STATE / "console-audit.log"
SESSION_TTL = 8 * 3600
MAX_JOBS = 60

# ---------------------------------------------------------------- .env
SECRET_RE = re.compile(r"(PASSWORD|SECRET|TOKEN|_KEY|APIKEY)$")


def read_env():
    """Ordered list of (key, value, comment) - last definition wins, like docker compose."""
    entries, seen = [], {}
    if not ENV_FILE.exists():
        return entries
    pending = []
    for raw in ENV_FILE.read_text(errors="replace").splitlines():
        line = raw.strip()
        if not line:
            pending = []
            continue
        if line.startswith("#"):
            pending.append(line.lstrip("# ").strip())
            continue
        m = re.match(r"^([A-Z][A-Z0-9_]*)=(.*)$", line)
        if not m:
            continue
        key, rest = m.group(1), m.group(2)
        val, inline = rest, ""
        cm = re.search(r"\s+#\s?(.*)$", rest)
        if cm and not rest.startswith("#"):
            val, inline = rest[: cm.start()], cm.group(1)
        val = val.strip().strip('"').strip("'")
        help_text = inline or " ".join(p for p in pending if not p.startswith("----") and not p.startswith("===="))
        if key in seen:
            entries[seen[key]] = (key, val, help_text or entries[seen[key]][2])
        else:
            seen[key] = len(entries)
            entries.append((key, val, help_text))
        pending = []
    return entries


def env_dict():
    return {k: v for k, v, _ in read_env()}


# ---------------------------------------------------------------- command allowlist
# level: read (runs at once) | change (one confirmation) | danger (type the word to confirm)
CATALOG = {
    "status": "read", "health": "read", "version": "read", "info": "read", "doctor": "change",
    "logs": "read", "tools": "change", "soc": "change", "elk": "change", "n8n": "change",
    "suricata": "change", "zeek": "change", "wazuh": "read", "agents": "change", "cluster": "read",
    "cert": "change", "backup": "change", "retention": "change", "volumes": "change", "reminders": "change",
    "start": "change", "stop": "change", "restart": "change", "scale": "danger", "node-type": "danger",
    "indexers": "danger", "update": "danger", "config": "change", "daemon": "change", "prune-logs": "change",
    "maintenance": "change", "watchdog": "change", "support-bundle": "change", "ai-context": "read",
    "indexer": "read", "api": "read", "passwd": "danger", "reset": "danger", "console": "change", "plan": "read",
    "notify": "change", "login": "change", "disk": "read", "uninstall": "danger", "images": "danger",
    "wait-ready": "read", "wait": "read", "migrate": "danger", "proxy": "change",
}
READ_SUBS = {
    "tools": {"status", "ls", ""}, "soc": {"status", ""}, "elk": {"status", "indices", "search", "explain", ""},
    "n8n": {"status", ""}, "suricata": {"status", "alerts", ""}, "zeek": {"status", "show", "notices", "top", ""},
    "agents": {"list", "summary", "outdated", "enroll-cmd", ""}, "cert": {"status", ""}, "backup": {"list", "ls"},
    "retention": {"show", "status", ""}, "volumes": {"ls", "list", "orphans", ""}, "reminders": {"list", ""}, "config": {"show", "get", "validate"},
    "daemon": {"status", "logs", ""}, "console": {"status", "url", ""}, "update": {"check", ""},
    "indexers": {"status", ""}, "node-type": {"status", ""}, "notify": {"status", ""},
    "proxy": {"ls", "list", "status", "show", "cert-file", ""},
}
DANGER_SUBS = {
    "volumes": {"rm", "prune", "restore"}, "backup": {"restore-snapshot", "restore-manager", "restore-config"},
    "cert": {"internal-regen"}, "agents": {"remove"}, "soc": {"wazuh", "elk", "both"},
    "proxy": {"rm", "remove", "del", "delete"},
}
# Storage (free space) and Settings (remove Vexor): these commands run only with exactly these arguments.
DANGER_EXACT = {
    "uninstall": [["uninstall", "--keep-data", "--yes"], ["uninstall", "--yes"]],
    "images": [["images", "prune", "--yes"]],
    "volumes": [["volumes", "prune", "--yes"], ["volumes", "prune"]],
}
BLOCKED = {"shell", "exec", "install", "reset purge", "config edit", "completion", "motd"}
# vexor wazuh <area> <verb>: detection files, integrations and manager config (Detection page)
WAZUH_VERBS = {
    "read": {"ls", "list", "show", "cat", "history", "templates", ""},
    "change": {"put", "save", "restore", "add", "edit", "set", "test", "reset"},   # reset: back to the shipped built-in (history kept)
    "danger": {"rm", "remove", "delete", "del"},
}
SECRET_OPTS = {"--api-key"}       # their value never reaches the confirm text, job list or audit log


def mask_args(args):
    out, hide = [], False
    for a in args:
        out.append("****" if hide else a)
        hide = a in SECRET_OPTS
    return out


def classify_wazuh(args):
    area = args[1] if len(args) > 1 else ""
    verb = args[2] if len(args) > 2 else ""
    if area == "logtest":
        return ("read", None) if len(args) > 2 else (None, "'wazuh logtest' without a line is interactive - run it over SSH")
    if area == "agents":
        return classify(["agents", *args[2:]])
    if area in ("rules", "decoders", "lists", "integrations", "integration"):
        if area.startswith("integration") and verb == "test":
            return "change", None
        if area.startswith("integration") and verb == "raw":
            return ("change" if args[3:4] == ["put"] else "read"), None
        for level, verbs in WAZUH_VERBS.items():
            if verb in verbs:
                return level, None
        return None, f"'wazuh {area} {verb}' is not a known command"
    if area == "config":
        if verb in ("ls", "list", "show", "") or args[2:4] == ["custom", "show"] or args[2:] == ["custom"]:
            return "read", None
        if args[2:4] == ["custom", "rm"]:
            return "danger", None
        if verb == "set" or args[2:4] == ["custom", "put"]:
            return "change", None
        return None, f"'wazuh config {verb}' is not a known command"
    if area == "detection":
        return "read", None
    return "read", None
ARG_RE = re.compile(r"^[^\x00-\x1f\x7f]{0,300}$")


def classify(args):
    """-> (level, error). Raises nothing; error is a message for the user."""
    if not args:
        return None, "empty command"
    if args[0] == "vexor":
        args = args[1:]
    if not args:
        return None, "empty command"
    cmd, sub = args[0], (args[1] if len(args) > 1 else "")
    if cmd not in CATALOG:
        return None, f"'{cmd}' is not available in the console"
    joined = " ".join(args[:2])
    if cmd in BLOCKED or joined in BLOCKED:
        return None, f"'{joined}' needs a terminal - run it over SSH"
    for a in args:
        if not ARG_RE.match(a):
            return None, "arguments may not contain control characters"
    if cmd == "wazuh":
        return classify_wazuh(args)
    if cmd in ("indexer", "api") and sub.upper() != "GET":
        return None, f"only GET requests through '{cmd}' in the console"
    if cmd == "logs" and ("-f" in args or "--follow" in args):
        return "read", None  # streamed until the browser closes it
    if cmd in ("uninstall", "images") or (cmd == "volumes" and sub == "prune"):
        if args not in DANGER_EXACT[cmd]:
            return None, f"'{' '.join(args)}' is not allowed in the console in this form - use Storage → Free space, Settings → Remove Vexor, or a terminal"
        return "danger", None
    if cmd in DANGER_SUBS and sub in DANGER_SUBS[cmd]:
        return "danger", None
    if cmd in READ_SUBS and sub in READ_SUBS[cmd]:
        return "read", None
    if cmd == "doctor" and "--fix" not in args:
        return "read", None
    return CATALOG[cmd], None


# ---------------------------------------------------------------- jobs (one vexor process each)
class Job:
    def __init__(self, args, user, level="change"):
        self.id = secrets.token_hex(6)
        self.args = args
        self.user = user
        self.level = level
        self.started = time.time()
        self.ended = None
        self.code = None
        self.lines = []
        self.cond = threading.Condition()
        self.proc = None
        self.cleanup = []          # temp files (detection content, API keys) removed when the job ends

    def run(self):
        env = dict(os.environ, VEXOR_NO_SUDO="1", TERM="dumb")
        try:
            self.proc = subprocess.Popen([str(VEXOR), "--no-color", "-y", *self.args], cwd=str(ROOT), env=env,
                                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                         text=True, bufsize=1, errors="replace")
            for line in self.proc.stdout:
                with self.cond:
                    self.lines.append(line.rstrip("\n"))
                    if len(self.lines) > 20000:
                        del self.lines[:5000]
                    self.cond.notify_all()
            self.code = self.proc.wait()
        except Exception as e:  # noqa: BLE001 - surface any launch failure to the UI
            with self.cond:
                self.lines.append(f"✘ console could not run vexor: {e}")
            self.code = 127
        with self.cond:
            self.ended = time.time()
            self.cond.notify_all()
        if self.level != "read":
            invalidate()     # the stack changed: the next read waits for fresh data
        audit(self.user, f"job {self.id} exit {self.code}: vexor {shlex.join(mask_args(self.args))}")
        for f in self.cleanup:
            try:
                os.unlink(f)
            except OSError:
                pass

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()

    def summary(self):
        return {"id": self.id, "cmd": "vexor " + shlex.join(mask_args(self.args)), "started": self.started, "ended": self.ended,
                "code": self.code, "lines": len(self.lines), "user": self.user}


JOBS = {}
JOBS_LOCK = threading.Lock()


def start_job(args, user, level="change", cleanup=()):
    job = Job(args, user, level)
    job.cleanup = list(cleanup)
    with JOBS_LOCK:
        JOBS[job.id] = job
        if len(JOBS) > MAX_JOBS:
            for old in sorted(JOBS.values(), key=lambda j: j.started)[: len(JOBS) - MAX_JOBS]:
                if old.ended:
                    JOBS.pop(old.id, None)
    threading.Thread(target=job.run, daemon=True).start()
    return job


def run_rc(args, timeout=60):
    """-> (exit code, stdout) of a vexor command; (124, "") on timeout."""
    try:
        r = subprocess.run(args, cwd=str(ROOT), capture_output=True, text=True, timeout=timeout,
                           env=dict(os.environ, VEXOR_NO_SUDO="1", TERM="dumb"), errors="replace")
        return r.returncode, r.stdout
    except (subprocess.TimeoutExpired, OSError):
        return 124, ""


def run_quick(args, timeout=60):
    """Run a read-only vexor/docker command and return stdout (used by the JSON endpoints)."""
    try:
        r = subprocess.run(args, cwd=str(ROOT), capture_output=True, text=True, timeout=timeout,
                           env=dict(os.environ, VEXOR_NO_SUDO="1", TERM="dumb"), errors="replace")
        return r.stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""


# ---------------------------------------------------------------- cache (stale-while-revalidate)
# The JSON endpoints run docker/vexor commands that take seconds on a real host. A read returns the last value at once
# and refreshes it in a background thread; at most one refresh per key runs at a time, so `vexor json state` never runs
# twice concurrently however many browsers poll. A change job bumps the generation: the next read of an older value
# waits for one fresh refresh instead. While someone reads a key, a warmer thread keeps it fresh ahead of the next poll.
_cache = {}             # key -> (time, value, generation)
_cache_lock = threading.Lock()
_inflight = {}          # key -> threading.Event of the refresh that is running
_wanted = {}            # key -> (ttl, fn, last read time): what the warmer keeps fresh
_gen = 0
WARM_FOR = 45           # keep refreshing a key this long after its last read
# seconds a value stays current; just under the browser's poll (Overview 15 s, Containers 10 s) so each poll finds a
# value the warmer has just refreshed, and the host runs about one refresh per poll, not more
TTL = {"state": 12, "containers": 8, "stats": 8, "disk": 60, "proxy": 30, "volumes": 300, "map": 2.5, "detection": 30}


def invalidate():
    global _gen
    with _cache_lock:
        _gen += 1


def _refresh(key, fn):
    """Compute key once; callers that arrive while it runs wait for the same result."""
    with _cache_lock:
        ev = _inflight.get(key)
        owner = ev is None
        if owner:
            ev = _inflight[key] = threading.Event()
            gen = _gen
    if not owner:
        ev.wait(timeout=180)
        return
    try:
        val = fn()
        with _cache_lock:
            _cache[key] = (time.time(), val, gen)
    except Exception as e:  # noqa: BLE001 - a failed refresh keeps the last value
        print(f"refresh {key} failed: {e}", file=sys.stderr, flush=True)
    finally:
        with _cache_lock:
            _inflight.pop(key, None)
        ev.set()


def _refresh_bg(key, fn):
    if key not in _inflight:
        threading.Thread(target=_refresh, args=(key, fn), daemon=True).start()


def cached(key, ttl, fn, swr=True, fresh=False):
    """Value of key. swr: an expired value is returned at once and refreshed in the background. fresh: wait for a new one."""
    now = time.time()
    with _cache_lock:
        hit = _cache.get(key)
        _wanted[key] = (ttl, fn, now)
        current = hit is not None and hit[2] == _gen
    if hit and current and not fresh:
        if now - hit[0] >= ttl:
            if swr:
                _refresh_bg(key, fn)
                return hit[1]
        else:
            return hit[1]
    for _ in range(2):    # a refresh already running may have started before the change: then run one more
        _refresh(key, fn)
        with _cache_lock:
            hit = _cache.get(key)
            if hit and hit[2] == _gen and (not fresh or hit[0] >= now):
                break
    return hit[1] if hit else fn()


def peek(key, ttl, fn):
    """Last value of key (None before the first), refreshed in the background when older than ttl. Never waits."""
    now = time.time()
    with _cache_lock:
        hit = _cache.get(key)
        _wanted[key] = (ttl, fn, now)
    if not hit or now - hit[0] >= ttl or hit[2] != _gen:
        _refresh_bg(key, fn)
    return hit[1] if hit else None


def warmer():
    """Refresh what browsers are reading before it expires, so a poll never waits for docker or vexor."""
    while True:
        time.sleep(1)
        now = time.time()
        with _cache_lock:
            todo = [(k, fn) for k, (ttl, fn, seen) in _wanted.items() if now - seen < WARM_FOR and k not in _inflight
                    and (k not in _cache or now - _cache[k][0] >= ttl or _cache[k][2] != _gen)]
        for k, fn in todo:
            _refresh_bg(k, fn)


def warm_start():
    """Fill the slow caches once at startup, so the first page after a restart does not wait. Not volumes: their du walks
    every file of the indexer data, so it runs only when someone opens the Storage page."""
    for key, fn in (("state", state), ("containers", containers), ("disk", disk), ("proxy", proxy_routes)):
        _refresh(key, fn)
        with _cache_lock:
            _wanted.setdefault(key, (TTL[key], fn, 0))


# ---------------------------------------------------------------- data for the UI
def state():
    out = run_quick([str(VEXOR), "--no-color", "json", "state"], timeout=40)
    try:
        return json.loads(out)
    except ValueError:
        return {"error": "vexor json state failed", "raw": out[-2000:]}


def containers():
    out = run_quick(["docker", "compose", "ps", "-a", "--format", "json"], timeout=30)
    rows = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            items = json.loads(line)
        except ValueError:
            continue
        for c in items if isinstance(items, list) else [items]:
            rows.append({"service": c.get("Service"), "name": c.get("Name"), "state": c.get("State"),
                         "status": c.get("Status"), "health": c.get("Health"), "image": c.get("Image"),
                         "ports": c.get("Publishers") or [], "created": c.get("CreatedAt")})
    return sorted(rows, key=lambda r: r["service"] or "")


def with_stats(rows):
    """Rows plus CPU/memory. Those come from their own cache: `docker stats` samples for ~2 s, so the list never waits."""
    running = tuple(sorted(r["name"] for r in rows if r["state"] == "running" and r["name"]))
    stats = peek("stats", TTL["stats"], lambda: container_stats(running)) or {}
    if running and not set(running) <= set(stats):
        _refresh_bg("stats", lambda: container_stats(running))      # a container started since the last sample
    return [dict(r, **stats.get(r["name"], {})) for r in rows]


def container_stats(names):
    """One `docker stats` sample of the project's running containers only (not every container on the host)."""
    stats = {}
    if not names:
        return stats
    for line in run_quick(["docker", "stats", "--no-stream", "--format", "{{json .}}", *names], timeout=30).splitlines():
        try:
            s = json.loads(line)
            stats[s.get("Name")] = {"cpu": s.get("CPUPerc"), "mem": s.get("MemUsage"), "memPct": s.get("MemPerc")}
        except ValueError:
            pass
    return stats


def df_row(path, roles):
    out = run_quick(["df", "-P", "-B1", str(path)], timeout=10).strip().splitlines()
    if len(out) < 2:
        return None
    f = out[-1].split()
    try:
        size, used, avail, pct = int(f[1]), int(f[2]), int(f[3]), int(f[4].rstrip("%"))
    except (ValueError, IndexError):
        return None
    return {"mount": f[5] if len(f) > 5 else str(path), "size": size, "used": used, "avail": avail, "pct": pct, "roles": roles}


def disk_fallback():
    rows = {}
    root = run_quick(["docker", "info", "--format", "{{.DockerRootDir}}"], timeout=10).strip() or "/var/lib/docker"
    for path, role in ((root, "docker-root"), (ROOT, "checkout")):
        r = df_row(path, [role])
        if r:
            if r["mount"] in rows:
                rows[r["mount"]]["roles"] += r["roles"]
            else:
                rows[r["mount"]] = r
    return {"filesystems": list(rows.values()), "source": "df"}


def disk():
    """Per-filesystem usage from `vexor disk --json`; plain df when that command is missing or fails."""
    out = run_quick([str(VEXOR), "--no-color", "disk", "--json"], timeout=40)
    try:
        d = json.loads(out.strip().splitlines()[-1])
        fs = [f for f in d["filesystems"] if isinstance(f, dict) and "mount" in f]
        if fs:
            return {"filesystems": fs, "source": "vexor"}
    except (ValueError, IndexError, KeyError, TypeError):
        pass
    return disk_fallback()


def volumes():
    out = run_quick([str(VEXOR), "--no-color", "json", "volumes"], timeout=120)
    try:
        return json.loads(out)
    except ValueError:
        return []


PORT_KEYS = {
    "PROXY_PORT": ("Wazuh dashboard (HTTPS through nginx)", "admins"),
    "AGENT_PORT": ("Agent events (nginx balances the managers)", "endpoints"),
    "ENROLL_PORT": ("Agent enrollment", "endpoints"),
    "SYSLOG_PORT": ("Syslog (UDP) into the master", "endpoints"),
    "API_PORT": ("Wazuh API", "restricted"),
    "INDEXER_HOST_PORT": ("Wazuh indexer API (bound to INDEXER_BIND)", "host"),
    "KIBANA_PORT": ("Kibana (HTTPS through nginx)", "admins"),
    "ES_PORT": ("Elasticsearch API (bound to ES_BIND)", "host"),
    "LOGSTASH_BEATS_PORT": ("Beats / Elastic Agent into Logstash", "restricted"),
    "N8N_PORT": ("n8n (HTTPS through nginx)", "admins"),
    "GRAFANA_PORT": ("Grafana (HTTPS through nginx)", "admins"),
    "PORTAINER_PORT": ("Portainer (HTTPS through nginx)", "admins"),
    "CONSOLE_PORT": ("This console (HTTPS)", "admins"),
    "ROUTES_HTTPS_PORT": ("Proxy routes: named hosts over HTTPS (vexor proxy)", "admins"),
    "ROUTES_HTTP_PORT": ("Proxy routes: HTTP redirect + Let's Encrypt challenges", "admins"),
}
FIVE_X = {"KIBANA_PORT", "ES_PORT", "LOGSTASH_BEATS_PORT", "N8N_PORT", "GRAFANA_PORT", "PORTAINER_PORT", "CONSOLE_PORT"}


def listening(port):
    out = run_quick(["ss", "-Hltnu", f"( sport = :{port} )"], timeout=5)
    return bool(out.strip())


def port_in_use(k, env):
    on = lambda name, default="false": env.get(name, default).lower() in ("true", "yes", "on", "1")
    soc = env.get("SOC", "wazuh").lower()
    if k in ("KIBANA_PORT", "ES_PORT", "LOGSTASH_BEATS_PORT"):
        return soc in ("elk", "both")
    if k in ("N8N_PORT", "GRAFANA_PORT", "PORTAINER_PORT"):
        return on(k[:-5])
    if k == "CONSOLE_PORT":
        return on("CONSOLE", "true")
    if k in ("ROUTES_HTTPS_PORT", "ROUTES_HTTP_PORT"):
        try:
            return bool(json.loads((ROOT / "config" / "nginx" / "routes.json").read_text()).get("routes"))
        except (OSError, ValueError):
            return False
    return soc != "elk"


def ports():
    env = env_dict()
    rows = []
    for k, (what, who) in PORT_KEYS.items():
        if k not in env:
            continue
        rows.append({"key": k, "value": env[k], "what": what, "audience": who, "fiveX": k in FIVE_X,
                     "inUse": port_in_use(k, env), "listening": listening(env[k]) if env[k].isdigit() else False})
    return rows


def validate_ports(changes):
    env = env_dict()
    merged = {k: env.get(k, "") for k in PORT_KEYS}
    merged.update(changes)
    errors = {}
    seen = {}
    for k, v in merged.items():
        if k not in env and k not in changes:
            continue
        if not re.fullmatch(r"\d{1,5}", v or "") or not 1 <= int(v) <= 65535:
            errors[k] = "must be a port number 1-65535"
            continue
        if k in FIVE_X and not 50000 <= int(v) <= 59999:
            errors[k] = "tool ports must be in 50000-59999"
        if v in seen:
            errors[k] = f"already used by {seen[v]}"
        seen[v] = k
    for k, v in changes.items():
        if k not in errors and v != env.get(k) and listening(v):
            errors[k] = f"port {v} is already in use on this host"
    return errors


def pending():
    """.env keys that differ from the last applied snapshot (cheap; no docker calls)."""
    applied = STATE / "env.applied"
    if not applied.exists():
        return {"known": False, "keys": []}
    cur = env_dict()
    old = {}
    for raw in applied.read_text(errors="replace").splitlines():
        m = re.match(r"^([A-Z][A-Z0-9_]*)=(.*)$", raw.strip())
        if m:
            v = m.group(2)
            c = re.search(r"\s+#", v)
            old[m.group(1)] = (v[: c.start()] if c and not v.startswith("#") else v).strip().strip('"').strip("'")
    keys = sorted(k for k in set(cur) | set(old) if cur.get(k) != old.get(k) and k not in ("COMPOSE_PROFILES", "COMPOSE_FILE"))
    return {"known": True, "keys": keys}


# ---------------------------------------------------------------- detection (custom rules, decoders, lists, integrations, config)
DET_DIR = ROOT / "config" / "wazuh_custom"
DET_HIST = STATE / "detection-history"
DET_KINDS = ("rules", "decoders", "lists")
DET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
DET_WAZUH_LISTS = {"audit-keys", "security-eventchannel", "amazon", "malicious-ioc"}   # flat names Wazuh ships (vexor det_custom_ok)
DET_SHOW = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}(/[A-Za-z0-9][A-Za-z0-9_.-]{0,80})?$")
DET_VERSION = re.compile(r"^[0-9]{8}T[0-9]{6}Z(-[0-9]+)?$")
DET_MAX = 256 * 1024
DET_BODY_MAX = 6 * DET_MAX + 4096          # JSON escaping of the content (\uXXXX) at worst
LOG_FORMATS = {"syslog", "json", "snort-full", "squid", "eventlog", "eventchannel", "audit", "mysql_log", "postgresql_log",
               "nmapg", "iis", "command", "full_command", "djb-multilog", "multi-line"}


def vexor_json(args, timeout=60, default=None):
    out = run_quick([str(VEXOR), "--no-color", *args], timeout=timeout)
    try:
        return json.loads(out.strip().splitlines()[-1]) if out.strip() else default
    except (ValueError, IndexError):
        return default


def detection():
    """Status, the rules/decoders/lists listings and the templates in one vexor call."""
    d = vexor_json(["wazuh", "detection", "status", "--all"], timeout=90, default=None)
    if not isinstance(d, dict):
        return {"error": "vexor wazuh detection status failed", "rules": {"files": []}, "decoders": {"files": []},
                "lists": {"files": []}, "templates": [], "status": {}, "last_error": None}
    return d


def det_name(kind, name):
    """Validated custom file name (rules/decoders get .xml) or None (built-in names: det_builtin)."""
    if kind not in DET_KINDS or not isinstance(name, str):
        return None
    base = name[:-4] if kind != "lists" and name.endswith(".xml") else name
    if not DET_NAME.match(base) or re.match(r"^[0-9]{4}-", base) or (kind == "lists" and base in DET_WAZUH_LISTS):
        return None
    return base if kind == "lists" else base + ".xml"


def det_overridden(kind, name):
    """Built-in file edited in config/wazuh_custom (the .overrides manifest vexor keeps)."""
    try:
        return f"{kind}/{name}" in (DET_DIR / ".overrides").read_text().split()
    except OSError:
        return False


def det_builtin(kind, name):
    """A built-in Wazuh file name (vexor lists it with source wazuh, or it is edited already) or None.
    Same syntax as vexor det_name: no '..', one sub directory for lists only."""
    if kind not in DET_KINDS or not isinstance(name, str) or ".." in name or det_name(kind, name):
        return None
    if kind != "lists" and not name.endswith(".xml"):
        name += ".xml"
    if not DET_SHOW.match(name) or (kind != "lists" and "/" in name):
        return None
    if det_overridden(kind, name):
        return name
    files = ((cached("detection", TTL["detection"], detection) or {}).get(kind) or {}).get("files") or []
    return name if any(f.get("name") == name and f.get("source") == "wazuh" for f in files) else None


def det_tmp(content, prefix):
    """0600 file under .state/tmp for one job; the job removes it when it ends."""
    d = STATE / "tmp"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    path = d / f"{prefix}-{secrets.token_hex(8)}"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    return str(path)


# ---------------------------------------------------------------- map: containers, networks, live traffic
# Everything here is read, never invented: one `docker inspect` for the project's containers, then each running
# container's own network namespace through /proc/<pid>/net (the console runs as root on the host). No exec and
# no extra processes. Rates need two samples, so the first answer has none.
TCP_STATE = {"01": "established", "0A": "listen", "07": "unconnected"}
MAP_ISSUE_RESTARTS = 3          # from this many restarts (Docker's RestartCount) a container counts as an issue
MAP_NO_PROC = ("Live traffic and connections need the console to run as root on the Docker host "
               "(it reads /proc/<pid>/net). Showing container state only.")
_map_lock = threading.Lock()
_map_prev = {}                  # container id -> (time, rx bytes, tx bytes) of the previous sample


def hex_ip(h):
    """Address field of /proc/net/tcp ('0100007F', or 32 hex digits in tcp6) -> text. IPv4-mapped IPv6 -> IPv4."""
    raw = bytes.fromhex(h)
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw[::-1])
    if len(raw) != 16:
        raise ValueError("bad address")
    raw = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))   # four 32-bit words in little-endian order
    if raw[:12] == b"\0" * 10 + b"\xff\xff":
        return socket.inet_ntop(socket.AF_INET, raw[12:])
    return socket.inet_ntop(socket.AF_INET6, raw)


def parse_proc_net(text, proto="tcp"):
    """/proc/<pid>/net/{tcp,tcp6,udp,udp6} -> [{proto, local, lport, remote, rport, state}]."""
    rows = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 4 or f[1].count(":") != 1 or f[2].count(":") != 1:
            continue
        try:
            (lh, lp), (rh, rp) = f[1].split(":"), f[2].split(":")
            rows.append({"proto": proto, "local": hex_ip(lh), "lport": int(lp, 16), "remote": hex_ip(rh),
                         "rport": int(rp, 16), "state": TCP_STATE.get(f[3].upper(), f[3].upper())})
        except (ValueError, OSError):
            continue
    return rows


def parse_net_dev(text):
    """/proc/<pid>/net/dev -> totals over every interface except loopback."""
    keys = ("rxBytes", "rxPackets", "rxErrors", "rxDrops", "txBytes", "txPackets", "txErrors", "txDrops")
    tot = dict.fromkeys(keys, 0)
    tot["interfaces"] = []
    for line in text.splitlines()[2:]:
        if ":" not in line:
            continue
        name, data = line.split(":", 1)
        name, f = name.strip(), data.split()
        if name == "lo" or len(f) < 16:
            continue
        try:
            vals = [int(f[i]) for i in (0, 1, 2, 3, 8, 9, 10, 11)]
        except ValueError:
            continue
        tot["interfaces"].append(name)
        for k, v in zip(keys, vals):
            tot[k] += v
    return tot


def is_loopback(ip):
    return ip.startswith("127.") or ip == "::1"


def is_local_ip(ip):
    return is_loopback(ip) or ip in ("0.0.0.0", "::")


def read_proc_net(pid, name):
    with open(f"/proc/{pid}/net/{name}", errors="replace") as f:
        return f.read()


def own_netns(pid, cid):
    """True when /proc/<pid> really is this container in a network namespace of its own (not a pid inside a Docker VM)."""
    try:
        if cid and cid in Path(f"/proc/{pid}/cgroup").read_text(errors="replace"):
            return True
        return os.stat(f"/proc/{pid}/ns/net").st_ino != os.stat("/proc/self/ns/net").st_ino
    except OSError:
        return False


def expected_services():
    """Services the current layout enables, from the cached `vexor json state` the Overview uses (refreshed in the background)."""
    st = peek("state", 60, state)      # the layout changes rarely: the map alone does not keep `vexor json state` busy
    svcs = st.get("services") if isinstance(st, dict) else None
    return svcs if isinstance(svcs, list) else None


def inspect_project(project):
    ids = run_quick(["docker", "ps", "-a", "-q", "--no-trunc", "--filter", f"label=com.docker.compose.project={project}"], timeout=15).split()
    if not ids:
        return []
    try:
        return json.loads(run_quick(["docker", "inspect", *ids], timeout=20) or "[]")
    except ValueError:
        return []


def map_node(c):
    st, cfg, hc = c.get("State") or {}, c.get("Config") or {}, c.get("HostConfig") or {}
    name = (c.get("Name") or "").lstrip("/")
    nets = [{"name": k, "ip": v.get("IPAddress") or "", "ip6": v.get("GlobalIPv6Address") or "", "gateway": v.get("Gateway") or ""}
            for k, v in sorted(((c.get("NetworkSettings") or {}).get("Networks") or {}).items())]
    return {"id": name or c.get("Id", "")[:12], "cid": c.get("Id", ""),
            "service": (cfg.get("Labels") or {}).get("com.docker.compose.service") or name, "name": name,
            "state": st.get("Status") or "unknown", "health": (st.get("Health") or {}).get("Status") or "",
            "restarts": c.get("RestartCount") or 0, "exitCode": st.get("ExitCode"), "oom": bool(st.get("OOMKilled")),
            "startedAt": st.get("StartedAt") or "", "finishedAt": st.get("FinishedAt") or "", "image": cfg.get("Image") or "",
            "pid": st.get("Pid") or 0, "networkMode": hc.get("NetworkMode") or "", "networks": nets,
            "traffic": None, "listening": None, "connections": None, "note": ""}


def node_status(n):
    """-> (ok | issue | offline, [reasons])"""
    reasons = []
    if n["state"] in ("exited", "dead", "created", "removing"):
        if n["exitCode"] not in (None, 0):
            reasons.append(f"exit code {n['exitCode']}")
        if n["oom"]:
            reasons.append("killed: out of memory")
        return "offline", reasons
    if n["state"] in ("restarting", "paused"):
        reasons.append(n["state"])
    if n["health"] == "unhealthy":
        reasons.append("healthcheck failing")
    if n["oom"]:
        reasons.append("was killed: out of memory")
    if n["restarts"] >= MAP_ISSUE_RESTARTS:
        reasons.append(f"restarted {n['restarts']} times")
    t = n["traffic"] or {}
    if t.get("rxErrors") or t.get("txErrors"):
        reasons.append(f"network errors: rx {t['rxErrors']}, tx {t['txErrors']}")
    return ("issue" if reasons else "ok"), reasons


def sample_netns(n, now):
    """Traffic counters and sockets of one running container. Raises OSError when /proc cannot be read."""
    dev = parse_net_dev(read_proc_net(n["pid"], "dev"))
    prev = _map_prev.get(n["cid"])
    _map_prev[n["cid"]] = (now, dev["rxBytes"], dev["txBytes"])
    dev["rxRate"] = dev["txRate"] = None       # first sample, or the counters were reset by a restart
    if prev and now - prev[0] >= 0.5 and dev["rxBytes"] >= prev[1] and dev["txBytes"] >= prev[2]:
        dev["rxRate"] = round((dev["rxBytes"] - prev[1]) / (now - prev[0]), 1)
        dev["txRate"] = round((dev["txBytes"] - prev[2]) / (now - prev[0]), 1)
    n["traffic"] = dev
    socks = []
    for name in ("tcp", "tcp6", "udp", "udp6"):
        try:
            socks += parse_proc_net(read_proc_net(n["pid"], name), name.rstrip("6"))
        except OSError:
            continue       # e.g. IPv6 disabled in this namespace
    return socks


def link_sockets(nodes, socks, by_ip):
    """Sockets of every sampled container -> listening ports, per-container connection lists, edges client -> server."""
    listen = {nid: {(r["proto"], r["lport"]) for r in rows if r["state"] in ("listen", "unconnected") and r["rport"] == 0
                    and not is_loopback(r["local"])}     # loopback-only listeners (e.g. Docker's DNS on 127.0.0.11) are internal
              for nid, rows in socks.items()}
    conns = {}          # (client, server, proto, port) -> {connection}; both ends see a connection, the set counts it once
    for nid, rows in socks.items():
        for r in rows:
            if r["state"] != "established" or is_local_ip(r["remote"]):
                continue
            peer = by_ip.get(r["remote"])
            if peer == nid:
                continue
            if peer is None:     # outside the project: agents, browsers, other hosts, the Docker gateway (published ports)
                if (r["proto"], r["lport"]) in listen[nid]:
                    key = ("external", nid, r["proto"], r["lport"])
                else:
                    key = (nid, "external", r["proto"], r["rport"])
                conns.setdefault(key, set()).add((r["remote"], r["rport"], r["local"], r["lport"]))
                continue
            if (r["proto"], r["lport"]) in listen[nid]:
                server_here = True
            elif (r["proto"], r["rport"]) in listen.get(peer, set()):
                server_here = False
            else:                # neither side lists the port as listening: the lower port is the server's
                server_here = (r["lport"], nid) < (r["rport"], peer)
            key = (peer, nid, r["proto"], r["lport"]) if server_here else (nid, peer, r["proto"], r["rport"])
            conns.setdefault(key, set()).add(tuple(sorted(((r["local"], r["lport"]), (r["remote"], r["rport"])))))
    edges, per_node = [], {nid: [] for nid in socks}
    ext = {"inbound": 0, "outbound": 0, "peers": set(), "ports": {}}
    for (client, server, proto, port), tups in sorted(conns.items()):
        edges.append({"from": client, "to": server, "proto": proto, "port": port, "count": len(tups)})
        if "external" in (client, server):
            inbound = client == "external"
            ips = sorted({t[0] for t in tups})
            ext["inbound" if inbound else "outbound"] += len(tups)
            ext["peers"].update(ips)
            ext["ports"][f"{port}/{proto}"] = ext["ports"].get(f"{port}/{proto}", 0) + len(tups)
            per_node[server if inbound else client].append({"dir": "in" if inbound else "out", "peer": "external", "port": port,
                                                            "proto": proto, "count": len(tups), "ips": ips[:5]})
            continue
        if client in per_node:
            per_node[client].append({"dir": "out", "peer": server, "port": port, "proto": proto, "count": len(tups)})
        if server in per_node:
            per_node[server].append({"dir": "in", "peer": client, "port": port, "proto": proto, "count": len(tups)})
    for n in nodes:
        if n["id"] in socks:
            n["listening"] = [{"port": p, "proto": pr} for pr, p in sorted(listen[n["id"]], key=lambda x: (x[1], x[0]))]
            n["connections"] = per_node[n["id"]]
    ext["peers"] = len(ext["peers"])
    return edges, ext


def build_map():
    with _map_lock:      # one sample at a time: the rates depend on the previous one
        return _build_map()


def _build_map():
    project = env_dict().get("COMPOSE_PROJECT_NAME") or "vexor"
    now = time.time()
    nodes = sorted((map_node(c) for c in inspect_project(project)), key=lambda n: (n["service"], n["name"]))
    by_ip = {ip: n["id"] for n in nodes for net in n["networks"] for ip in (net["ip"], net["ip6"]) if ip}
    socks, limits = {}, None
    for n in nodes:
        if n["state"] != "running" or not n["pid"]:
            continue
        if n["networkMode"] == "host":
            n["note"] = "Uses the host network: its counters and sockets are the whole host's, so the map leaves them out."
        elif n["networkMode"].startswith("container:"):
            n["note"] = "Shares another container's network namespace."
        elif not own_netns(n["pid"], n["cid"]):
            limits = MAP_NO_PROC
        else:
            try:
                socks[n["id"]] = sample_netns(n, now)
            except OSError:
                limits = MAP_NO_PROC
    live = {n["cid"] for n in nodes}
    for cid in [k for k in _map_prev if k not in live]:
        _map_prev.pop(cid, None)
    edges, external = link_sockets(nodes, socks, by_ip)
    for n in nodes:
        n["status"], n["reasons"] = node_status(n)
        n.pop("pid", None)
    expected = expected_services()
    have = {n["service"] for n in nodes}
    for svc in expected or []:
        if svc not in have:
            nodes.append({"id": "missing:" + svc, "service": svc, "name": "", "state": "missing", "status": "missing",
                          "reasons": ["the current layout enables it, but it has no container"], "health": "", "restarts": 0,
                          "networks": [], "traffic": None, "listening": None, "connections": None, "note": ""})
    nets = {}
    for n in nodes:
        for net in n["networks"]:
            nets[net["name"]] = nets.get(net["name"], 0) + 1
    return {"project": project, "time": now, "expected": expected, "nodes": nodes, "edges": edges, "external": external,
            "networks": [{"name": k, "containers": v} for k, v in sorted(nets.items())], "limits": limits}


# ---------------------------------------------------------------- proxy routes (vexor proxy)
ROUTE_HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")
NGINX_CFG = ROOT / "config" / "nginx"
PEM_CERT_RE = re.compile(rb"-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?")


def proxy_routes():
    out = run_quick([str(VEXOR), "--no-color", "proxy", "ls", "--json"], timeout=60)
    try:
        return json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"routes": [], "error": "vexor proxy ls failed", "raw": out[-1500:]}


def proxy_cert_file(host, what):
    """-> (bytes, filename) of a PUBLIC certificate, or (None, error). Never a private key."""
    if what not in ("ca", "cert"):
        return None, "what must be ca or cert"
    if what == "cert":
        if not ROUTE_HOST_RE.match(host or ""):
            return None, "bad host"
        if host not in {r.get("host") for r in cached("proxy", TTL["proxy"], proxy_routes).get("routes", [])}:
            return None, "no such route"
        args = ["proxy", "cert-file", host, "cert"]
    else:
        args = ["proxy", "cert-file", "ca"]
    lines = run_quick([str(VEXOR), "--no-color", *args], timeout=30).strip().splitlines()
    if not lines:
        return None, "no certificate yet"
    try:
        f = Path(lines[-1].strip()).resolve(strict=True)
    except (OSError, RuntimeError):
        return None, "no certificate yet"
    base = NGINX_CFG.resolve()
    if base not in f.parents or f.name.endswith("-key.pem") or f.suffix not in (".pem", ".crt") or not f.is_file():
        return None, "refused"
    data = f.read_bytes()[:262144]
    if b"PRIVATE KEY" in data:
        return None, "refused"
    m = PEM_CERT_RE.search(data)   # the first certificate: the route's own (its file also carries the chain)
    if not m:
        return None, "not a certificate"
    return m.group(0), ("vexor-local-ca.crt" if what == "ca" else f"{host}.crt")


def logins():
    out = run_quick([str(VEXOR), "--no-color", "login", "--json"], timeout=30)
    try:
        return json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"logins": []}


def plan(changes):
    args = [str(VEXOR), "--no-color", "plan", "--json"] + [f"{k}={v}" for k, v in changes.items()]
    out = run_quick(args, timeout=180)
    try:
        return json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"error": "plan failed", "raw": out[-1500:]}


def settings():
    rows = []
    for k, v, h in read_env():
        secret = bool(SECRET_RE.search(k))
        rows.append({"key": k, "value": "" if secret else v, "secret": secret, "set": bool(v) and v != "CHANGE_ME",
                     "help": h, "port": k in PORT_KEYS})
    return rows


# ---------------------------------------------------------------- command suggestions (Terminal page)
# GET /api/complete?line=<text before the caret> answers on every keystroke, so nothing here waits for docker or vexor:
# the grammar is one static table (what the CLI accepts, from its bash completion, help and usage messages), and the
# dynamic values (services, detection files, integrations, agents, routes, volumes) come from caches that peek()
# refreshes in the background - the very first keystroke may see none of them. A value type is an enumeration, a
# dynamic source, a hint (a free-form slot nobody can list: a URL, a log line, a key) or a mix. Never a .env value.
COMPLETE_MAX = 12
COMPLETE_TTL = {"agents": 30, "volumes": 30}
ENV_EXAMPLE = ROOT / ".env.example"
SVC_ALIASES = {      # vexor resolve_svc: short name -> compose service (managers / indexers: every enabled one)
    "master": ("wazuh.master", "Wazuh master manager"), "nginx": ("nginx", "nginx: dashboard, agents, routes"),
    "dashboard": ("wazuh.dashboard", "Wazuh dashboard"), "indexer1": ("wazuh1.indexer", "Wazuh indexer 1"),
    "worker": ("wazuh.worker", "Wazuh worker manager"), "worker2": ("wazuh2.worker", "Wazuh worker 2"),
    "worker3": ("wazuh3.worker", "Wazuh worker 3"), "indexer2": ("wazuh2.indexer", "Wazuh indexer 2"),
    "indexer3": ("wazuh3.indexer", "Wazuh indexer 3"), "managers": (None, "every enabled manager"),
    "indexers": (None, "every enabled indexer"),
}
WAZUH_LOGS = [("errors", "error lines of every container (--since, default 1h)"), ("alerts", "alerts.json of a manager"),
              ("ossec", "ossec.log of a manager (default master)"), ("api", "api.log of a manager"),
              ("cluster", "cluster.log of a manager"), ("integrations", "integrations.log (Slack, n8n ...)"),
              ("archives", "archives.json (needs logall_json)"), ("size", "disk used by container and manager logs")]
INTEGRATIONS = [("slack", "Slack incoming webhook"), ("custom-n8n", "alerts to n8n (= vexor n8n connect)"),
                ("pagerduty", "PagerDuty (API key)"), ("virustotal", "VirusTotal file lookups (API key)"),
                ("shuffle", "Shuffle SOAR webhook"), ("maltiverse", "Maltiverse IoC enrichment (API key)")]
HOOK_EXAMPLES = {"slack": "https://hooks.slack.com/services/T0000/B0000/XXXXXXXX", "custom-n8n": "vexor-alerts",
                 "shuffle": "https://shuffle.example.org/api/v1/hooks/webhook_0000", "maltiverse": "https://api.maltiverse.com"}


def dyn(key, ttl, fn, default):
    """Cached value of key without waiting (default until the first background refresh is done). Never raises."""
    try:
        v = peek(key, ttl, fn)
    except Exception:  # noqa: BLE001 - a suggestion source must never break typing
        return default
    return default if v is None else v


def agents_list():
    """[{id, name, status}] through the Wazuh API (seconds: only ever run by the cache in the background)."""
    out = run_quick([str(VEXOR), "--no-color", "api", "GET", "/agents?limit=1000&select=id,name,status"], timeout=40)
    try:
        items = json.loads(out[out.index("{"):]).get("data", {}).get("affected_items", [])
    except (ValueError, AttributeError):
        return []
    return [{"id": str(a.get("id", "")), "name": str(a.get("name", "")), "status": str(a.get("status", ""))} for a in items]


def project_volumes():
    p = env_dict().get("COMPOSE_PROJECT_NAME") or "vexor"
    out = run_quick(["docker", "volume", "ls", "-q", "--filter", f"label=com.docker.compose.project={p}"], timeout=20)
    return sorted(v.strip() for v in out.splitlines() if v.strip())


_env_keys = {}      # (mtimes) -> [(key, help)]


def env_keys():
    """Setting names with their help: .env.example in order, then keys only .env has. Keys, never values."""
    files = [f for f in (ENV_EXAMPLE, ENV_FILE) if f.exists()]
    try:
        stamp = tuple(f.stat().st_mtime_ns for f in files)
    except OSError:
        return []
    if stamp in _env_keys:
        return _env_keys[stamp]
    rows, seen, pending = [], set(), []
    try:
        lines = ENV_EXAMPLE.read_text(errors="replace").splitlines() if ENV_EXAMPLE.exists() else []
    except OSError:
        lines = []
    for raw in lines:
        line = raw.strip()
        m = re.match(r"^#? ?([A-Z][A-Z0-9_]*)=", line)
        if m:
            k = m.group(1)
            if k not in seen:
                seen.add(k)
                cm = re.search(r"\s+#\s?(.*)$", line[m.end():])
                rows.append((k, (cm.group(1) if cm else " ".join(pending)).strip()))
            pending = []
        elif line.startswith("#") and not re.match(r"^#\s*(----|====)", line):
            pending.append(line.lstrip("# ").strip())
        else:
            pending = []
    try:
        rows += [(k, "") for k, _, _ in read_env() if k not in seen]   # read_env: only its keys are used
    except OSError:
        pass
    _env_keys.clear()
    _env_keys[stamp] = rows
    return rows


def env_default(key):
    """Default of a NON-secret setting from .env.example (an example value for the hint), else ''."""
    if SECRET_RE.search(key):
        return ""
    try:
        for raw in ENV_EXAMPLE.read_text(errors="replace").splitlines():
            m = re.match(rf"^#? ?{re.escape(key)}=([^#\s]*)", raw.strip())
            if m and m.group(1) and m.group(1) != "CHANGE_ME":
                return m.group(1).strip("\"'")
    except OSError:
        pass
    return ""


# -- dynamic sources: fn(ctx) -> [(text, desc)]; ctx = {"words", "path", "positional"}
def src_services(ctx):
    rows = dyn("containers", TTL["containers"], containers, [])
    have = {r.get("service") for r in rows}
    out = [(a, d) for a, (svc, d) in SVC_ALIASES.items() if not have or svc is None or svc in have]
    for r in rows:
        if r.get("service"):
            out.append((r["service"], " ".join(x for x in (r.get("state"), f"({r['health']})" if r.get("health") else "") if x)))
    return out


def src_log_targets(ctx):
    svcs = src_services(ctx)
    return svcs[:3] + WAZUH_LOGS[:3] + svcs[3:] + WAZUH_LOGS[3:]


def det_files(kind, want=None):
    files = ((dyn("detection", TTL["detection"], detection, {}) or {}).get(kind) or {}).get("files") or []
    order = {"custom": 0, "vexor": 1, "wazuh": 2}
    label = {"custom": "custom", "vexor": "Vexor", "wazuh": "built-in"}
    what = {"rules": "rules", "decoders": "decoders", "lists": "entries"}.get(kind, "")
    out = []
    for f in sorted(files, key=lambda f: (order.get(f.get("source"), 3), not f.get("modified"))):
        if not f.get("name") or (want and not want(f)):
            continue
        src, n = f.get("source") or "", f.get("rules")
        out.append((f["name"], label.get(src, src) + (f", {n} {what}" if n is not None else "")
                    + (", edited" if f.get("modified") else "") + (f" - error: {f['error']}" if f.get("error") else "")))
    return out


def src_det_versions(ctx):
    kind = ctx["path"][1] if len(ctx["path"]) > 1 else ""
    name = ctx["positional"][0] if ctx["positional"] else ""
    fname = det_name(kind, name) or (name if kind != "lists" and name.endswith(".xml") else name + ("" if kind == "lists" else ".xml"))
    if not fname or ".." in fname:
        return []
    try:
        vers = sorted((p.name for p in (DET_HIST / kind / fname).iterdir() if DET_VERSION.match(p.name)), reverse=True)
    except OSError:
        return []
    return [(v, "saved version") for v in vers]


def det_integrations_list():
    return vexor_json(["wazuh", "integrations", "ls", "--json"], default={"integrations": [], "error": "vexor wazuh integrations ls failed"})


def det_config_list():
    return vexor_json(["wazuh", "config", "ls", "--json"], default={"settings": [], "error": "vexor wazuh config ls failed"})


def src_integrations(ctx):
    rows = (dyn("det-integrations", TTL["detection"], det_integrations_list, {}) or {}).get("integrations") or []
    seen, out = set(), []
    for r in rows:
        if r.get("name") and r["name"] not in seen:
            seen.add(r["name"])
            out.append((r["name"], "configured" + ("" if r.get("managed") else " (n8n / by hand)")))
    return out or INTEGRATIONS


def wconf_settings():
    return (dyn("det-config", TTL["detection"], det_config_list, {}) or {}).get("settings") or []


def src_wconf_keys(ctx):
    used = set(ctx["positional"][0::2])
    return [(s["key"], s.get("help") or "") for s in wconf_settings() if s.get("key") and s["key"] not in used]


def src_wconf_values(ctx):
    key = ctx["positional"][-1] if ctx["positional"] else ""
    s = next((s for s in wconf_settings() if s.get("key") == key), None)
    return [(str(c), "") for c in (s or {}).get("choices") or []]


def src_agents(ids):
    def fn(ctx):
        rows = dyn("complete-agents", COMPLETE_TTL["agents"], agents_list, [])
        if ids:
            return [(a["id"], f"{a['name']} ({a['status']})") for a in rows if a["id"] != "000"]
        return [(a["name"], f"agent {a['id']} ({a['status']})") for a in rows]
    return fn


def src_proxy_hosts(ctx):
    rows = (dyn("proxy", TTL["proxy"], proxy_routes, {}) or {}).get("routes") or []
    return [(r["host"], f"-> {r.get('target', '')} ({r.get('tls', '')})") for r in rows if r.get("host")]


def src_proxy_targets(ctx):
    sugg = (dyn("proxy", TTL["proxy"], proxy_routes, {}) or {}).get("suggestions") or []
    base = ["wazuh.dashboard:5601", "n8n:5678", "grafana:3000", "kibana:5601", "portainer:9000"]
    return [(t, "Vexor service") for t in dict.fromkeys(list(sugg) + base)]


def src_volumes(ctx):
    return [(v, "volume") for v in dyn("complete-volumes", COMPLETE_TTL["volumes"], project_volumes, [])]


def src_zeek_logs(ctx):
    try:
        names = sorted(p.stem for p in (ROOT / "tools-data" / "zeek" / "logs").iterdir() if re.fullmatch(r"[a-z_]+\.log", p.name))
    except OSError:
        names = []
    return [(n, "Zeek log") for n in names or ["conn", "dns", "http", "ssl", "ssh", "notice", "weird"]]


def src_env_keys(ctx):
    return [(k, (h + " (secret)" if SECRET_RE.search(k) else h)) for k, h in env_keys()]


def integ_name(ctx):
    return ctx["positional"][0] if ctx["positional"] else ""


def hook_example(ctx):
    return HOOK_EXAMPLES.get(integ_name(ctx), "https://example.org/hooks/vexor")


def env_value_hint(ctx):
    key = ctx["positional"][0] if ctx["positional"] else ""
    if SECRET_RE.search(key):
        return {"desc": f"secret {key}: the typed value shows in the job list and audit log - passwords: vexor passwd"}
    return {"desc": f"new value of {key} (written to .env; then: vexor config apply)", "example": env_default(key)}


def wconf_value_hint(ctx):
    key = ctx["positional"][-1] if ctx["positional"] else ""
    s = next((s for s in wconf_settings() if s.get("key") == key), {})
    ex = {"int": "10", "bool": "yes"}.get(s.get("type"), "")
    return {"desc": (s.get("help") or f"value of {key}") + " - lists: comma-separated", "example": ex}


def hint(ph, desc, example="", **kw):
    return dict(hint=ph, desc=desc, example=example, **kw)


def enum(*pairs, **kw):
    """Enumerated values [(text, desc)]; hint=... adds the free-form slot after them."""
    return dict(values=[p if isinstance(p, tuple) else (p, "") for p in pairs], **kw)


# value types: values (fixed), source (dynamic), hint (+ desc/example, either may be a fn(ctx) -> dict)
VALUES = {
    "service": dict(source=src_services, hint="<service>", desc="a compose service or a short name (master, nginx ...)", example="wazuh.master"),
    "logs-target": dict(source=src_log_targets),
    "wait-service": dict(source=lambda c: src_services(c) + [(s, "") for s in ("elasticsearch", "kibana", "logstash", "n8n", "grafana", "portainer")]),
    "lines": enum(("20", ""), ("50", ""), ("200", "default"), ("1000", ""), hint="<N>", desc="number of lines", example="100"),
    "duration": enum(("15m", "last 15 minutes"), ("1h", "last hour"), ("6h", "last 6 hours"), ("24h", "last day"),
                     hint="<duration>", desc="10m, 1h, 24h ... or a timestamp like 2026-10-23T08:00", example="1h"),
    "level": enum(("3", ""), ("7", "default for n8n"), ("10", ""), ("12", "high"), hint="<level>", desc="Wazuh rule level 0-15", example="10"),
    "grep": hint("<text>", "only alerts containing this text (case-insensitive)", "sshd"),
    "logline": hint('"<log-line>"', "one log line, quoted (no line: interactive - SSH only)",
                    '"Oct 23 10:00:01 srv sshd[812]: Failed password for root from 203.0.113.9 port 22 ssh2"'),
    "log-format": enum(*[(f, "") for f in ("syslog", "json", "eventchannel", "eventlog", "audit", "squid", "snort-full", "iis",
                                           "mysql_log", "postgresql_log", "nmapg", "command", "full_command", "djb-multilog", "multi-line")]),
    "location": hint("<location>", "location the line claims to come from", "/var/log/auth.log"),
    "from": enum(("-", "read the content from stdin"), hint="<path>", desc="file on the Vexor host to load", example="/tmp/local_rules.xml"),
    "det-rules": dict(source=lambda c: det_files("rules")), "det-decoders": dict(source=lambda c: det_files("decoders")),
    "det-lists": dict(source=lambda c: det_files("lists")),
    "det-put-rules": dict(source=lambda c: det_files("rules", lambda f: f.get("editable")), hint="<new-name>",
                          desc="a new custom file: 1-64 letters, digits, _ or -", example="local-ssh"),
    "det-put-decoders": dict(source=lambda c: det_files("decoders", lambda f: f.get("editable")), hint="<new-name>",
                             desc="a new custom file: 1-64 letters, digits, _ or -", example="local-firewall"),
    "det-put-lists": dict(source=lambda c: det_files("lists", lambda f: f.get("editable")), hint="<new-name>",
                          desc="a new CDB list: 1-64 letters, digits, _ or -", example="blocked-ips"),
    "det-custom-rules": dict(source=lambda c: det_files("rules", lambda f: f.get("source") == "custom")),
    "det-custom-decoders": dict(source=lambda c: det_files("decoders", lambda f: f.get("source") == "custom")),
    "det-custom-lists": dict(source=lambda c: det_files("lists", lambda f: f.get("source") == "custom")),
    "det-builtin-rules": dict(source=lambda c: det_files("rules", lambda f: f.get("source") == "wazuh")),
    "det-builtin-decoders": dict(source=lambda c: det_files("decoders", lambda f: f.get("source") == "wazuh")),
    "det-builtin-lists": dict(source=lambda c: det_files("lists", lambda f: f.get("source") == "wazuh")),
    "det-version": dict(source=src_det_versions, hint="<version>", desc="a saved version (vexor wazuh <kind> history <name>)", example="20261023T101500Z"),
    "list-entry": hint("<key>[:<value>]", "CDB entry to add (IP, hash, user ...) with an optional value", "203.0.113.9:blocked"),
    "list-key": hint("<key>", "CDB key to delete", "203.0.113.9"),
    "integ-new": enum(*INTEGRATIONS, hint="custom-<id>", desc="your own integration script (custom-<id>)", example="custom-teams"),
    "integ-name": dict(source=src_integrations),
    "hook-url": hint("<hook-url>", "webhook URL (custom-n8n: path on the bundled n8n or a full URL)", hook_example),
    "api-key": hint("<api-key>", "the key itself - never stored in history or the audit log (shown as ****)"),
    "key-file": hint("<file>", "file holding the API key (keeps it out of the command line)", "/root/vt.key"),
    "group": hint("<group>", "only alerts of these rule groups (comma-separated)", "authentication_failed,sshd"),
    "rule-ids": hint("<rule-ids>", "only these rule ids (comma-separated)", "5710,5712"),
    "integ-format": enum(("json", "alert format the script receives")),
    "wconf-key": dict(source=src_wconf_keys, hint="<key>", desc="a curated ossec.conf setting (vexor wazuh config ls)", example="log_alert_level"),
    "wconf-value": dict(source=src_wconf_values, hint="<value>", dynhint=wconf_value_hint),
    "scope": enum(("master", "only the master (default)"), ("all", "every manager")),
    "os": enum(("linux", "deb-based"), ("rpm", "rpm-based"), ("windows", "PowerShell"), ("macos", "pkg")),
    "agent-name": dict(source=src_agents(False), hint="<agent-name>", desc="agent name", example="srv-linux"),
    "agent-ids": dict(source=src_agents(True), hint="<id[,id..]>", desc="agent ids (vexor agents list)", example="003,004"),
    "name": hint("<name>", "agent name to register", "web-01"),
    "password": hint("[password]", "enrollment password (empty: one is generated); kept in .env"),
    "n8n-path": hint("<path|url>", "webhook path on the bundled n8n (default vexor-alerts) or a full URL", "vexor-alerts"),
    "extra-hooks": hint("<url|level|groups;..>", "more webhooks, ;-separated", "http://n8n:5678/webhook/vexor-crit|12|"),
    "ip": hint("<ip>", "source IP of the fake alert", "203.0.113.9"),
    "dir": hint("<dir>", "directory on the Vexor host", "/srv/backups"),
    "file": hint("<file>", "file on the Vexor host", "/srv/backups/volumes/20261023-013000/vexor_n8n-data.tar.gz"),
    "snapshot": hint("<snapshot-id>", "indexer snapshot (vexor backup list)", "vexor-20261023-013000"),
    "es-snapshot": hint("<es-snap-id>", "Elasticsearch snapshot (vexor backup list)", "vexor-es-20261023-013000"),
    "stamp": hint("<stamp>", "manager state backup (vexor backup list)", "20261015-013000"),
    "config-archive": hint("<file>", "config backup archive", "backups/stack-config-20261015-013000.tar.gz"),
    "index-pattern": hint("<pattern>", "index pattern", "wazuh-alerts-4.x-2026.10.*"),
    "days": enum(("30", ""), ("90", ""), hint="<days>", desc="whole number of days", example="60"),
    "rule-id": hint("<rule-id>", "one rule id", "5710"),
    "lucene": hint("<query>", "Lucene query", "agent.name:srv-linux AND rule.level:>10"),
    "query": hint("<query>", "Lucene query (empty: newest events)", "event.dataset:zeek.dns"),
    "env-key": dict(source=src_env_keys, hint="<KEY>", desc="a .env setting", example="RETENTION_DAYS"),
    "env-value": dict(hint="<value>", dynhint=env_value_hint),
    "kv": hint("KEY=VALUE", "a setting to try (nothing is changed)", "WORKER_COUNT=2"),
    "login-name": enum(*[(n, "") for n in ("dashboard", "indexer", "api", "enroll", "n8n", "grafana", "portainer", "console",
                                           "kibana", "elasticsearch", "logstash", "wazuh", "elk")]),
    "proxy-host": dict(source=src_proxy_hosts),
    "proxy-host-ca": dict(source=lambda c: src_proxy_hosts(c) + [("ca", "the local CA")]),
    "new-host": hint("<host>", "domain, subdomain or IPv4 address", "soc.example.com"),
    "proxy-target": dict(source=src_proxy_targets, hint="<target>", desc="Vexor service:port or [http(s)://]IP:PORT", example="192.168.1.20:8443"),
    "cert-what": enum(("cert", "the route certificate"), ("ca", "the local CA")),
    "tls": enum(("local", "local CA (default)"), ("letsencrypt", "Let's Encrypt, http-01 on port 80"), ("off", "plain HTTP")),
    "size": hint("<size>", "largest request body", "100m"),
    "cert-name": hint("[name|ip ..]", "names / IPs the certificate covers (default: this host)", "soc.example.com"),
    "port": hint("[port]", "temporary download port (default 8081)", "8081"),
    "crt": hint("<cert.pem>", "certificate file", "/root/soc.crt"), "key": hint("<key.pem>", "private key file", "/root/soc.key"),
    "chain": hint("[chain.pem]", "intermediate chain file", "/root/chain.pem"),
    "domain": hint("<domain>", "public DNS name pointing to this host", "soc.example.com"),
    "email": hint("<email>", "Let's Encrypt account address", "admin@example.com"),
    "tool": enum(("n8n", "automation / SOAR"), ("grafana", "dashboards"), ("portainer", "Docker UI"), ("suricata", "network IDS"), ("zeek", "network logs")),
    "zeek-log": dict(source=src_zeek_logs), "zeek-top": enum(("hosts", "top talkers"), ("ports", "top ports"), ("dns", "top DNS names")),
    "es-method": enum("GET", "POST", "PUT", "DELETE"),
    "es-path": enum(("/_cat/indices?v", ""), ("/_cluster/health?pretty", ""), ("/_cat/nodes?v", ""), hint="<path>", desc="Elasticsearch API path", example="/_cat/shards?v"),
    "json-body": hint("['json']", "request body", '\'{"size": 1}\''),
    "get": enum(("GET", "only GET in the console")),
    "ix-path": enum(("/_cat/indices?v", "indices"), ("/_cluster/health?pretty", "cluster health"), ("/_cat/nodes?v", "nodes"),
                    ("/_cat/shards?v", "shards"), hint="<path>", desc="indexer API path", example="/_cat/aliases?v"),
    "api-path": enum(("/agents/summary/status", "agent counts"), ("/manager/info", "manager version"), ("/cluster/healthcheck", "cluster"),
                     ("/manager/status", "daemons"), hint="<path>", desc="Wazuh API path", example="/agents?status=disconnected"),
    "update-version": enum(("latest", "newest 4.x release"), hint="<version>", desc="a Wazuh 4.x version", example="4.14.8"),
    "notify-level": enum("fail", "warn", "ok", "info"), "message": hint('"<message>"', "text of the alert", '"disk 90% full"'),
    "reminder-id": hint("<id>", "reminder id (vexor reminders)", "indexer-cleanup"),
    "number": hint("[N]", "number of lines", "100"), "seconds": hint("<seconds>", "how long to wait", "300"),
    "scale-n": enum(("1", "one worker"), ("2", "two workers"), ("3", "three workers")), "indexer-count": enum("1", "3"),
    "volume": dict(source=src_volumes, hint="<volume>", desc="volume name (the project prefix is optional)", example="n8n-data"),
    "volume-all": dict(source=lambda c: [("all", "every volume of the project")] + src_volumes(c)),
}


def N(desc, subs=None, args=(), flags=None, repeat=0, aliases=None, usage=None, hidden=False):
    """One grammar node: subcommands, positional slots (value types), flags {flag: (value type | None, desc[, when(ctx)])}."""
    return {"desc": desc, "subs": subs or {}, "args": list(args), "flags": flags or {}, "repeat": repeat,
            "aliases": aliases or {}, "usage": usage, "hidden": hidden}


JSON_FLAG = {"--json": (None, "machine-readable output")}
LOG_FLAGS = {"-f": (None, "follow (streams until you stop it)"), "-n": ("lines", "number of lines (default 200)"),
             "--since": ("duration", "only lines newer than this")}
FROM_FLAG = {"--from": ("from", "load the content from this file (- = stdin)")}
no_n8n = lambda c: integ_name(c) != "custom-n8n"
INTEG_FLAGS = {
    "--hook-url": ("hook-url", "webhook URL (custom-n8n: path or URL)", lambda c: integ_name(c) not in ("pagerduty", "virustotal")),
    "--level": ("level", "only alerts of this level or higher"),
    "--group": ("group", "only these rule groups"),
    "--rule-id": ("rule-ids", "only these rule ids", no_n8n),
    "--api-key": ("api-key", "API key / token (never stored in history or audit)", no_n8n),
    "--api-key-file": ("key-file", "read the API key from a file", no_n8n),
    "--format": ("integ-format", "alert format", no_n8n),
}


def det_node(kind):
    subs = {
        "ls": N(f"custom and built-in {kind}", flags=JSON_FLAG),
        "show": N(f"print one {kind[:-1]} file", args=[f"det-{kind}"]),
        "put": N("save a file (checked by Wazuh, rolled back when refused)", args=[f"det-put-{kind}"], flags=FROM_FLAG),
        "history": N("saved versions of a file", args=[f"det-{kind}"], flags=JSON_FLAG),
        "restore": N("bring back a saved version", args=[f"det-{kind}", "det-version"]),
        "templates": N("starter templates", flags=JSON_FLAG),
        "reset": N("back to the shipped built-in file (history kept)", args=[f"det-builtin-{kind}"]),
        "rm": N("delete a custom file", args=[f"det-custom-{kind}"]),
    }
    if kind == "lists":
        subs["add"] = N("add an entry to a CDB list", args=["det-lists", "list-entry"])
        subs["del"] = N("delete an entry from a CDB list", args=["det-lists", "list-key"])
    return N(f"Wazuh {kind}: custom files and edited built-ins", subs=subs,
             aliases={"list": "ls", "cat": "show", "save": "put", "remove": "rm", "delete": "rm"})


AGENTS_NODE = N("Wazuh agents: list, enroll commands, remove", subs={
    "list": N("every agent with status, version, OS"),
    "summary": N("agent counts by status"),
    "outdated": N("agents older than the manager"),
    "enroll-cmd": N("copy-paste install commands", args=["os"], flags={"--name": ("name", "agent name"), "--group": ("group", "agent group")}),
    "remove": N("remove agents (they must re-enroll)", args=["agent-ids"]),
    "password": N("enrollment password", subs={"on": N("require a password", args=["password"]), "off": N("no password"),
                                               "show": N("print the password")}),
}, aliases={"ls": "list", "rm": "remove", "delete": "remove"})

# Order = suggestion order on an empty line: the commands people use most first.
GRAMMAR = {
    "status": N("containers, manager/indexer cluster, agents, dashboard, disk"),
    "doctor": N("~60 checks with hints; --fix repairs what is safe", flags={"--fix": (None, "repair what is safe")}),
    "logs": N("container logs, Wazuh log files, recent errors", args=["logs-target"], repeat=1, flags=LOG_FLAGS,
              usage="vexor logs [svc..|ossec|api|cluster|alerts [node]|errors|size] [-f] [-n N] [--since 10m]"),
    "wazuh": N("Wazuh: alerts, logtest, rules, decoders, lists, integrations, ossec.conf", subs={
        "status": N("indexer / manager cluster / API details"),
        "alerts": N("newest alerts of every manager", flags={"-n": ("lines", "number of alerts (default 20)"),
                                                            "--level": ("level", "only this level or higher"),
                                                            "--grep": ("grep", "only alerts containing this text")}),
        "rules": det_node("rules"), "decoders": det_node("decoders"), "lists": det_node("lists"),
        "integrations": N("Slack, PagerDuty, VirusTotal, Shuffle, Maltiverse, n8n, custom scripts", subs={
            "ls": N("configured integrations", flags=JSON_FLAG),
            "add": N("add an integration", args=["integ-new"], flags=INTEG_FLAGS,
                     usage="vexor wazuh integrations add <name> [--hook-url URL] [--api-key K] [--level N] [--group G] [--rule-id IDS] [--format json]"),
            "edit": N("change an integration", args=["integ-name"], flags=INTEG_FLAGS,
                      usage="vexor wazuh integrations edit <name> [--hook-url URL] [--api-key K] [--level N] [--group G] [--rule-id IDS] [--format json]"),
            "test": N("send a test alert through it", args=["integ-name"]),
            "rm": N("remove an integration", args=["integ-name"]),
            "raw": N("the managed integrations as XML", subs={"show": N("print the XML"), "put": N("replace the XML", flags=FROM_FLAG)}),
        }, aliases={"list": "ls", "remove": "rm", "delete": "rm", "del": "rm"},
            usage="vexor wazuh integrations ls | add|edit <name> [--hook-url URL] [--api-key K] [--level N] [--group G] [--rule-id IDS] | rm|test <name> | raw show|put"),
        "logtest": N("run one log line through the master's decoders and rules", args=["logline"],
                     flags={"--format": ("log-format", "log format (default syslog)"), "--location": ("location", "claimed source"), **JSON_FLAG}),
        "config": N("curated ossec.conf settings and a raw XML block", subs={
            "ls": N("settings with their values", flags=JSON_FLAG),
            "set": N("change settings (checked by Wazuh, managers recreated)", args=["wconf-key", "wconf-value"], repeat=2,
                     usage="vexor wazuh config set <key> <value> [<key> <value> ..]"),
            "custom": N("your own XML block in ossec.conf", subs={
                "show": N("print the block"), "put": N("replace the block", flags={**FROM_FLAG, "--scope": ("scope", "master or all managers")}),
                "rm": N("remove the block")}),
        }, aliases={"list": "ls"}),
        "detection": N("custom file counts, last change, last error", subs={"status": N("detection status", flags={**JSON_FLAG, "--all": (None, "with every file")})}),
        "agents": AGENTS_NODE,
        "cluster": N("manager cluster nodes"),
    }, aliases={"integration": "integrations"}),
    "agents": AGENTS_NODE,
    "n8n": N("automation / SOAR: alert forwarding, workflow, credentials", subs={
        "status": N("n8n, owner, alert forwarding, webhook, credentials"),
        "connect": N("send alerts to an n8n webhook", args=["n8n-path"], flags={"--level": ("level", "lowest alert level (default 7)"),
                                                                               "--groups": ("group", "only these rule groups"),
                                                                               "--extra": ("extra-hooks", "more webhooks")},
                     usage="vexor n8n connect [path|url] [--level N] [--groups G]"),
        "workflow": N("import + publish the starter workflow", subs={"import": N("import and publish"), "file": N("write the workflow JSON")}),
        "test": N("send a fake alert through the workflow", flags={"--level": ("level", "level of the fake alert (default 12)"), "--srcip": ("ip", "source IP")}),
        "credentials": N("Wazuh API + Elasticsearch users for n8n"),
        "disconnect": N("stop sending alerts to n8n"),
        "enable": N("start n8n (N8N=true)"), "disable": N("remove n8n (data kept)"),
        "backup": N("export workflows and credentials", args=["dir"]),
        "reset-owner": N("remove every n8n user account"),
        "logs": N("n8n container log", flags=LOG_FLAGS),
    }),
    "backup": N("snapshots, manager state and config; restores", subs={
        "run": N("back up now"), "list": N("backups and snapshots"), "register": N("register the snapshot repository"),
        "restore-snapshot": N("restore indexer indices", args=["snapshot"], flags={"--indices": ("index-pattern", "only these indices"),
                                                                                 "--rename": (None, "restore as restored-*")}),
        "restore-es": N("restore Elasticsearch indices", args=["es-snapshot"], flags={"--indices": ("index-pattern", "only these indices"),
                                                                                  "--rename": (None, "restore as restored-*"), "--kibana": (None, "also Kibana")}),
        "restore-manager": N("restore manager state", args=["stamp"]),
        "restore-config": N("restore the stack config", args=["config-archive"]),
    }, aliases={"ls": "list"}),
    "health": N("detailed indexer / manager / API state"),
    "restart": N("restart everything or the given services", args=["service"], repeat=1),
    "start": N("start the stack (or services) and wait until ready", args=["service"], repeat=1),
    "stop": N("stop containers", args=["service"], repeat=1),
    "info": N("dashboard URL, login, agent ports, certificate mode", flags={"--show-secrets": (None, "print the passwords too")}),
    "login": N("url, user and password of every managed login", args=["login-name"], repeat=1, flags=JSON_FLAG),
    "config": N(".env settings: show, get, set, validate, apply", subs={
        "show": N("every setting (secrets masked)", flags={"--show-secrets": (None, "print the secrets too")}),
        "get": N("one setting", args=["env-key"]), "set": N("change one setting in .env", args=["env-key", "env-value"]),
        "validate": N("check .env"), "plan": N("what an apply would change"), "apply": N("apply .env to the stack"),
        "edit": N("open .env in an editor (terminal only)"),
    }),
    "plan": N("what an apply would change, without changing anything", args=["kv"], repeat=1, flags=JSON_FLAG),
    "proxy": N("named hosts through nginx (TLS, websockets)", subs={
        "ls": N("routes, target, TLS, certificate expiry", flags=JSON_FLAG), "show": N("one route", args=["proxy-host"]),
        "add": N("add a route", args=["new-host", "proxy-target"], flags={"--tls": ("tls", "certificate mode"), "--websocket": (None, "pass websockets"),
                                                                       "--max-body": ("size", "largest request body")}),
        "edit": N("change a route", args=["proxy-host"], flags={"--target": ("proxy-target", "new target"), "--tls": ("tls", "certificate mode"),
                                                               "--websocket": (None, "pass websockets"), "--no-websocket": (None, "no websockets"),
                                                               "--max-body": ("size", "largest request body")}),
        "rm": N("remove a route and its certificate", args=["proxy-host"]),
        "cert": N("issue / re-issue the route certificate", args=["proxy-host"], flags={"--renew": (None, "renew now")}),
        "cert-file": N("path of a route certificate or the local CA", args=["proxy-host-ca", "cert-what"]),
        "apply": N("re-render, nginx -t, reload"),
    }, aliases={"list": "ls", "remove": "rm", "del": "rm", "delete": "rm"}),
    "cert": N("dashboard certificate: local CA, import, Let's Encrypt", subs={
        "status": N("names, issuer, expiry"), "create": N("local CA + certificate for this host", args=["cert-name"], repeat=1),
        "export-ca": N("CA file + install steps", args=["dir"]), "serve-ca": N("temporary http download of the CA", args=["port"]),
        "import": N("use your own certificate", args=["crt", "key", "chain"]),
        "letsencrypt": N("public certificate", args=["domain"], flags={"--email": ("email", "account address"),
                                                                    "--staging": (None, "test CA"), "--dns": (None, "DNS challenge")}),
        "renew": N("renew when < 30 days left", flags={"--force": (None, "renew now")}),
        "use-default": N("back to the built-in self-signed certificate"),
        "internal-regen": N("re-issue internal node certificates (restarts the stack)"),
    }),
    "tools": N("optional tools: n8n, Grafana, Portainer, Suricata, Zeek", subs={
        "status": N("enabled, state, URL of every tool"), "apply": N("start enabled / remove disabled tools"),
        "enable": N("turn a tool on", args=["tool"]), "disable": N("turn a tool off", args=["tool"]),
        "update-rules": N("update Suricata rules"),
    }),
    "suricata": N("network IDS", subs={
        "status": N("signatures, alerts in 24 h, top signatures"),
        "alerts": N("newest alerts", flags={"-n": ("lines", "number of alerts"), "--since": ("duration", "only newer than")}),
        "test": N("real test traffic -> Suricata -> Wazuh"), "update-rules": N("download new rules"),
        "enable": N("SURICATA=true"), "disable": N("SURICATA=false"), "logs": N("Suricata container log", flags=LOG_FLAGS),
    }),
    "zeek": N("network logs", subs={
        "status": N("log files, size, freshness"), "show": N("readable lines of one log", args=["zeek-log"], flags={"-n": ("lines", "number of lines")}),
        "notices": N("notice.log", flags={"-n": ("lines", "number of lines")}), "top": N("top talkers, ports, DNS names", args=["zeek-top"]),
        "test": N("generate test traffic"), "enable": N("ZEEK=true"), "disable": N("ZEEK=false"), "logs": N("Zeek container log", flags=LOG_FLAGS),
    }),
    "elk": N("Elasticsearch, Logstash, Kibana (SOC=elk|both)", subs={
        "status": N("health, Kibana, events in the last hour"), "indices": N("vexor-* indices"),
        "search": N("Lucene search, newest first", args=["query"], flags={"-n": ("lines", "number of hits"), "--index": ("index-pattern", "index pattern")}),
        "data-views": N("re-create Kibana data views"), "retention": N("re-apply ILM retention"),
        "beats-config": N("filebeat.yml for other machines"), "beats-ca": N("the CA Beats trust"),
        "es": N("raw Elasticsearch API", args=["es-method", "es-path", "json-body"]),
        "explain": N("shard allocation explain"), "reset-password": N("new elastic password (+ .env)"),
        "logs": N("ELK container logs", args=["service"]),
    }),
    "soc": N("which SOC stacks run; switch them", subs={
        "status": N("which stacks run"), "wazuh": N("Wazuh only"), "elk": N("ELK only"), "both": N("Wazuh + ELK")}),
    "retention": N("delete Wazuh and ELK data older than RETENTION_DAYS", subs={
        "status": N("policies and index sizes"), "apply": N("apply the retention policies"),
        "purge": N("delete documents matching a filter", flags={
            "--older-than": ("days", "older than N days"), "--agent": ("agent-name", "of this agent"), "--rule-id": ("rule-id", "of this rule"),
            "--sca": (None, "SCA results"), "--query": ("lucene", "matching a Lucene query"), "--index": ("index-pattern", "only these indices"),
            "--dry-run": (None, "count only"), "--compact": (None, "free the disk space afterwards")}),
    }, aliases={"show": "status"}),
    "volumes": N("Docker volumes: list, back up, restore, remove", subs={
        "ls": N("volumes, size, users"), "orphans": N("volumes no service uses"),
        "backup": N("tar.gz of a volume", args=["volume-all"], flags={"--stop": (None, "stop its users first"), "--out": ("dir", "target directory")}),
        "restore": N("restore a volume from a tar.gz", args=["volume", "file"]), "rm": N("remove a volume", args=["volume"]),
        "prune": N("remove orphan volumes", flags={"--yes": (None, "confirmed")}),
    }, aliases={"list": "ls"}),
    "disk": N("free/used space of every filesystem Docker uses", flags=JSON_FLAG),
    "console": N("this web console", subs={
        "status": N("is it up"), "url": N("where"), "restart": N("restart it"), "logs": N("its journal", args=["number"]),
        "password": N("show / rotate the login", flags={"--generate": (None, "new random password")}),
        "enable": N("start the service"), "disable": N("stop the service"),
    }),
    "cluster": N("manager cluster nodes"),
    "version": N("vexor and Wazuh version"),
    "update": N("Wazuh version upgrades", subs={
        "check": N("current vs latest 4.x"), "apply": N("upgrade", args=["update-version"], flags={"--no-backup": (None, "skip the backup"), "--force": (None, "even with warnings")}),
        "rollback": N("back to the version before"), "images": N("re-pull current images"),
    }),
    "notify": N("health alerts to NOTIFY_URL or n8n", subs={
        "status": N("target and last alerts"), "test": N("send a test alert"), "send": N("send an alert", args=["notify-level", "message"])}),
    "reminders": N("follow-up tasks", subs={"list": N("open reminders"), "done": N("close a reminder", args=["reminder-id"])}),
    "indexer": N("raw indexer API (GET only here)", args=["get", "ix-path"], usage="vexor indexer GET <path>   e.g. vexor indexer GET '/_cat/indices?v'"),
    "api": N("raw Wazuh API (GET only here)", args=["get", "api-path"], usage="vexor api GET <path>   e.g. vexor api GET /agents/summary/status"),
    "wait-ready": N("wait until services are running and healthy", args=["wait-service"], repeat=1,
                    flags={"--timeout": ("seconds", "give up after"), **JSON_FLAG}),
    "wait": N("= wait-ready", args=["wait-service"], repeat=1, flags={"--timeout": ("seconds", "give up after"), **JSON_FLAG}, hidden=True),
    "support-bundle": N("diagnostics archive (secrets masked)"),
    "ai-context": N("one Markdown file for an AI diagnosis (masked)", flags={"--print": (None, "print instead of writing a file")}),
    "maintenance": N("prune logs, retention, certificate renewal, image cleanup"),
    "watchdog": N("one self-heal pass"),
    "prune-logs": N("delete rotated manager logs older than MANAGER_LOG_RETENTION_DAYS"),
    "daemon": N("boot service, timers, completion", subs={
        "status": N("units and timers"), "install": N("install units and timers"), "uninstall": N("remove them"), "logs": N("journal", args=["number"])}),
    "scale": N("number of worker managers (multi)", args=["scale-n"]),
    "node-type": N("single or multi node layout", subs={
        "status": N("applied layout"), "single": N("-> 1 manager, 1 indexer", flags={"--dry-run": (None, "show the plan"), "--no-backup": (None, "skip the backup")}),
        "multi": N("-> master + workers, 3 indexers", flags={"--indexers": ("indexer-count", "1 or 3 indexers"), "--dry-run": (None, "show the plan"),
                                                             "--no-backup": (None, "skip the backup")})}),
    "indexers": N("indexer cluster size", subs={
        "status": N("nodes, shards, leftovers"), "1": N("3 -> 1 indexer", flags={"--dry-run": (None, "show the plan"), "--no-backup": (None, "skip the backup")}),
        "3": N("1 -> 3 indexers", flags={"--dry-run": (None, "show the plan"), "--no-backup": (None, "skip the backup")}),
        "abort": N("undo an unfinished shrink"), "cleanup": N("delete the old wazuh2/3 volumes")}),
    "passwd": N("change a password on the running stack (+ .env)", subs={
        u: N(f"the {u} password", flags={"--generate": (None, "random password")}) for u in ("admin", "kibanaserver", "api")}),
    "images": N("old image versions", subs={"prune": N("remove old image versions", flags={"--yes": (None, "confirmed")})}),
    "reset": N("remove containers / data", subs={"containers": N("remove containers"), "data": N("remove data volumes"),
                                                 "full": N("everything but .env"), "purge": N("everything (terminal only)")}),
    "migrate": N("rename the old 'wazuh' Docker project to vexor", flags={"--yes": (None, "no prompt")}),
    "uninstall": N("remove this project (plan + confirm first)", flags={"--keep-data": (None, "keep volumes and files"),
                                                                        "--images": (None, "also images"), "--yes": (None, "confirmed")}),
}
GRAMMAR_ROOT = N("vexor", subs=GRAMMAR, usage="vexor <command> [args]")


def split_line(line):
    """Shell-like words [(start, value)] of line; tolerates an unterminated quote. The last word is the one being typed
    (an empty one when the line ends with blank space)."""
    words, i, n = [], 0, len(line)
    while True:
        while i < n and line[i].isspace():
            i += 1
        if i >= n:
            words.append((n, ""))
            return words
        start, buf, quote = i, [], None
        while i < n:
            ch = line[i]
            if quote:
                if ch == quote:
                    quote = None
                elif ch == "\\" and quote == '"' and i + 1 < n:
                    i += 1
                    buf.append(line[i])
                else:
                    buf.append(ch)
            elif ch in "'\"":
                quote = ch
            elif ch == "\\" and i + 1 < n:
                i += 1
                buf.append(line[i])
            elif ch.isspace():
                break
            else:
                buf.append(ch)
            i += 1
        words.append((start, "".join(buf)))
        if i >= n:
            return words


def line_level(words):
    """read|change|danger of a (possibly unfinished) command line, None when the console refuses it."""
    if not words:
        return None
    level, err = classify(words)
    if not err:
        return level
    if any(f[:len(words)] == words for f in DANGER_EXACT.get(words[0], [])):
        return "danger"
    for extra in (["x"], ["GET", "/"], ["x", "x"]):        # still needs an argument (wazuh logtest <line>, api GET <path>)
        level, e = classify(words + extra)
        if not e:
            return level
    return None


def match_rank(token, text):
    """0 prefix, 1 word start, 2 substring, 3 subsequence, 4 close (typo); None = no match. Case-insensitive."""
    t, s = token.lower(), text.lower()
    if not t or s.startswith(t):
        return 0
    if any(seg.startswith(t) for seg in re.split(r"[-_./:=,<>\[\]]+", s) if seg):
        return 1
    if t in s:
        return 2
    if len(t) >= 2 and s.lstrip("-<[")[:1] == t.lstrip("-")[:1]:     # same first letter, then in order: dctr -> doctor
        it = iter(s)
        if all(c in it for c in t):
            return 3
    if len(t) >= 3 and difflib.SequenceMatcher(None, t, s[:len(t) + 2]).ratio() >= 0.75:
        return 4
    return None


def walk(words):
    """Follow the completed words through the grammar -> (node, path, stack, used flags, positional, pending value type)."""
    node, path, stack, used, positional, pending = GRAMMAR_ROOT, [], [GRAMMAR_ROOT], set(), [], None
    for w in words:
        if pending is not None:
            pending = None
            continue
        if w.startswith("-") and len(w) > 1:
            name, eq, _ = w.partition("=")
            spec = next((n["flags"][name] for n in reversed(stack) if name in n["flags"]), None)
            used.add(name)
            if spec and spec[0] and not eq:
                pending = spec[0]
            continue
        key = node["aliases"].get(w, w)
        if not positional and key in node["subs"]:
            node = node["subs"][key]
            path.append(key)
            stack.append(node)
            continue
        positional.append(w)
    return node, path, stack, used, positional, pending


def slot_type(node, positional):
    args, i, r = node["args"], len(positional), node["repeat"]
    if i < len(args):
        return args[i]
    if r and args:
        return args[len(args) - r + (i - len(args)) % r]
    return None


def value_items(vtype, ctx, exclude=()):
    """-> (values [(text, desc)], hint item or None) of a value type."""
    spec = VALUES.get(vtype) or {}
    vals = list(spec.get("values") or [])
    if spec.get("source"):
        try:
            vals += spec["source"](ctx)
        except Exception:  # noqa: BLE001 - a broken source gives no suggestions, never an error
            pass
    vals = [(t, d) for t, d in dict((t, d) for t, d in vals if t not in exclude).items()]
    h = None
    if spec.get("hint"):
        h = {"text": spec["hint"], "desc": spec.get("desc", ""), "example": spec.get("example", "")}
        if callable(h["example"]):
            h["example"] = h["example"](ctx)
        if spec.get("dynhint"):
            h.update(spec["dynhint"](ctx))
    return vals, h


def node_usage(path, node):
    if node["usage"]:
        return node["usage"]
    parts = ["vexor", *path]
    subs = [s for s, n in node["subs"].items() if not n["hidden"]]
    if subs:
        parts.append("|".join(subs[:9]) + ("|.." if len(subs) > 9 else ""))
    for a in node["args"]:
        parts.append((VALUES.get(a) or {}).get("hint") or f"<{a}>")
    if node["repeat"]:
        parts.append("..")
    for f, spec in node["flags"].items():
        parts.append(f"[{f}" + (f" {(VALUES.get(spec[0]) or {}).get('hint') or spec[0].upper()}" if spec[0] else "") + "]")
    u = " ".join(parts)
    return u if len(u) <= 160 else u[:157] + "..."


def complete(line):
    """Suggestions for the word under the end of line: {start, token, items, usage, level}. See /api/complete."""
    line = line[:2000]
    m = re.match(r"\s*vexor\s+", line)
    off = m.end() if m else 0
    parts = split_line(line[off:])
    start, token = parts[-1][0] + off, parts[-1][1]
    words = [w for _, w in parts[:-1]]
    out = {"start": start, "token": token, "items": [], "usage": "", "level": None}
    if words:
        out["level"] = line_level(words) or "blocked"
        if words[0] not in GRAMMAR or out["level"] == "blocked":
            out["usage"] = classify(words)[1] or ""
            return out
    node, path, stack, used, positional, pending = walk(words)
    ctx = {"words": words, "path": path, "positional": positional}
    out["usage"] = node_usage(path, node) if words else ""
    cands, hint_item = [], None          # (kind, text, desc, level words)
    if pending is not None:
        vals, hint_item = value_items(pending, ctx)
        cands += [("value", t, d) for t, d in vals]
    else:
        if not token.startswith("-"):
            if not positional:
                cands += [("command" if not words else "sub", s, n["desc"]) for s, n in node["subs"].items() if not n["hidden"]]
            vtype = slot_type(node, positional)
            if vtype:
                vals, hint_item = value_items(vtype, ctx, exclude=set(positional) if node["repeat"] else ())
                cands += [("value", t, d) for t, d in vals]
        for n in reversed(stack):
            for f, spec in n["flags"].items():
                if f not in used and (len(spec) < 3 or spec[2](ctx)):
                    cands.append(("flag", f, spec[1]))
            if n["flags"]:
                break                     # the deepest node with flags owns them
    ranked, seen = [], set()
    for i, (kind, text, desc) in enumerate(cands):
        r = match_rank(token, text)
        if r is None or text in seen:
            continue
        lvl = line_level(words + [text])
        if lvl is None:
            continue                      # blocked or refused in the console: never suggested
        seen.add(text)
        ranked.append((r, i, {"text": shlex.quote(text) if kind == "value" and re.search(r"[\s'\"\\$`;&|<>()*?#]", text) else text,
                              "kind": kind, "desc": (desc or "")[:90], "level": lvl, "insertable": True}))
    ranked.sort(key=lambda x: (x[0], x[1]))
    items = [x[2] for x in ranked]
    if hint_item:
        lvl = line_level(words + [hint_item["example"] or "x"])
        if lvl is not None:
            items = items[:COMPLETE_MAX - 1]
            items.append({"text": hint_item["text"], "kind": "hint", "desc": (hint_item["desc"] or "")[:90], "level": lvl,
                          "insertable": False, "example": hint_item["example"] or ""})
    out["items"] = items[:COMPLETE_MAX]
    return out


# ---------------------------------------------------------------- auth
SESSIONS = {}
FAILS = {}


def console_creds():
    env = env_dict()
    return env.get("CONSOLE_USER", "admin"), env.get("CONSOLE_PASSWORD", "")


PW_FILE = STATE / "console-password-set"   # scrypt of the password the user chose in the console
PW_MIN = 12
PW_CHARS = re.compile(r"[A-Za-z0-9._@%+=:,/!^*()~-]+")   # what .env holds unquoted and compose reads back as is
PW_FAILS = {}
_pw_seen = {}


def pw_digest(pw, salt):
    return hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1).hex()


def password_temp():
    """True while CONSOLE_PASSWORD is not one the user chose here (still the generated one)."""
    pw = console_creds()[1]
    if not pw:
        return False
    if pw in _pw_seen:
        return _pw_seen[pw]
    try:
        salt_hex, want = PW_FILE.read_text().split()
        temp = not hmac.compare_digest(pw_digest(pw, bytes.fromhex(salt_hex)), want)
    except (OSError, ValueError):
        temp = True
    _pw_seen.clear()
    _pw_seen[pw] = temp
    return temp


def write_env_value(key, value):
    lines = ENV_FILE.read_text().split("\n")
    hits = [i for i, ln in enumerate(lines) if ln.startswith(key + "=")]
    if hits:
        m = re.match(r"^[^=]*=[^#]*?(\s+#.*)?$", lines[hits[-1]])
        lines[hits[-1]] = f"{key}={value}" + (m.group(1) if m and m.group(1) else "")
    else:
        lines.insert(len(lines) - 1 if lines and lines[-1] == "" else len(lines), f"{key}={value}")
    tmp = ENV_FILE.with_name(ENV_FILE.name + ".tmp")
    tmp.write_text("\n".join(lines))
    os.chmod(tmp, ENV_FILE.stat().st_mode & 0o777)
    os.replace(tmp, ENV_FILE)


def audit(user, msg):
    try:
        STATE.mkdir(exist_ok=True)
        with open(AUDIT, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {user} {msg}\n")
        os.chmod(AUDIT, 0o600)
    except OSError:
        pass


# ---------------------------------------------------------------- HTTP
_static = {}


def static_bytes(f, st, gz):
    """-> (body, gzipped) of a UI file, compressed once per version of the file."""
    key = (str(f), st.st_mtime_ns, st.st_size, gz)
    hit = _static.get(key)
    if hit is None:
        data = f.read_bytes()
        hit = (gzip.compress(data, 6), True) if gz and len(data) > 1024 else (data, False)
        if len(_static) > 64:
            _static.clear()
        _static[key] = hit
    return hit


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "VexorConsole"
    sys_version = ""
    protocol_version = "HTTP/1.1"   # keep-alive: no new TLS handshake for every poll
    timeout = 60   # per connection: a client that stalls (also during the TLS handshake) frees its thread

    def log_message(self, fmt, *a):  # quiet access log; the audit log records actions
        pass

    # -- helpers
    def gzip_ok(self, body):
        return len(body) > 1024 and "gzip" in self.headers.get("Accept-Encoding", "")

    def send_json(self, obj, code=200, extra=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Vary", "Accept-Encoding")
        if self.gzip_ok(body):
            body = gzip.compress(body, 5)
            self.send_header("Content-Encoding", "gzip")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.security_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
                         "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

    def body_json(self, limit=65536):
        n = int(self.headers.get("Content-Length") or 0)
        if n > limit:
            self.close_connection = True      # the unread body would be taken for the next request
            return None
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return None

    def session(self):
        c = self.headers.get("Cookie", "")
        m = re.search(r"vexor_console=([a-f0-9]{64})", c)
        if not m:
            return None
        s = SESSIONS.get(m.group(1))
        if not s or s["exp"] < time.time():
            SESSIONS.pop(m.group(1), None)
            return None
        s["exp"] = time.time() + SESSION_TTL
        return s

    def require(self, write=False):
        s = self.session()
        if not s:
            self.send_json({"error": "login required"}, 401)
            return None
        if write and not hmac.compare_digest(self.headers.get("X-Vexor-CSRF", ""), s["csrf"]):
            self.send_json({"error": "bad CSRF token - reload the page"}, 403)
            return None
        return s

    # -- static
    def static(self, path):
        if path in ("/", "/index.html"):
            f = UI_DIR / "index.html"
        elif path.startswith("/ui/"):
            f = (UI_DIR / path[4:]).resolve()
            if UI_DIR.resolve() not in f.parents:
                return self.send_error(404)
        elif path.startswith("/site/"):
            f = (SITE_ASSETS / path[6:]).resolve()
            if SITE_ASSETS.resolve() not in f.parents:
                return self.send_error(404)
        else:
            return self.send_error(404)
        if not f.is_file():
            return self.send_error(404)
        ctype = {".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml"}.get(f.suffix, "application/octet-stream")
        st = f.stat()
        etag = f'"{st.st_mtime_ns:x}-{st.st_size:x}"'
        # no-cache = the browser revalidates every time: a 304 costs no body, and an updated console shows at once
        head = {"Content-Type": ctype, "Cache-Control": "no-cache", "ETag": etag, "Vary": "Accept-Encoding",
                "Last-Modified": email.utils.formatdate(st.st_mtime, usegmt=True)}
        inm = self.headers.get("If-None-Match")
        ims = self.headers.get("If-Modified-Since")
        fresh = etag in [t.strip() for t in inm.split(",")] if inm else False
        if not inm and ims:
            try:
                fresh = int(st.st_mtime) <= email.utils.parsedate_to_datetime(ims).timestamp()
            except (TypeError, ValueError, OverflowError):
                fresh = False
        if fresh:
            self.send_response(304)
            for k, v in head.items():
                if k != "Content-Type":
                    self.send_header(k, v)
            self.security_headers()
            return self.end_headers()
        data = static_bytes(f, st, ctype.startswith(("text/", "image/svg")) and "gzip" in self.headers.get("Accept-Encoding", ""))
        self.send_response(200)
        for k, v in head.items():
            self.send_header(k, v)
        if data[1]:
            self.send_header("Content-Encoding", "gzip")
        self.security_headers()
        self.send_header("Content-Length", str(len(data[0])))
        self.end_headers()
        self.wfile.write(data[0])

    # -- routes
    def do_GET(self):
        if self.headers.get("Content-Length", "0") not in ("", "0"):
            self.close_connection = True      # a GET body is never read
        u = urllib.parse.urlsplit(self.path)
        p = u.path
        if not p.startswith("/api/"):
            return self.static(p)
        if p == "/api/session":
            s = self.session()
            return self.send_json({"user": s["user"], "csrf": s["csrf"], "mustChange": password_temp()} if s else {"user": None})
        s = self.require()
        if not s:
            return
        if password_temp():
            return self.must_change()
        q = urllib.parse.parse_qs(u.query)
        fresh = "fresh" in q        # the Refresh button: wait for new data instead of the cached value
        if p == "/api/state":
            return self.send_json(cached("state", TTL["state"], state, fresh=fresh))
        if p == "/api/containers":         # lite: without CPU/memory (the Overview), so no `docker stats` runs for it
            rows = cached("containers", TTL["containers"], containers, fresh=fresh)
            return self.send_json(rows if "lite" in q else with_stats(rows))
        if p == "/api/map":
            return self.send_json(cached("map", TTL["map"], build_map, swr=False))     # fast; rates need real samples
        if p == "/api/disk":
            return self.send_json(cached("disk", TTL["disk"], disk, fresh=fresh))
        if p == "/api/volumes":            # du of every volume: slow, so kept for 5 minutes unless asked
            return self.send_json(cached("volumes", TTL["volumes"], volumes, fresh=fresh))
        if p == "/api/ports":
            return self.send_json(ports())
        if p == "/api/settings":
            return self.send_json(settings())
        if p == "/api/pending":
            return self.send_json(pending())
        if p == "/api/proxy":
            return self.send_json(cached("proxy", TTL["proxy"], proxy_routes, fresh=fresh))
        if p == "/api/proxy/download":
            what = (q.get("what") or ["cert"])[0]
            host = (q.get("host") or [""])[0].strip().lower()
            data, name = proxy_cert_file(host, what)
            if data is None:
                return self.send_json({"error": name}, 404 if name in ("no such route", "no certificate yet") else 400)
            audit(s["user"], f"download {name}")
            self.send_response(200)
            self.send_header("Content-Type", "application/x-pem-file")
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("Cache-Control", "no-store")
            self.security_headers()
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            return self.wfile.write(data)
        if p == "/api/logins":           # list without secrets; passwords come one at a time from /reveal
            rows = logins().get("logins", [])
            return self.send_json([{k: v for k, v in r.items() if k != "password"} | {"hasPassword": bool(r.get("password"))} for r in rows])
        if p == "/api/detection":
            return self.send_json(cached("detection", TTL["detection"], detection, fresh=fresh))
        if p == "/api/detection/integrations":
            return self.send_json(cached("det-integrations", TTL["detection"], det_integrations_list, fresh=fresh))
        if p == "/api/detection/config":
            return self.send_json(cached("det-config", TTL["detection"], det_config_list, fresh=fresh))
        if p == "/api/detection/file":
            return self.det_file_get(q)
        if p == "/api/detection/template":
            kind, tid = (q.get("kind") or [""])[0], (q.get("id") or [""])[0]
            if kind not in DET_KINDS:
                return self.send_json({"error": "kind must be rules, decoders or lists"}, 400)
            t = next((t for t in (vexor_json(["wazuh", kind, "templates", "--json"], default={}) or {}).get("templates", []) if t.get("id") == tid), None)
            return self.send_json({"id": tid, "content": t["content"]} if t else {"error": "no such template"}, 200 if t else 404)
        if p == "/api/complete":           # Terminal suggestions on every keystroke: cached data only, never waits
            try:
                return self.send_json(complete((q.get("line") or [""])[0]))
            except Exception as e:  # noqa: BLE001 - a suggestion bug must not show as a failed request
                print(f"complete failed: {e!r}", file=sys.stderr, flush=True)
                return self.send_json({"start": 0, "token": "", "items": [], "usage": "", "level": None})
        if p == "/api/catalog":
            return self.send_json({"commands": CATALOG, "read": {k: sorted(v) for k, v in READ_SUBS.items()},
                                   "danger": {k: sorted(v) for k, v in DANGER_SUBS.items()}, "blocked": sorted(BLOCKED)})
        if p == "/api/jobs":
            with JOBS_LOCK:
                return self.send_json(sorted((j.summary() for j in JOBS.values()), key=lambda j: -j["started"]))
        m = re.fullmatch(r"/api/jobs/([a-f0-9]{12})/stream", p)
        if m:
            return self.stream(m.group(1), int((q.get("from") or ["0"])[0]))
        if p == "/api/audit":
            try:
                lines = AUDIT.read_text().splitlines()[-200:]
            except OSError:
                lines = []
            return self.send_json(lines[::-1])
        self.send_json({"error": "not found"}, 404)

    def must_change(self):
        self.send_json({"error": "choose a new console password first", "code": "password_change_required"}, 403)

    def stream(self, jid, start):
        job = JOBS.get(jid)
        if not job:
            return self.send_json({"error": "no such job"}, 404)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")    # no length: the stream ends with the connection
        self.close_connection = True
        self.security_headers()
        self.end_headers()
        i = max(0, start)
        try:
            while True:
                with job.cond:
                    while i >= len(job.lines) and job.ended is None:
                        job.cond.wait(timeout=15)
                        if i >= len(job.lines) and job.ended is None:
                            break
                    new = job.lines[i:]
                    done = job.ended is not None and i + len(new) >= len(job.lines)
                if new:
                    i += len(new)
                    self.wfile.write(("data: " + json.dumps({"lines": new}) + "\n\n").encode())
                elif not done:
                    self.wfile.write(b": keep-alive\n\n")
                if done:
                    self.wfile.write(("event: end\ndata: " + json.dumps({"code": job.code}) + "\n\n").encode())
                    self.wfile.flush()
                    return
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            if job.args and job.args[0] == "logs" and job.ended is None:
                job.stop()  # nobody is watching a followed log any more

    def do_POST(self):
        p = urllib.parse.urlsplit(self.path).path
        data = self.body_json(DET_BODY_MAX if p == "/api/detection/file" else 65536)   # read the body first: on a kept-alive connection it must not be left unread
        if p == "/api/login":
            return self.login(data)
        if p == "/api/logout":
            c = re.search(r"vexor_console=([a-f0-9]{64})", self.headers.get("Cookie", ""))
            if c:
                SESSIONS.pop(c.group(1), None)
            return self.send_json({"ok": True}, extra={"Set-Cookie": "vexor_console=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"})
        s = self.require(write=True)
        if not s:
            return
        if data is None:
            return self.send_json({"error": "bad JSON"}, 400)
        if p == "/api/password":
            return self.change_password(s, data)
        if password_temp():
            return self.must_change()
        if p == "/api/run":
            args = data.get("args")
            if isinstance(args, str):
                try:
                    args = shlex.split(args)
                except ValueError as e:
                    return self.send_json({"error": f"cannot parse: {e}"}, 400)
            if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
                return self.send_json({"error": "args must be a list of strings"}, 400)
            if args and args[0] == "vexor":
                args = args[1:]
            level, err = classify(args)
            if err:
                return self.send_json({"error": err}, 400)
            if level == "change" and not data.get("confirmed"):
                return self.send_json({"confirm": "change", "cmd": "vexor " + shlex.join(mask_args(args))}, 409)
            if level == "danger" and data.get("confirmWord") != args[0]:
                return self.send_json({"confirm": "danger", "word": args[0], "cmd": "vexor " + shlex.join(mask_args(args))}, 409)
            audit(s["user"], f"run: vexor {shlex.join(mask_args(args))}")
            if level != "read":
                invalidate()
            return self.send_json(start_job(args, s["user"], level).summary())
        m = re.fullmatch(r"/api/jobs/([a-f0-9]{12})/stop", p)
        if m:
            job = JOBS.get(m.group(1))
            if job:
                job.stop()
                audit(s["user"], f"stop job {job.id}")
            return self.send_json({"ok": bool(job)})
        if p == "/api/ports/check":
            ch = {k: str(v) for k, v in (data.get("changes") or {}).items() if k in PORT_KEYS}
            return self.send_json({"errors": validate_ports(ch)})
        if p == "/api/settings/apply":
            return self.apply_settings(s, data)
        if p == "/api/plan":
            changes = {str(k): str(v) for k, v in (data.get("changes") or {}).items()
                       if re.fullmatch(r"[A-Z][A-Z0-9_]*", str(k)) and not SECRET_RE.search(str(k))}
            return self.send_json(plan(changes))
        if p == "/api/detection/file":
            return self.det_file_post(s, data)
        if p == "/api/detection/logtest":
            return self.det_logtest(s, data)
        if p == "/api/detection/integration":
            return self.det_integration(s, data)
        if p == "/api/logins/reveal":
            lid = str(data.get("id", ""))
            row = next((r for r in logins().get("logins", []) if r["id"] == lid), None)
            if not row:
                return self.send_json({"error": "no such login"}, 404)
            audit(s["user"], f"revealed the password of '{row['name']}' ({row['user'] or row['key']})")
            return self.send_json({"id": lid, "password": row.get("password", "")})
        self.send_json({"error": "not found"}, 404)

    # -- detection page
    def det_file_get(self, q):
        kind, name, ver = ((q.get(k) or [""])[0] for k in ("kind", "name", "version"))
        if kind == "config":
            if name != "custom":
                return self.send_json({"error": "only the custom block can be read here"}, 400)
            code, out = run_rc([str(VEXOR), "--no-color", "wazuh", "config", "custom", "show"], timeout=30)
            return self.send_json({"name": "custom", "content": out, "editable": True} if code == 0 else {"error": "could not read the custom block"}, 200 if code == 0 else 500)
        if kind == "integrations":
            if name != "raw":
                return self.send_json({"error": "only the raw XML can be read here"}, 400)
            code, out = run_rc([str(VEXOR), "--no-color", "wazuh", "integrations", "raw", "show"], timeout=30)
            return self.send_json({"name": "raw", "content": out, "editable": True} if code == 0 else {"error": "could not read the integrations"}, 200 if code == 0 else 500)
        if kind not in DET_KINDS:
            return self.send_json({"error": "kind must be rules, decoders, lists or config"}, 400)
        if ver:
            fname = det_name(kind, name) or det_builtin(kind, name)
            f = DET_HIST / kind / fname / ver if fname and DET_VERSION.match(ver) else None
            if not f or not f.is_file():
                return self.send_json({"error": "no such version"}, 404)
            return self.send_json({"name": fname, "version": ver, "content": f.read_text(errors="replace"), "editable": False})
        fname = det_name(kind, name)
        if fname and (DET_DIR / kind / fname).is_file():
            f = DET_DIR / kind / fname
            if f.stat().st_size > 4 * DET_MAX:
                return self.send_json({"error": "file too large to edit here"}, 413)
            return self.send_json({"name": fname, "content": f.read_text(errors="replace"), "editable": True, "source": "custom"})
        if not DET_SHOW.match(name or "") or ".." in name:
            return self.send_json({"error": "invalid name"}, 400)
        bname = det_builtin(kind, name)       # built-in Wazuh file: editable, the edited copy (if any) is what vexor shows
        code, out = run_rc([str(VEXOR), "--no-color", "wazuh", kind, "show", bname or name], timeout=30)
        if code != 0:
            return self.send_json({"error": f"no such file: {kind}/{name}"}, 404)
        if bname:
            if len(out.encode()) > 4 * DET_MAX:
                return self.send_json({"error": "file too large to edit here"}, 413)
            return self.send_json({"name": bname, "content": out, "editable": True, "source": "wazuh",
                                   "modified": det_overridden(kind, bname)})
        return self.send_json({"name": name, "content": out, "editable": False})

    def det_file_post(self, s, data):
        kind, name, content = data.get("kind"), data.get("name"), data.get("content")
        if not isinstance(content, str):
            return self.send_json({"error": "content must be text"}, 400)
        if len(content.encode()) > DET_MAX:
            return self.send_json({"error": f"content larger than {DET_MAX // 1024} KB"}, 413)
        if "\x00" in content:
            return self.send_json({"error": "content may not contain NUL bytes"}, 400)
        if kind == "config":
            scope = data.get("scope") or "master"
            if name != "custom" or scope not in ("master", "all"):
                return self.send_json({"error": "config: name must be custom, scope master or all"}, 400)
            args, label = ["wazuh", "config", "custom", "put", "--from", "", "--scope", scope], "config/custom block"
        elif kind == "integrations":
            if name != "raw":
                return self.send_json({"error": "integrations: name must be raw"}, 400)
            args, label = ["wazuh", "integrations", "raw", "put", "--from", ""], "integrations (XML)"
        else:
            fname = det_name(kind, name) or det_builtin(kind, name)   # a built-in: vexor keeps an edited copy and excludes the shipped one
            if not fname:
                return self.send_json({"error": "kind must be rules, decoders or lists; name: 1-64 letters, digits, _ or -, or a built-in Wazuh file"}, 400)
            args, label = ["wazuh", kind, "put", fname, "--from", ""], f"{kind}/{fname}"
        i = args.index("--from") + 1
        if not data.get("confirmed"):
            shown = list(args)
            shown[i] = "<the editor content>"
            return self.send_json({"confirm": "change", "cmd": "vexor " + shlex.join(shown)}, 409)
        try:
            args[i] = det_tmp(content, "detection")
        except OSError as e:
            return self.send_json({"error": f"could not write a temp file: {e}"}, 500)
        audit(s["user"], f"detection: save {label} ({len(content.encode())} bytes)")
        invalidate()
        return self.send_json(start_job(args, s["user"], "change", cleanup=[args[i]]).summary())

    def det_logtest(self, s, data):
        line, fmt, loc = data.get("line"), data.get("format") or "syslog", data.get("location") or "console"
        if not isinstance(line, str) or not line.strip() or len(line) > 65536 or re.search(r"[\x00\r\n]", line):
            return self.send_json({"error": "one log line (no line breaks, up to 64 KB)"}, 400)
        if fmt not in LOG_FORMATS:
            return self.send_json({"error": "format must be one of: " + ", ".join(sorted(LOG_FORMATS))}, 400)
        if not isinstance(loc, str) or not ARG_RE.match(loc) or len(loc) > 256:
            return self.send_json({"error": "location: up to 256 printable characters"}, 400)
        code, out = run_rc([str(VEXOR), "--no-color", "wazuh", "logtest", line, "--format", fmt, "--location", loc, "--json"], timeout=30)
        try:
            res = json.loads(out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return self.send_json({"error": "logtest did not answer (is wazuh.master running?)" if code == 124 or not out else out[-500:]}, 502)
        return self.send_json(res, 200 if not res.get("error") else 502)

    def det_integration(self, s, data):
        act, name = data.get("action"), data.get("name")
        if act not in ("add", "edit") or not isinstance(name, str) or not re.fullmatch(r"slack|pagerduty|virustotal|shuffle|maltiverse|custom-[A-Za-z0-9_-]{1,40}", name):
            return self.send_json({"error": "action add|edit; name slack, pagerduty, virustotal, shuffle, maltiverse or custom-<id>"}, 400)
        args = ["wazuh", "integrations", act, name]
        for key, opt in (("hook_url", "--hook-url"), ("level", "--level"), ("group", "--group"), ("rule_id", "--rule-id"), ("format", "--format")):
            v = data.get(key)
            if v is None:
                continue
            v = str(v)
            if not ARG_RE.match(v):
                return self.send_json({"error": f"{key} may not contain control characters"}, 400)
            args += [opt, v]
        key = data.get("api_key")
        if key is not None and not isinstance(key, str):
            return self.send_json({"error": "api_key must be text"}, 400)
        if key and (len(key) > 4096 or re.search(r"[\x00-\x1f]", key)):
            return self.send_json({"error": "api_key: one line, up to 4096 characters"}, 400)
        shown = args + (["--api-key-file", "<hidden>"] if key else [])
        if not data.get("confirmed"):
            return self.send_json({"confirm": "change", "cmd": "vexor " + shlex.join(shown)}, 409)
        cleanup = []
        if key:                      # never in argv: a 0600 file the job deletes
            try:
                cleanup.append(det_tmp(key, "apikey"))
            except OSError as e:
                return self.send_json({"error": f"could not write a temp file: {e}"}, 500)
            args += ["--api-key-file", cleanup[0]]
        audit(s["user"], f"detection: integration {act} {name}" + (" (new API key)" if key else ""))
        invalidate()
        job = start_job(args, s["user"], "change", cleanup=cleanup)
        return self.send_json(dict(job.summary(), cmd="vexor " + shlex.join(shown)))

    def change_password(self, s, data):
        ip = self.client_address[0]
        now = time.time()
        fails = [t for t in PW_FAILS.get(ip, []) if now - t < 300]
        PW_FAILS[ip] = fails
        if len(fails) >= 5:
            audit(s["user"], "password change refused: too many wrong attempts")
            return self.send_json({"error": "too many wrong passwords - wait 5 minutes"}, 429)
        cur, new, again = (data.get(k) for k in ("current", "new", "repeat"))
        if not all(isinstance(x, str) for x in (cur, new, again)):
            return self.send_json({"error": "current, new and repeat are required"}, 400)
        old = console_creds()[1]
        if not old or not hmac.compare_digest(hashlib.sha256(cur.encode()).digest(), hashlib.sha256(old.encode()).digest()):
            fails.append(now)
            audit(s["user"], "password change failed: wrong current password")
            time.sleep(1)
            return self.send_json({"error": "the current password is wrong"}, 403)
        err = None
        if new != again:
            err = "the two new passwords differ"
        elif len(new) < PW_MIN:
            err = f"the new password needs at least {PW_MIN} characters"
        elif not PW_CHARS.fullmatch(new):
            err = "use letters, digits and . _ @ % + = : , / ! ^ * ( ) ~ - only (no spaces, quotes, # or $)"
        elif new == old:
            err = "the new password must differ from the current one"
        if err:
            audit(s["user"], f"password change refused: {err}")
            return self.send_json({"error": err}, 400)
        try:
            write_env_value("CONSOLE_PASSWORD", new)
            STATE.mkdir(exist_ok=True)
            salt = secrets.token_bytes(16)
            PW_FILE.write_text(f"{salt.hex()} {pw_digest(new, salt)}\n")
            os.chmod(PW_FILE, 0o600)
        except OSError as e:
            audit(s["user"], f"password change failed: {e}")
            return self.send_json({"error": f"could not write .env: {e}"}, 500)
        PW_FAILS.pop(ip, None)
        _pw_seen.clear()
        for tok in [t for t, v in SESSIONS.items() if v is not s]:
            SESSIONS.pop(tok, None)      # every other session must sign in again
        audit(s["user"], "console password changed")
        return self.send_json({"ok": True})

    def apply_settings(self, s, data):
        changes = {str(k): str(v) for k, v in (data.get("changes") or {}).items()}
        env = env_dict()
        bad = {}
        for k, v in changes.items():
            if k not in env:
                bad[k] = "unknown setting"
            elif SECRET_RE.search(k):
                bad[k] = "passwords and keys change through their own commands"
            elif not re.fullmatch(r"[^\x00-\x1f\x7f#\"'`$\\]{0,300}", v):
                bad[k] = "value has characters .env cannot hold (quotes, #, $, backslash)"
        bad.update(validate_ports({k: v for k, v in changes.items() if k in PORT_KEYS}))
        if bad:
            return self.send_json({"errors": bad}, 400)
        if not changes:
            return self.send_json({"error": "nothing changed"}, 400)
        if not data.get("confirmed"):
            return self.send_json({"confirm": "change", "cmd": "vexor config set … && vexor config apply"}, 409)
        script = [["config", "set", k, v] for k, v in changes.items()]
        audit(s["user"], "settings: " + ", ".join(f"{k}={v}" for k, v in changes.items()))
        job = Job(["config", "apply"], s["user"], "change")
        with JOBS_LOCK:
            JOBS[job.id] = job

        def run_all():
            for a in script:
                r = subprocess.run([str(VEXOR), "--no-color", "-y", *a], cwd=str(ROOT), capture_output=True, text=True,
                                   env=dict(os.environ, VEXOR_NO_SUDO="1"), errors="replace")
                with job.cond:
                    job.lines.extend(("$ vexor " + shlex.join(a) + "\n" + r.stdout + r.stderr).rstrip().splitlines())
                    job.cond.notify_all()
                if r.returncode != 0:
                    with job.cond:
                        job.code, job.ended = r.returncode, time.time()
                        job.cond.notify_all()
                    invalidate()
                    return
            with job.cond:
                job.lines.append("$ vexor config apply")
            job.run()
        invalidate()
        threading.Thread(target=run_all, daemon=True).start()
        return self.send_json(job.summary())

    def login(self, data):
        ip = self.client_address[0]
        now = time.time()
        fails = [t for t in FAILS.get(ip, []) if now - t < 300]
        FAILS[ip] = fails
        if len(fails) >= 5:
            return self.send_json({"error": "too many failed logins - wait 5 minutes"}, 429)
        data = data or {}
        user, pw = console_creds()
        ok = bool(pw) and pw != "CHANGE_ME" and hmac.compare_digest(str(data.get("user", "")), user) \
            and hmac.compare_digest(hashlib.sha256(str(data.get("password", "")).encode()).digest(), hashlib.sha256(pw.encode()).digest())
        if not ok:
            fails.append(now)
            audit(f"({ip})", "login failed")
            time.sleep(1)
            return self.send_json({"error": "wrong user or password"}, 401)
        for tok in [t for t, v in SESSIONS.items() if v["exp"] < now]:
            SESSIONS.pop(tok, None)      # forget expired sessions
        for k in [k for k, v in FAILS.items() if not v]:
            FAILS.pop(k, None)
        token = secrets.token_hex(32)
        SESSIONS[token] = {"user": user, "csrf": secrets.token_hex(16), "exp": now + SESSION_TTL, "ip": ip}
        audit(user, f"login from {ip}")
        return self.send_json({"user": user, "csrf": SESSIONS[token]["csrf"]},
                              extra={"Set-Cookie": f"vexor_console={token}; Path=/; Max-Age={SESSION_TTL}; Secure; HttpOnly; SameSite=Strict"})


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler):
        self.address_family = socket.AF_INET6 if ":" in addr[0] else socket.AF_INET
        super().__init__(addr, handler)


# ---------------------------------------------------------------- reload after an update
# A `git pull` changes the code but nothing restarts the service, so the new page would talk to the old
# server. Watch this file and re-exec when it changed (and compiles), keeping the signed-in sessions.
SELF = Path(__file__).resolve()
SESSIONS_FILE = STATE / "console-sessions.json"


def code_stamp():
    try:
        st = SELF.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def load_sessions():
    try:
        data = json.loads(SESSIONS_FILE.read_text())
        SESSIONS_FILE.unlink()
    except (OSError, ValueError):
        return
    now = time.time()
    for tok, s in data.items() if isinstance(data, dict) else []:
        if re.fullmatch(r"[a-f0-9]{64}", tok) and isinstance(s, dict) and s.get("exp", 0) > now:
            SESSIONS[tok] = s


def reload_watch(httpd):
    start = code_stamp()
    while True:
        time.sleep(3)
        now = code_stamp()
        if not now or now == start:
            continue
        time.sleep(2)                                   # let the writer (git) finish
        if code_stamp() != now:
            continue
        try:
            compile(SELF.read_text(), str(SELF), "exec")    # a broken file keeps the running server
        except (OSError, SyntaxError, ValueError) as e:
            print(f"console: new server.py does not compile, keeping the running one: {e}", flush=True)
            start = now
            continue
        with JOBS_LOCK:
            busy = any(j.ended is None for j in JOBS.values())
        if busy:                                        # finish running commands first
            continue
        try:
            STATE.mkdir(exist_ok=True)
            fd = os.open(SESSIONS_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(SESSIONS, f)
        except OSError:
            pass
        audit("(console)", "server.py changed - reloading")
        print("console: server.py changed - reloading", flush=True)
        httpd.socket.close()
        os.execv(sys.executable, [sys.executable, str(SELF), *sys.argv[1:]])


def main():
    load_sessions()
    env = env_dict()
    bind = env.get("CONSOLE_BIND") or env.get("BIND_IP") or "0.0.0.0"   # empty CONSOLE_BIND follows BIND_IP
    port = int(env.get("CONSOLE_PORT", "50443") or 50443)
    cert = env.get("PROXY_CERT") or "./config/wazuh_indexer_ssl_certs/wazuh.dashboard.pem"
    key = env.get("PROXY_KEY") or "./config/wazuh_indexer_ssl_certs/wazuh.dashboard-key.pem"
    cert, key = (ROOT / cert).resolve(), (ROOT / key).resolve()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cert), str(key))
    httpd = Server((bind, port), Handler)
    # handshake in the request thread, not in accept(): one client that connects and sends nothing must not block the console
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
    print(f"vexor console on https://{bind}:{port}  (cert {cert})", flush=True)
    threading.Thread(target=reload_watch, args=(httpd,), daemon=True).start()
    threading.Thread(target=warm_start, daemon=True).start()
    threading.Thread(target=warmer, daemon=True).start()
    httpd.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
