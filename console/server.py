#!/usr/bin/env python3
"""Vexor Console - a web UI for the vexor CLI.

Runs on the Vexor host as root (systemd unit vexor-console.service), serves HTTPS on CONSOLE_PORT with the
dashboard certificate, and lets an authenticated admin see and change the stack. Every change goes through
`vexor` itself (an allowlist of commands, run without a shell), so the console and the CLI behave identically.
Standard library only.
"""
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
SECRET_RE = re.compile(r"(PASSWORD|SECRET|TOKEN|ENCRYPTION_KEY|APIKEY)$")


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
    "notify": "change",
}
READ_SUBS = {
    "tools": {"status", "ls", ""}, "soc": {"status", ""}, "elk": {"status", "indices", "search", "explain", ""},
    "n8n": {"status", ""}, "suricata": {"status", "alerts", ""}, "zeek": {"status", "show", "notices", "top", ""},
    "agents": {"list", "summary", "outdated", "enroll-cmd", ""}, "cert": {"status", ""}, "backup": {"list", "ls"},
    "retention": {"show", ""}, "volumes": {"ls", "list", ""}, "reminders": {"list", ""}, "config": {"show", "get", "validate"},
    "daemon": {"status", "logs", ""}, "console": {"status", "url", ""}, "update": {"check", ""},
    "indexers": {"status", ""}, "node-type": {"status", ""}, "notify": {"status", ""},
}
DANGER_SUBS = {
    "volumes": {"rm", "prune", "restore"}, "backup": {"restore-snapshot", "restore-manager", "restore-config"},
    "cert": {"internal-regen"}, "agents": {"remove"}, "soc": {"wazuh", "elk", "both"},
}
BLOCKED = {"shell", "exec", "install", "reset purge", "config edit", "wazuh logtest", "completion", "motd"}
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
    if cmd in ("indexer", "api") and sub.upper() != "GET":
        return None, f"only GET requests through '{cmd}' in the console"
    if cmd == "logs" and ("-f" in args or "--follow" in args):
        return "read", None  # streamed until the browser closes it
    if cmd in DANGER_SUBS and sub in DANGER_SUBS[cmd]:
        return "danger", None
    if cmd in READ_SUBS and sub in READ_SUBS[cmd]:
        return "read", None
    if cmd == "doctor" and "--fix" not in args:
        return "read", None
    return CATALOG[cmd], None


# ---------------------------------------------------------------- jobs (one vexor process each)
class Job:
    def __init__(self, args, user):
        self.id = secrets.token_hex(6)
        self.args = args
        self.user = user
        self.started = time.time()
        self.ended = None
        self.code = None
        self.lines = []
        self.cond = threading.Condition()
        self.proc = None

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
        audit(self.user, f"job {self.id} exit {self.code}: vexor {shlex.join(self.args)}")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()

    def summary(self):
        return {"id": self.id, "cmd": "vexor " + shlex.join(self.args), "started": self.started, "ended": self.ended,
                "code": self.code, "lines": len(self.lines), "user": self.user}


JOBS = {}
JOBS_LOCK = threading.Lock()


def start_job(args, user):
    job = Job(args, user)
    with JOBS_LOCK:
        JOBS[job.id] = job
        if len(JOBS) > MAX_JOBS:
            for old in sorted(JOBS.values(), key=lambda j: j.started)[: len(JOBS) - MAX_JOBS]:
                if old.ended:
                    JOBS.pop(old.id, None)
    threading.Thread(target=job.run, daemon=True).start()
    return job


def run_quick(args, timeout=60):
    """Run a read-only vexor/docker command and return stdout (used by the JSON endpoints)."""
    try:
        r = subprocess.run(args, cwd=str(ROOT), capture_output=True, text=True, timeout=timeout,
                           env=dict(os.environ, VEXOR_NO_SUDO="1", TERM="dumb"), errors="replace")
        return r.stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""


_cache = {}


def cached(key, ttl, fn):
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    val = fn()
    _cache[key] = (time.time(), val)
    return val


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
    stats = {}
    sout = run_quick(["docker", "stats", "--no-stream", "--format", "{{json .}}"], timeout=30)
    for line in sout.splitlines():
        try:
            s = json.loads(line)
            stats[s.get("Name")] = {"cpu": s.get("CPUPerc"), "mem": s.get("MemUsage"), "memPct": s.get("MemPerc")}
        except ValueError:
            pass
    for r in rows:
        r.update(stats.get(r["name"], {}))
    return sorted(rows, key=lambda r: r["service"] or "")


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


# ---------------------------------------------------------------- auth
SESSIONS = {}
FAILS = {}


def console_creds():
    env = env_dict()
    return env.get("CONSOLE_USER", "admin"), env.get("CONSOLE_PASSWORD", "")


def audit(user, msg):
    try:
        STATE.mkdir(exist_ok=True)
        with open(AUDIT, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {user} {msg}\n")
        os.chmod(AUDIT, 0o600)
    except OSError:
        pass


# ---------------------------------------------------------------- HTTP
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "VexorConsole"
    sys_version = ""

    def log_message(self, fmt, *a):  # quiet access log; the audit log records actions
        pass

    # -- helpers
    def send_json(self, obj, code=200, extra=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
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

    def body_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 65536:
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
        data = f.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-cache")
        self.security_headers()
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # -- routes
    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        p = u.path
        if not p.startswith("/api/"):
            return self.static(p)
        if p == "/api/session":
            s = self.session()
            return self.send_json({"user": s["user"], "csrf": s["csrf"]} if s else {"user": None})
        s = self.require()
        if not s:
            return
        q = urllib.parse.parse_qs(u.query)
        if p == "/api/state":
            return self.send_json(cached("state", 10, state))
        if p == "/api/containers":
            return self.send_json(cached("containers", 5, containers))
        if p == "/api/volumes":
            return self.send_json(cached("volumes", 60, volumes) if "fresh" not in q else volumes())
        if p == "/api/ports":
            return self.send_json(ports())
        if p == "/api/settings":
            return self.send_json(settings())
        if p == "/api/pending":
            return self.send_json(pending())
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

    def stream(self, jid, start):
        job = JOBS.get(jid)
        if not job:
            return self.send_json({"error": "no such job"}, 404)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
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
        if p == "/api/login":
            return self.login()
        if p == "/api/logout":
            c = re.search(r"vexor_console=([a-f0-9]{64})", self.headers.get("Cookie", ""))
            if c:
                SESSIONS.pop(c.group(1), None)
            return self.send_json({"ok": True}, extra={"Set-Cookie": "vexor_console=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"})
        s = self.require(write=True)
        if not s:
            return
        data = self.body_json()
        if data is None:
            return self.send_json({"error": "bad JSON"}, 400)
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
                return self.send_json({"confirm": "change", "cmd": "vexor " + shlex.join(args)}, 409)
            if level == "danger" and data.get("confirmWord") != args[0]:
                return self.send_json({"confirm": "danger", "word": args[0], "cmd": "vexor " + shlex.join(args)}, 409)
            audit(s["user"], f"run: vexor {shlex.join(args)}")
            _cache.clear()
            return self.send_json(start_job(args, s["user"]).summary())
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
        self.send_json({"error": "not found"}, 404)

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
        job = Job(["config", "apply"], s["user"])
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
                    return
            with job.cond:
                job.lines.append("$ vexor config apply")
            job.run()
        _cache.clear()
        threading.Thread(target=run_all, daemon=True).start()
        return self.send_json(job.summary())

    def login(self):
        ip = self.client_address[0]
        now = time.time()
        fails = [t for t in FAILS.get(ip, []) if now - t < 300]
        FAILS[ip] = fails
        if len(fails) >= 5:
            return self.send_json({"error": "too many failed logins - wait 5 minutes"}, 429)
        data = self.body_json() or {}
        user, pw = console_creds()
        ok = bool(pw) and pw != "CHANGE_ME" and hmac.compare_digest(str(data.get("user", "")), user) \
            and hmac.compare_digest(hashlib.sha256(str(data.get("password", "")).encode()).digest(), hashlib.sha256(pw.encode()).digest())
        if not ok:
            fails.append(now)
            audit(f"({ip})", "login failed")
            time.sleep(1)
            return self.send_json({"error": "wrong user or password"}, 401)
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


def main():
    env = env_dict()
    bind = env.get("CONSOLE_BIND", "0.0.0.0") or "0.0.0.0"
    port = int(env.get("CONSOLE_PORT", "50443") or 50443)
    cert = env.get("PROXY_CERT") or "./config/wazuh_indexer_ssl_certs/wazuh.dashboard.pem"
    key = env.get("PROXY_KEY") or "./config/wazuh_indexer_ssl_certs/wazuh.dashboard-key.pem"
    cert, key = (ROOT / cert).resolve(), (ROOT / key).resolve()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cert), str(key))
    httpd = Server((bind, port), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"vexor console on https://{bind}:{port}  (cert {cert})", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
