#!/usr/bin/env python3
"""Tests of the Terminal command suggestions (GET /api/complete) in server.py.

Run on the Vexor host:  python3 console/test_complete.py   (as root, the live-data and HTTP tests run too)
Standard library only; the server's functions are imported directly. The dynamic sources are seeded with fixtures, so
the results do not depend on what runs on the host.
"""
import http.client
import json
import os
import re
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import server  # noqa: E402

FIXTURES = {
    "containers": [{"service": "nginx", "name": "vexor-nginx-1", "state": "running", "health": ""},
                   {"service": "wazuh.master", "name": "vexor-wazuh.master-1", "state": "running", "health": "healthy"},
                   {"service": "n8n", "name": "vexor-n8n-1", "state": "running", "health": ""}],
    "detection": {"rules": {"files": [{"name": "local_rules.xml", "source": "custom", "editable": True, "rules": 1},
                                      {"name": "0095-sshd_rules.xml", "source": "wazuh", "editable": True, "rules": 40}]},
                  "decoders": {"files": []},
                  "lists": {"files": [{"name": "malicious-ioc/malicious-ip", "source": "wazuh", "editable": True, "rules": 3},
                                      {"name": "blocked-ips", "source": "custom", "editable": True, "rules": 2}]}},
    "det-integrations": {"integrations": [{"name": "custom-n8n", "managed": False}, {"name": "slack", "managed": True}]},
    "det-config": {"settings": [{"key": "logall", "choices": ["yes", "no"], "help": "Store every event", "type": "bool"},
                                {"key": "log_alert_level", "choices": None, "help": "Lowest level", "type": "int"}]},
    "proxy": {"routes": [{"host": "wazuh.srv", "target": "wazuh.dashboard:5601", "tls": "local"}], "suggestions": ["n8n:5678"]},
    "complete-agents": [{"id": "000", "name": "wazuh.master", "status": "active"}, {"id": "001", "name": "srv-linux", "status": "active"}],
    "complete-volumes": ["vexor_n8n-data"],
}


def seed():
    with server._cache_lock:
        for k, v in FIXTURES.items():
            server._cache[k] = (time.time() + 3600, v, server._gen)     # "fresh" for an hour: no background refresh


def texts(res):
    return [i["text"] for i in res["items"]]


class Complete(unittest.TestCase):
    def setUp(self):
        seed()

    def check_schema(self, res, line):
        self.assertEqual(set(res) >= {"start", "token", "items", "usage"}, True)
        self.assertLessEqual(len(res["items"]), server.COMPLETE_MAX)
        self.assertTrue(0 <= res["start"] <= len(line))
        for i in res["items"]:
            self.assertEqual(set(i) >= {"text", "kind", "desc", "level", "insertable"}, True, i)
            self.assertIn(i["kind"], ("command", "sub", "flag", "value", "hint"))
            self.assertIn(i["level"], ("read", "change", "danger", None))
            self.assertLessEqual(len(i["desc"]), 90)
            self.assertFalse(i["text"].endswith(" "))
            if i["kind"] == "hint":
                self.assertFalse(i["insertable"])
                self.assertIn("example", i)

    def run_line(self, line):
        t = time.perf_counter()
        res = server.complete(line)
        self.assertLess(time.perf_counter() - t, 0.05, f"{line!r} took too long")
        self.check_schema(res, line)
        return res

    def test_empty_line(self):
        res = self.run_line("")
        self.assertEqual((res["start"], res["token"]), (0, ""))
        self.assertEqual(texts(res)[:4], ["status", "doctor", "logs", "wazuh"])
        self.assertTrue(all(i["kind"] == "command" and i["desc"] for i in res["items"]))
        self.assertEqual(len(res["items"]), 12)

    def test_vexor_prefix_stripped(self):
        res = self.run_line("vexor do")
        self.assertEqual((res["start"], res["token"]), (6, "do"))
        self.assertEqual(texts(res)[0], "doctor")

    def test_prefix_do(self):
        res = self.run_line("do")
        self.assertEqual(texts(res)[0], "doctor")
        self.assertEqual(res["items"][0]["level"], "read")

    def test_fuzzy_after_prefix(self):
        res = self.run_line("stat")
        self.assertEqual(texts(res)[0], "status")
        self.assertIn("doctor", texts(self.run_line("doctr")))         # subsequence / typo

    def test_wazuh_subs(self):
        res = self.run_line("wazuh ")
        self.assertEqual(res["start"], 6)
        t = texts(res)
        for s in ("alerts", "rules", "integrations", "config", "logtest"):
            self.assertIn(s, t)
        self.assertEqual(res["level"], "read")
        self.assertIn("vexor wazuh", res["usage"])

    def test_integration_flags_custom_n8n(self):
        line = "wazuh integrations add custom-n8n --"
        res = self.run_line(line)
        self.assertEqual((res["start"], res["token"]), (len(line) - 2, "--"))
        t = texts(res)
        self.assertEqual(t[:3], ["--hook-url", "--level", "--group"])
        self.assertNotIn("--api-key", t)                               # custom-n8n: the token is generated
        self.assertTrue(all(i["kind"] == "flag" and i["level"] == "change" for i in res["items"]))
        self.assertIn("--api-key", texts(self.run_line("wazuh integrations add slack --")))

    def test_hook_url_hint(self):
        res = self.run_line("wazuh integrations add slack --hook-url ")
        self.assertEqual(len(res["items"]), 1)
        h = res["items"][0]
        self.assertEqual((h["kind"], h["text"], h["insertable"]), ("hint", "<hook-url>", False))
        self.assertTrue(h["example"].startswith("https://hooks.slack.com/"))

    def test_api_key_hint_never_has_a_value(self):
        res = self.run_line("wazuh integrations add virustotal --api-key ")
        h = res["items"][0]
        self.assertEqual(h["kind"], "hint")
        self.assertEqual(h["example"], "")
        self.assertIn("never stored", h["desc"])
        self.assertIn("--api-key", server.SECRET_OPTS)

    def test_logs_targets(self):
        res = self.run_line("logs ")
        t = texts(res)
        self.assertIn("master", t)
        self.assertIn("errors", t)
        self.assertIn("-f", [i["text"] for i in server.complete("logs -")["items"]])

    def test_logs_service_dynamic(self):
        res = self.run_line("logs ng")
        self.assertEqual(texts(res)[0], "nginx")
        self.assertEqual(res["items"][0]["kind"], "value")

    def test_since_values(self):
        res = self.run_line("logs nginx --since ")
        self.assertEqual(texts(res)[:4], ["15m", "1h", "6h", "24h"])
        self.assertEqual(res["items"][-1]["kind"], "hint")

    def test_config_set_keys(self):
        res = self.run_line("config set N8N")
        t = texts(res)
        self.assertTrue(t and all(x.startswith("N8N") for x in t[:3]), t)
        self.assertTrue(all(i["kind"] == "value" for i in res["items"][:-1]))
        self.assertEqual(res["items"][-1]["kind"], "hint")          # <KEY>: a setting .env.example does not list

    @unittest.skipUnless(os.access(server.ENV_FILE, os.R_OK), ".env not readable")
    def test_config_values_never_from_env(self):
        env = server.env_dict()
        secrets_ = {v for k, v in env.items() if server.SECRET_RE.search(k) and len(v) >= 6}
        for line in ("config set ", "config get ", "config set CONSOLE_PASSWORD ", "config set N8N_HOOK_TOKEN ", "config set RETENTION_DAYS "):
            blob = json.dumps(server.complete(line))
            for s in secrets_:
                self.assertNotIn(s, blob, line)
        h = server.complete("config set CONSOLE_PASSWORD ")["items"][0]
        self.assertEqual((h["kind"], h["example"]), ("hint", ""))

    def test_n8n_connect_hint(self):
        res = self.run_line("n8n connect ")
        hints = [i for i in res["items"] if i["kind"] == "hint"]
        self.assertEqual(hints[0]["text"], "<path|url>")
        self.assertEqual(hints[0]["example"], "vexor-alerts")
        self.assertIn("--level", texts(res))

    def test_unterminated_quote(self):
        line = 'wazuh logtest "Oct 23 sshd'
        res = self.run_line(line)
        self.assertEqual(res["start"], line.index('"'))
        self.assertEqual(res["token"], "Oct 23 sshd")
        self.assertEqual(res["items"][-1]["kind"], "hint")
        res = self.run_line("logs 'ngi")
        self.assertEqual((res["start"], res["token"]), (5, "ngi"))
        self.assertEqual(texts(res)[0], "nginx")

    def test_flag_not_repeated(self):
        t = texts(self.run_line("wazuh integrations add slack --level 7 --"))
        self.assertNotIn("--level", t)
        self.assertIn("--group", t)
        self.assertNotIn("-f", texts(self.run_line("logs nginx -f -")))

    def test_blocked_absent(self):
        top = [i["text"] for i in server.complete("")["items"]] + texts(self.run_line("s")) + texts(self.run_line("e"))
        for b in ("shell", "exec", "install", "completion", "motd"):
            self.assertNotIn(b, top)
        self.assertNotIn("edit", texts(self.run_line("config ")))
        self.assertNotIn("purge", texts(self.run_line("reset ")))
        self.assertNotIn("PUT", texts(self.run_line("api ")))
        self.assertNotIn("--images", texts(self.run_line("uninstall --")))
        res = self.run_line("shell ")
        self.assertEqual((res["items"], res["level"]), ([], "blocked"))
        res = self.run_line("config edit ")
        self.assertEqual(res["level"], "blocked")

    def test_levels(self):
        lv = {i["text"]: i["level"] for i in self.run_line("wazuh rules ")["items"]}
        self.assertEqual((lv["ls"], lv["put"], lv["rm"]), ("read", "change", "danger"))
        self.assertEqual({i["text"]: i["level"] for i in self.run_line("doctor --")["items"]}["--fix"], "change")
        self.assertEqual(self.run_line("wazuh logtest ")["items"][0]["level"], "read")

    def test_detection_files(self):
        t = texts(self.run_line("wazuh rules show "))
        self.assertEqual(t[0], "local_rules.xml")
        self.assertIn("0095-sshd_rules.xml", t)
        self.assertEqual(texts(self.run_line("wazuh lists rm ")), ["blocked-ips"])
        self.assertIn("malicious-ioc/malicious-ip", texts(self.run_line("wazuh lists show mal")))
        h = self.run_line("wazuh lists add blocked-ips ")["items"][-1]
        self.assertEqual(h["example"], "203.0.113.9:blocked")

    def test_dynamic_sources(self):
        self.assertEqual(texts(self.run_line("wazuh integrations test "))[:2], ["custom-n8n", "slack"])
        self.assertEqual(texts(self.run_line("wazuh config set logall "))[:2], ["yes", "no"])
        self.assertNotIn("logall", texts(self.run_line("wazuh config set logall yes ")))
        self.assertIn("001", texts(self.run_line("agents remove ")))
        self.assertNotIn("000", texts(self.run_line("agents remove ")))
        self.assertIn("wazuh.srv", texts(self.run_line("proxy rm ")))
        self.assertIn("vexor_n8n-data", texts(self.run_line("volumes rm ")))
        self.assertIn("srv-linux", texts(self.run_line("retention purge --agent ")))

    def test_max_items(self):
        for line in ("", "s", "e", "wazuh ", "wazuh rules show ", "logs ", "config set ", "proxy --", "a"):
            self.assertLessEqual(len(server.complete(line)["items"]), 12, line)

    def test_failing_source_is_empty(self):
        with server._cache_lock:
            server._cache["detection"] = (time.time() + 3600, None, server._gen)
        self.assertEqual(texts(self.run_line("wazuh rules rm ")), [])

    def test_grammar_covers_catalog(self):
        self.assertEqual(set(server.CATALOG) - set(server.GRAMMAR), set())
        self.assertEqual(set(server.GRAMMAR) - set(server.CATALOG), set())
        for k in server.VALUES:
            self.assertTrue(server.VALUES[k], k)

    def test_grammar_value_types_exist(self):
        def nodes(n, path):
            yield path, n
            for s, c in n["subs"].items():
                yield from nodes(c, path + [s])
        for path, n in nodes(server.GRAMMAR_ROOT, []):
            for a in n["args"]:
                self.assertIn(a, server.VALUES, path)
            for f, spec in n["flags"].items():
                self.assertTrue(f.startswith("-"), path)
                self.assertTrue(spec[0] is None or spec[0] in server.VALUES, (path, f))

    def test_grammar_matches_bash_completion(self):
        src = "".join(p.read_text(errors="replace")             # the entry script + its lib/ modules
                      for p in [server.ROOT / "vexor", *sorted((server.ROOT / "lib").glob("*.sh"))])
        body = src[src.index("completion_script() {"):]
        top = set(re.search(r'words="([^"]+)"', body).group(1).split())
        aliases = {"wait"}                                 # vexor accepts it (= wait-ready); the completion lists wait-ready
        self.assertEqual({c for c in server.GRAMMAR if c not in top} - aliases, set())
        per = dict(re.findall(r"^      ([a-z|-]+)\)\s+words=\"([^\"]+)\"", body, re.M))
        for cmds, words in per.items():                    # every sub word of the bash completion is known to the grammar
            for c in cmds.split("|"):
                if c not in server.GRAMMAR:
                    continue
                g = server.GRAMMAR[c]
                known = set(g["subs"]) | set(g["aliases"]) | set(g["flags"])
                for n in g["subs"].values():
                    known |= set(n["flags"]) | set(n["subs"])
                    for a in n["args"]:
                        known |= {t for t, _ in (server.VALUES[a].get("values") or [])}
                for a in g["args"]:
                    known |= {t for t, _ in (server.VALUES[a].get("values") or [])}
                missing = {w for w in words.split() if not w.startswith("$")} - known
                self.assertEqual(missing - BASH_EXTRA.get(c, set()), set(), c)


# words the bash completion offers that the grammar has elsewhere (one level deeper, or service names from compose)
BASH_EXTRA = {
    "logs": {"master", "worker", "worker2", "worker3", "indexer1", "indexer2", "indexer3", "dashboard", "nginx", "managers", "indexers",
             "ossec", "api", "cluster", "alerts", "archives", "errors", "size"},
    "start": set(), "wait-ready": {"elasticsearch", "kibana", "logstash", "n8n", "grafana", "portainer"},
    "wait": {"elasticsearch", "kibana", "logstash", "n8n", "grafana", "portainer"},
    "wazuh": {"ls", "show", "put", "rm", "reset", "history", "restore", "templates", "add", "del", "edit", "test", "set", "custom",
              "--from", "--hook-url", "--api-key", "--api-key-file", "--level", "--group", "--rule-id", "--scope", "--format",
              "--location"},
    "n8n": {"import", "file"},
    "zeek": {"hosts", "ports", "dns", "conn", "http", "ssl", "ssh", "notice", "weird"},
    "tools": {"n8n", "grafana", "portainer", "suricata", "zeek"},
    "proxy": {"local", "letsencrypt", "off", "ca", "cert"},
    "agents": {"linux", "rpm", "windows", "macos"},
    "volumes": {"all"},
    "indexer": {"PUT", "POST", "DELETE"}, "api": {"PUT", "POST", "DELETE"},     # refused by the console (GET only)
    "console": set(), "login": set(),
}


@unittest.skipUnless(os.geteuid() == 0, "needs root (vexor, docker, .env)")
class Live(unittest.TestCase):
    """Against the real stack: fill the caches once (seconds), then the answers are instant."""

    def test_live_services_and_files(self):
        server.cached("containers", server.TTL["containers"], server.containers, fresh=True)
        server.cached("detection", server.TTL["detection"], server.detection, fresh=True)
        t0 = time.perf_counter()
        res = server.complete("logs ng")
        self.assertLess(time.perf_counter() - t0, 0.05)
        self.assertIn("nginx", texts(res))
        self.assertTrue(len(texts(server.complete("wazuh rules show "))) > 3)
        keys = texts(server.complete("config set RETENTION"))
        self.assertIn("RETENTION_DAYS", keys)


@unittest.skipUnless(os.geteuid() == 0, "needs root (.env)")
class Http(unittest.TestCase):
    """The handler itself on a plain-HTTP socket: login required, then JSON."""

    @classmethod
    def setUpClass(cls):
        server.password_temp = lambda: False
        cls.httpd = server.Server(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.port = cls.httpd.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def get(self, path, cookie=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("GET", path, headers={"Cookie": cookie} if cookie else {})
        try:
            r = c.getresponse()
            return r.status, json.loads(r.read() or b"{}")
        finally:
            c.close()

    def test_auth_required(self):
        code, body = self.get("/api/complete?line=do")
        self.assertEqual(code, 401)
        self.assertEqual(body.get("error"), "login required")

    def test_with_session(self):
        seed()
        tok = "a" * 64
        server.SESSIONS[tok] = {"user": "test", "csrf": "x", "exp": time.time() + 60, "ip": "127.0.0.1"}
        try:
            code, body = self.get("/api/complete?line=wazuh%20integrations%20add%20slack%20--hook-url%20", f"vexor_console={tok}")
        finally:
            server.SESSIONS.pop(tok, None)
        self.assertEqual(code, 200)
        self.assertEqual(body["items"][0]["text"], "<hook-url>")


if __name__ == "__main__":
    unittest.main(verbosity=2)
