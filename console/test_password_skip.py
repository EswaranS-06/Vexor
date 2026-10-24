#!/usr/bin/env python3
"""Tests of "Skip for now" on the forced console-password change (POST /api/password-skip) in server.py.

Run:  python3 console/test_password_skip.py     (any user: .env, .state and the audit log are throwaway temp files)
Standard library only; the real Handler is served on plain HTTP with throwaway sessions.
"""
import http.client
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import server  # noqa: E402

GENERATED = "generated-console-pw-0123456789"
CHOSEN = "my-own-password-9876"
SKIP_AUDIT = "skipped the default-password change (this session)"


class PasswordSkip(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.saved = {k: getattr(server, k) for k in ("ENV_FILE", "STATE", "AUDIT", "PW_FILE", "SESSIONS_FILE")}
        server.ENV_FILE = root / ".env"
        server.STATE = root / ".state"
        server.AUDIT = server.STATE / "console-audit.log"
        server.PW_FILE = server.STATE / "console-password-set"
        server.SESSIONS_FILE = server.STATE / "console-sessions.json"
        cls.httpd = server.Server(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.port = cls.httpd.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        for k, v in cls.saved.items():
            setattr(server, k, v)
        server._pw_seen.clear()
        server.SESSIONS.clear()
        cls.tmp.cleanup()

    def setUp(self):
        server.SESSIONS.clear()
        server.PW_FAILS.clear()
        server._pw_seen.clear()
        server.STATE.mkdir(exist_ok=True)
        server.ENV_FILE.write_text(f"CONSOLE_USER=admin\nCONSOLE_PASSWORD={GENERATED}\n")
        for f in (server.PW_FILE, server.AUDIT, server.SESSIONS_FILE):
            f.unlink(missing_ok=True)

    def session(self, name):
        tok = (name * 64)[:64]
        server.SESSIONS[tok] = {"user": "admin", "csrf": "csrf-" + name, "exp": time.time() + 60, "ip": "127.0.0.1"}
        return tok

    def call(self, method, path, tok=None, csrf=None, body=None):
        h = {"Content-Type": "application/json"}
        if tok:
            h["Cookie"] = f"vexor_console={tok}"
        if csrf:
            h["X-Vexor-CSRF"] = csrf
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            payload = json.dumps(body if body is not None else {}) if method == "POST" else None
            c.request(method, path, body=payload, headers=h)
            r = c.getresponse()
            return r.status, json.loads(r.read() or b"{}")
        finally:
            c.close()

    def skip(self, tok, csrf="csrf-a"):
        return self.call("POST", "/api/password-skip", tok, csrf)

    def audit_text(self):
        try:
            return server.AUDIT.read_text()
        except OSError:
            return ""

    def choose_own_password(self):
        server.ENV_FILE.write_text(f"CONSOLE_USER=admin\nCONSOLE_PASSWORD={CHOSEN}\n")
        salt = b"0123456789abcdef"
        server.PW_FILE.write_text(f"{salt.hex()} {server.pw_digest(CHOSEN, salt)}\n")
        server._pw_seen.clear()
        self.assertFalse(server.password_temp())

    def test_gate_without_skip(self):
        tok = self.session("a")
        code, me = self.call("GET", "/api/session", tok)
        self.assertEqual((code, me["mustChange"], me["pwSkipped"]), (200, True, False))
        code, body = self.call("GET", "/api/state", tok)
        self.assertEqual((code, body.get("code")), (403, "password_change_required"))
        code, body = self.call("POST", "/api/run", tok, "csrf-a", {"args": ["status"]})
        self.assertEqual((code, body.get("code")), (403, "password_change_required"))

    def test_skip_opens_the_gates_for_this_session_only(self):
        a, b = self.session("a"), self.session("b")
        self.assertEqual(self.skip(a), (200, {"ok": True}))
        code, me = self.call("GET", "/api/session", a)
        self.assertEqual((code, me["mustChange"], me["pwSkipped"]), (200, False, True))
        # past the must-change gate on both GET and POST (what the endpoint answers next is not the gate)
        self.assertEqual(self.call("GET", "/api/audit", a)[0], 200)
        code, body = self.call("POST", "/api/run", a, "csrf-a", {"args": ["nope-not-a-command"]})
        self.assertNotEqual(body.get("code"), "password_change_required")
        # the other session is still gated
        code, me = self.call("GET", "/api/session", b)
        self.assertEqual((me["mustChange"], me["pwSkipped"]), (True, False))
        code, body = self.call("GET", "/api/audit", b)
        self.assertEqual((code, body.get("code")), (403, "password_change_required"))
        self.assertEqual(self.skip(b, "csrf-b")[0], 200)     # each session skips on its own

    def test_skip_is_repeatable_but_audited_once(self):
        a = self.session("a")
        self.assertEqual(self.skip(a)[0], 200)
        self.assertEqual(self.skip(a)[0], 200)
        self.assertEqual(self.audit_text().count(SKIP_AUDIT), 1)

    def test_csrf_required(self):
        a = self.session("a")
        self.assertEqual(self.skip(a, csrf=None)[0], 403)
        self.assertEqual(self.skip(a, csrf="csrf-wrong")[0], 403)
        self.assertNotIn("skip_pw", server.SESSIONS[a])
        self.assertTrue(self.call("GET", "/api/session", a)[1]["mustChange"])

    def test_unauthenticated(self):
        self.assertEqual(self.call("POST", "/api/password-skip", None, "x")[0], 401)
        self.assertEqual(self.call("POST", "/api/password-skip", "f" * 64, "x")[0], 401)   # unknown cookie
        self.assertFalse(any("skip_pw" in s for s in server.SESSIONS.values()))
        self.assertNotIn(SKIP_AUDIT, self.audit_text())

    def test_refused_when_password_is_not_temporary(self):
        a = self.session("a")
        self.choose_own_password()
        self.assertEqual(self.skip(a)[0], 409)
        self.assertNotIn("skip_pw", server.SESSIONS[a])
        me = self.call("GET", "/api/session", a)[1]
        self.assertEqual((me["mustChange"], me["pwSkipped"]), (False, False))
        self.assertNotIn(SKIP_AUDIT, self.audit_text())

    def test_replay_after_password_change_is_refused(self):
        a = self.session("a")
        self.assertEqual(self.skip(a)[0], 200)
        self.choose_own_password()
        me = self.call("GET", "/api/session", a)[1]
        self.assertEqual((me["mustChange"], me["pwSkipped"]), (False, False))     # banner gone once the password is yours
        self.assertEqual(self.skip(a)[0], 409)

    def test_change_password_clears_the_flag(self):
        a = self.session("a")
        self.skip(a)
        code, body = self.call("POST", "/api/password", a, "csrf-a", {"current": GENERATED, "new": CHOSEN, "repeat": CHOSEN})
        self.assertEqual(code, 200, body)
        self.assertNotIn("skip_pw", server.SESSIONS[a])
        self.assertEqual(self.skip(a)[0], 409)

    def test_audit_line_and_nothing_persisted(self):
        a = self.session("a")
        env_before = server.ENV_FILE.read_text()
        self.assertEqual(self.skip(a)[0], 200)
        lines = [ln for ln in self.audit_text().splitlines() if SKIP_AUDIT in ln]
        self.assertEqual(len(lines), 1, self.audit_text())
        self.assertRegex(lines[0], r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d admin skipped the default-password change \(this session\) from 127\.0\.0\.1$")
        self.assertEqual(server.ENV_FILE.read_text(), env_before)       # the password is untouched
        self.assertFalse(server.PW_FILE.exists())                       # nothing says "the user chose one"
        self.assertTrue(server.password_temp())
        # a fresh sign-in is a new session: gated again
        fresh = self.session("c")
        self.assertTrue(self.call("GET", "/api/session", fresh)[1]["mustChange"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
