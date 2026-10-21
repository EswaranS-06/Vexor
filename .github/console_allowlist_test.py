"""CI: the console must refuse terminal-only commands and ask for typed confirmation on destructive ones."""
import importlib.util

spec = importlib.util.spec_from_file_location("srv", "console/server.py")
srv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(srv)

READ = [["status"], ["suricata", "alerts", "-n", "5"], ["logs", "nginx", "-f"], ["doctor"], ["volumes", "ls"], ["disk", "--json"],
        ["proxy", "ls", "--json"], ["proxy"], ["proxy", "show", "soc.example.com"], ["proxy", "cert-file", "soc.example.com", "ca"]]
REFUSED = [["shell"], ["exec", "nginx", "id"], ["api", "DELETE", "/agents"], ["install"], ["config", "edit"],
           ["wazuh", "logtest"], ["nope"], ["status", "bad\nline"], ["uninstall"], ["uninstall", "--images", "--yes"],
           ["uninstall", "--yes", "--keep-data"], ["images"], ["images", "prune", "-a"], ["images", "prune", "--yes", "x"],
           ["volumes", "prune", "--all"]]
CHANGE = [["doctor", "--fix"], ["tools", "enable", "zeek"], ["n8n", "test"], ["restart", "nginx"],
          ["proxy", "add", "soc.example.com", "wazuh.dashboard:5601", "--tls", "local"], ["proxy", "edit", "soc.example.com", "--websocket"],
          ["proxy", "cert", "soc.example.com", "--renew"], ["proxy", "apply"]]
DANGER = [["reset", "full"], ["volumes", "rm", "x"], ["soc", "elk"], ["node-type", "multi"], ["passwd", "admin"],
          ["uninstall", "--keep-data", "--yes"], ["uninstall", "--yes"], ["volumes", "prune", "--yes"], ["images", "prune", "--yes"],
          ["proxy", "rm", "soc.example.com"]]

for a in READ:
    assert srv.classify(a) == ("read", None), (a, srv.classify(a))
for a in REFUSED:
    assert srv.classify(a)[1], (a, srv.classify(a))
for a in CHANGE:
    assert srv.classify(a) == ("change", None), (a, srv.classify(a))
for a in DANGER:
    assert srv.classify(a) == ("danger", None), (a, srv.classify(a))
print("console allowlist ok")
