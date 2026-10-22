"""CI: the console must refuse terminal-only commands and ask for typed confirmation on destructive ones."""
import importlib.util

spec = importlib.util.spec_from_file_location("srv", "console/server.py")
srv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(srv)

READ = [["status"], ["suricata", "alerts", "-n", "5"], ["logs", "nginx", "-f"], ["doctor"], ["volumes", "ls"], ["disk", "--json"],
        ["proxy", "ls", "--json"], ["proxy"], ["proxy", "show", "soc.example.com"], ["proxy", "cert-file", "soc.example.com", "ca"],
        ["wazuh"], ["wazuh", "alerts", "-n", "5"], ["wazuh", "rules", "ls", "--json"], ["wazuh", "decoders", "show", "x.xml"],
        ["wazuh", "lists", "history", "bad-ips", "--json"], ["wazuh", "rules", "templates", "--json"], ["wazuh", "integrations", "ls"],
        ["wazuh", "config", "ls", "--json"], ["wazuh", "config", "custom", "show"], ["wazuh", "logtest", "sshd[1]: test", "--json"],
        ["wazuh", "detection", "status", "--json"], ["wazuh", "agents", "list"]]
REFUSED = [["shell"], ["exec", "nginx", "id"], ["api", "DELETE", "/agents"], ["install"], ["config", "edit"],
           ["wazuh", "logtest"], ["nope"], ["status", "bad\nline"], ["uninstall"], ["uninstall", "--images", "--yes"],
           ["uninstall", "--yes", "--keep-data"], ["images"], ["images", "prune", "-a"], ["images", "prune", "--yes", "x"],
           ["volumes", "prune", "--all"], ["wazuh", "rules", "bogus"], ["wazuh", "config", "edit"], ["wazuh", "logtest", "a\nb"]]
CHANGE = [["doctor", "--fix"], ["tools", "enable", "zeek"], ["n8n", "test"], ["restart", "nginx"],
          ["proxy", "add", "soc.example.com", "wazuh.dashboard:5601", "--tls", "local"], ["proxy", "edit", "soc.example.com", "--websocket"],
          ["proxy", "cert", "soc.example.com", "--renew"], ["proxy", "apply"],
          ["wazuh", "rules", "put", "my", "--from", "/x"], ["wazuh", "decoders", "restore", "my.xml", "20261022T020000Z"],
          ["wazuh", "lists", "add", "bad-ips", "1.2.3.4"], ["wazuh", "integrations", "add", "slack", "--hook-url", "https://h"],
          ["wazuh", "integrations", "edit", "slack", "--level", "9"], ["wazuh", "integrations", "test", "slack"],
          ["wazuh", "config", "set", "logall", "yes"], ["wazuh", "config", "custom", "put", "--from", "/x", "--scope", "all"]]
DANGER = [["reset", "full"], ["volumes", "rm", "x"], ["soc", "elk"], ["node-type", "multi"], ["passwd", "admin"],
          ["uninstall", "--keep-data", "--yes"], ["uninstall", "--yes"], ["volumes", "prune", "--yes"], ["images", "prune", "--yes"],
          ["proxy", "rm", "soc.example.com"], ["wazuh", "rules", "rm", "my"], ["wazuh", "lists", "del", "bad-ips", "1.2.3.4"],
          ["wazuh", "integrations", "rm", "slack"], ["wazuh", "config", "custom", "rm"], ["wazuh", "agents", "remove", "001"]]

for a in READ:
    assert srv.classify(a) == ("read", None), (a, srv.classify(a))
for a in REFUSED:
    assert srv.classify(a)[1], (a, srv.classify(a))
for a in CHANGE:
    assert srv.classify(a) == ("change", None), (a, srv.classify(a))
for a in DANGER:
    assert srv.classify(a) == ("danger", None), (a, srv.classify(a))
masked = srv.mask_args(["wazuh", "integrations", "add", "slack", "--api-key", "s3cret"])
assert "s3cret" not in masked and masked[-1] == "****", masked
assert srv.det_name("rules", "my.xml") == "my.xml" and srv.det_name("rules", "my") == "my.xml" and srv.det_name("lists", "bad-ips") == "bad-ips"
for bad in ("../x", "a/b", "", ".x", "x" * 65, "x y"):
    assert srv.det_name("rules", bad) is None, bad
assert srv.det_name("config", "x") is None
print("console allowlist ok")
