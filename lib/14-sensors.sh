# shellcheck shell=bash
# vexor lib/14-sensors.sh - Suricata (network IDS), Zeek (network logs)
# Sourced by ./vexor in a fixed order (see the loader there); not executable on its own.
# ============================================================== Suricata (network IDS)
suricata_eve() { echo "$TOOLS_DATA/suricata/log/eve.json"; }
suricata_alert_lines() { grep -h '"event_type":"alert"' "$(suricata_eve)" 2>/dev/null || true; }
suricata_status() {
  hdr "Suricata (network IDS)"
  tool_on suricata || { warn "SURICATA=false - enable: vexor suricata enable"; return 0; }
  is_running suricata && ok "running, sniffing $(sniff_iface)" || bad "not running - vexor logs suricata"
  local n; n="$(suricata_sig_count)"
  [ "$n" -gt 0 ] && ok "$n signatures loaded (ET Open, refreshed daily)" || warn "0 signatures - vexor suricata update-rules"
  local eve; eve="$(suricata_eve)"
  if [ -f "$eve" ]; then
    file_fresh "$eve" 15 && ok "eve.json: $(du -h "$eve" | cut -f1), written in the last 15 min" || warn "eve.json not written for 15 min (no traffic on $(sniff_iface)?)"
  else warn "no eve.json yet"; fi
  suricata_alert_lines | python3 -I -c '
import collections, datetime, json, sys
now = datetime.datetime.now(datetime.timezone.utc); sev = collections.Counter(); sig = collections.Counter()
for line in sys.stdin:
    try:
        e = json.loads(line); t = datetime.datetime.strptime(e["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z")
    except (KeyError, ValueError):
        continue
    if now - t > datetime.timedelta(hours=24):
        continue
    sev[e["alert"]["severity"]] += 1; sig[e["alert"]["signature"]] += 1
print("  alerts in the last 24 h: %d  (high %d, medium %d, low %d)" % (sum(sev.values()), sev[1], sev[2], sev[3]))
for s, c in sig.most_common(5):
    print("    %6d  %s" % (c, s))'
  say "alerts go to: $(soc_wazuh && printf 'Wazuh (rules 100720/100721) ')$(soc_elk && printf 'Elasticsearch (vexor-suricata-*) ')$( [ -n "$(n8n_hook)" ] && printf 'n8n')"
}
suricata_alerts() {            # [-n N] [--since 1h|30m|2d]
  local n=20 since=""
  while [ $# -gt 0 ]; do case "$1" in -n) n="${2:?}"; shift ;; --since) since="${2:?}"; shift ;; esac; shift; done
  suricata_alert_lines | python3 -I -c '
import datetime, json, re, sys
n, since = int(sys.argv[1]), sys.argv[2]
cut = None
m = re.fullmatch(r"(\d+)([mhd])", since)
if m:
    unit = {"m": "minutes", "h": "hours", "d": "days"}[m.group(2)]
    cut = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(**{unit: int(m.group(1))})
rows = []
for line in sys.stdin:
    try:
        e = json.loads(line)
    except ValueError:
        continue
    if cut:
        try:
            if datetime.datetime.strptime(e["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z") < cut:
                continue
        except (KeyError, ValueError):
            pass
    a = e["alert"]
    try:
        ts = datetime.datetime.strptime(e["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except (KeyError, ValueError):
        ts = e.get("timestamp", "")[:19]
    rows.append("%s  sev %s  %-5s %21s -> %-21s %s (sid %s)" % (ts, a.get("severity"), e.get("proto", ""),
                "%s:%s" % (e["src_ip"], e.get("src_port", "")) if e.get("src_ip") else "(non-IP)", "%s:%s" % (e["dest_ip"], e.get("dest_port", "")) if e.get("dest_ip") else "", a.get("signature"), a.get("signature_id")))
print("\n".join(rows[-n:]) if rows else "  no alerts")' "$n" "$since"
}
# plain-HTTP pages whose body is "uid=0(root)..." - real traffic that matches sid 2100498 (GPL ATTACK_RESPONSE id check returned root)
TEST_URLS="http://httpbin.org/base64/dWlkPTAocm9vdCkgZ2lkPTAocm9vdCkgZ3JvdXBzPTAocm9vdCk= http://testmynids.org/uid/index.html"
test_request() {               # first test URL that answers; prints its host
  local u; for u in $TEST_URLS; do
    curl -s --max-time 10 -o /dev/null "$u" && { echo "$u" | sed -E 's#^https?://([^/]+)/.*#\1#'; return 0; }
  done
  return 1
}
suricata_test() {              # real traffic that matches GPL ATTACK_RESPONSE id check returned root (sid 2100498)
  is_running suricata || die "suricata is not running"
  local before; before="$(suricata_alert_lines | grep -c '"signature_id":2100498')"
  say "requesting a page whose body is 'uid=0(root)...' - matches sid 2100498"
  test_request >/dev/null || die "no test URL reachable (internet access?) - tried: $TEST_URLS"
  local i; for i in $(seq 1 15); do
    [ "$(suricata_alert_lines | grep -c '"signature_id":2100498')" -gt "$before" ] && { ok "Suricata raised the alert (sid 2100498)"; break; }
    sleep 2
  done
  [ "$i" = 15 ] && { bad "no Suricata alert after 30 s - vexor suricata status   (is $(sniff_iface) the interface this traffic uses?)"; return 1; }
  if soc_wazuh && is_running wazuh.master; then
    for i in $(seq 1 15); do
      dc exec -T wazuh.master sh -c 'tail -n 500 /var/ossec/logs/alerts/alerts.json | grep -q "\"signature_id\":\"2100498\""' 2>/dev/null \
        && { ok "Wazuh turned it into an alert (rule 100721, level 7)"; break; }
      sleep 2
    done
    [ "$i" = 15 ] && warn "not in Wazuh alerts yet - vexor wazuh alerts -n 20"
  fi
  if soc_elk; then
    sleep 5
    local c; c="$(es_curl GET '/vexor-suricata-*/_count?allow_no_indices=true' -d '{"query":{"bool":{"filter":[{"term":{"alert.signature_id":2100498}},{"range":{"@timestamp":{"gte":"now-5m"}}}]}}}' 2>/dev/null | pj 'print(d.get("count", 0))' 2>/dev/null)"
    [ "${c:-0}" -gt 0 ] && ok "stored in Elasticsearch (vexor-suricata-*)" || warn "not in Elasticsearch yet (Logstash reads every few seconds) - vexor elk search 'alert.signature_id:2100498'"
  fi
  return 0
}
cmd_suricata() {
  local sub="${1:-status}"; shift || true
  case "$sub" in
    status) suricata_status ;;
    enable|disable|on|off) cmd_tools "$sub" suricata ;;
    alerts) suricata_alerts "$@" ;;
    test) suricata_test ;;
    update-rules|rules) cmd_tools update-rules ;;
    logs) cmd_logs suricata "$@" ;;
    *) die "usage: vexor suricata [status] | alerts [-n N] [--since 1h] | test | update-rules | enable | disable | logs [-f]" ;;
  esac
}

# ============================================================== Zeek (network logs)
zeek_dir() { echo "$TOOLS_DATA/zeek/logs"; }
zeek_status() {
  hdr "Zeek (network logs)"
  tool_on zeek || { warn "ZEEK=false - enable: vexor zeek enable"; return 0; }
  is_running zeek && ok "running, sniffing $(sniff_iface)" || bad "not running - vexor logs zeek"
  local f n=0 sent; sent=",$(env_def ZEEK_WAZUH_LOGS notice,weird,dns,http,ssl,ssh),"
  printf '  %-14s %8s  %-10s %s\n' LOG SIZE UPDATED "READ BY"
  for f in "$(zeek_dir)"/*.log; do
    [ -f "$f" ] || continue
    local b; b="$(basename "$f" .log)"
    [[ "$b" =~ ^[a-z0-9_]+$ ]] || continue            # skip hourly copies (name.YYYY-MM-DD-HH-MM-SS.log)
    n=$((n + 1))
    printf '  %-14s %8s  %-12s %s\n' "$b" "$(du -h "$f" | cut -f1)" "$(( ($(date +%s) - $(stat -c %Y "$f")) / 60 )) min ago" \
      "$( [[ "$sent" == *",$b,"* ]] && { soc_wazuh && printf 'Wazuh '; soc_elk && printf 'ELK'; } )"
  done
  [ "$n" -gt 0 ] || warn "no logs yet (they appear with the first traffic on $(sniff_iface))"
  say "hourly copies: $(find "$(zeek_dir)" -maxdepth 1 -name '*.*-*.log' | wc -l) files, $(du -sh "$(zeek_dir)" | cut -f1) in total (kept $(env_def TOOLS_LOG_RETENTION_DAYS 7) days)"
  hint "change what Wazuh/ELK read with ZEEK_WAZUH_LOGS in .env (conn is large - add it on purpose), then: vexor tools apply"
}
zeek_show() {                  # zeek_show <log> [-n N]: readable lines of one Zeek log
  local name="${1:-}" n=20; shift || true
  [ -n "$name" ] || die "usage: vexor zeek show <log> [-n N]   logs: $(ls "$(zeek_dir)" 2>/dev/null | grep -E '^[a-z_]+\.log$' | sed 's/\.log$//' | tr '\n' ' ')"
  while [ $# -gt 0 ]; do case "$1" in -n) n="${2:?}"; shift ;; esac; shift; done
  local f; f="$(zeek_dir)/$name.log"; [ -f "$f" ] || die "no $name.log in $(zeek_dir)"
  tail -n "$n" "$f" | python3 -I -c '
import datetime, json, sys
name = sys.argv[1]
def g(e, *k): return " ".join(str(e.get(x, "-")) for x in k)
for line in sys.stdin:
    try:
        e = json.loads(line)
    except ValueError:
        continue
    t = datetime.datetime.fromtimestamp(float(e.get("ts", 0))).strftime("%Y-%m-%d %H:%M:%S")
    hp = "%s:%s -> %s:%s" % (e.get("id.orig_h"), e.get("id.orig_p"), e.get("id.resp_h"), e.get("id.resp_p"))
    if name == "conn": s = "%s %s %s %s bytes %s/%s" % (hp, e.get("proto"), e.get("service", "-"), e.get("conn_state"), e.get("orig_bytes", 0), e.get("resp_bytes", 0))
    elif name == "dns": s = "%s %s %s -> %s" % (e.get("id.orig_h"), e.get("qtype_name", "-"), e.get("query", "-"), ",".join(map(str, e.get("answers", []))) or e.get("rcode_name", "-"))
    elif name == "http": s = "%s %s %s%s -> %s" % (hp, e.get("method"), e.get("host", ""), e.get("uri", ""), e.get("status_code", "-"))
    elif name == "ssl": s = "%s %s %s" % (hp, e.get("version", "-"), e.get("server_name", "-"))
    elif name == "ssh": s = "%s auth_success=%s %s" % (hp, e.get("auth_success", "-"), e.get("client", ""))
    elif name == "notice": s = "%s %s %s" % (e.get("note"), e.get("msg"), e.get("src", ""))
    elif name == "weird": s = "%s %s" % (hp, e.get("name"))
    else: s = json.dumps({k: v for k, v in e.items() if k not in ("ts", "uid")})[:220]
    print(t, s)' "$name"
}
zeek_top() {                   # top talkers / ports / DNS names from the current hour of logs
  local what="${1:-hosts}" d; d="$(zeek_dir)"
  case "$what" in
    hosts|ports) [ -f "$d/conn.log" ] || die "no conn.log yet" ;;
    dns) [ -f "$d/dns.log" ] || die "no dns.log yet" ;;
    *) die "usage: vexor zeek top [hosts|ports|dns]" ;;
  esac
  python3 -I - "$d" "$what" <<'PY'
import collections, json, sys
d, what = sys.argv[1:3]
c = collections.Counter()
f = d + ("/dns.log" if what == "dns" else "/conn.log")
for line in open(f, errors="replace"):
    try:
        e = json.loads(line)
    except ValueError:
        continue
    if what == "hosts": c["%s -> %s" % (e.get("id.orig_h"), e.get("id.resp_h"))] += int(e.get("orig_bytes") or 0) + int(e.get("resp_bytes") or 0)
    elif what == "ports": c["%s/%s" % (e.get("id.resp_p"), e.get("proto"))] += 1
    else: c[e.get("query", "-")] += 1
unit = {"hosts": "bytes", "ports": "connections", "dns": "queries"}[what]
print("  top %s (current log, by %s)" % (what, unit))
for k, v in c.most_common(15):
    print("  %12d  %s" % (v, k))
PY
}
zeek_test() {
  is_running zeek || die "zeek is not running"
  local f; f="$(zeek_dir)/http.log"
  local before host; before="$(grep -c '/base64/\|/uid/index.html' "$f" 2>/dev/null || true)"
  say "requesting a test page over plain HTTP - Zeek should log it in http.log"
  host="$(test_request)" || die "no test URL reachable (internet access?) - tried: $TEST_URLS"
  local i; for i in $(seq 1 30); do
    [ "$(grep -c '/base64/\|/uid/index.html' "$f" 2>/dev/null || true)" -gt "${before:-0}" ] && { ok "Zeek logged the request to $host (http.log)"; return 0; }
    sleep 2
  done
  bad "not in http.log after 60 s - vexor zeek status   (is $(sniff_iface) the interface this traffic uses?)"; return 1
}
cmd_zeek() {
  local sub="${1:-status}"; shift || true
  case "$sub" in
    status) zeek_status ;;
    enable|disable|on|off) cmd_tools "$sub" zeek ;;
    show|tail) zeek_show "$@" ;;
    notices) zeek_show notice "$@" ;;
    top) zeek_top "$@" ;;
    test) zeek_test ;;
    logs) cmd_logs zeek "$@" ;;
    *) die "usage: vexor zeek [status] | show <log> [-n N] | notices [-n N] | top [hosts|ports|dns] | test | enable | disable | logs [-f]" ;;
  esac
}

