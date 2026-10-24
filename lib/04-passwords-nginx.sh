# shellcheck shell=bash
# vexor lib/04-passwords-nginx.sh - password generation / hashing / internal users, cluster key, nginx rendering, compose profiles / override / layout migration
# Sourced by ./vexor in a fixed order (see the loader there); not executable on its own.
# ============================================================== password generation / hashing / internal users
gen_pw() { echo "$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 20)Aa1.-"; }
valid_pw() {
  local p="$1" re_chars='^[A-Za-z0-9.*+?-]+$' re_sym='[.*+?-]'
  { [ ${#p} -ge 8 ] && [ ${#p} -le 64 ]; } || { echo "must be 8-64 characters"; return 1; }
  [[ "$p" =~ $re_chars ]] || { echo "allowed characters: letters, digits and . * + ? -"; return 1; }
  { [[ "$p" =~ [A-Z] ]] && [[ "$p" =~ [a-z] ]] && [[ "$p" =~ [0-9] ]] && [[ "$p" =~ $re_sym ]]; } \
    || { echo "needs an upper-case letter, a lower-case letter, a digit and one of . * + ? -"; return 1; }
}
hash_pw() {
  local out jh="JAVA_HOME=/usr/share/wazuh-indexer/jdk"     # exec skips the entrypoint that sets it
  if is_running wazuh1.indexer; then
    out="$(dc exec -T -e "$jh" wazuh1.indexer bash "$HASH_SH" -p "$1" 2>/dev/null)"
  else
    out="$(docker run --rm -e "$jh" "wazuh/wazuh-indexer:$(cur_version)" bash "$HASH_SH" -p "$1" 2>/dev/null)"
  fi
  printf '%s\n' "$out" | tr -d '\r' | grep -E '^\$2[aby]\$' | tail -1
}
set_user_hash() {              # set_user_hash <internal user> <bcrypt hash>
  python3 -I - "$INTERNAL_USERS" "$1" "$2" <<'PY'
import re, sys
path, user, h = sys.argv[1:4]
s = open(path).read()
s2, n = re.subn(rf'(^{re.escape(user)}:\n\s+hash: )"[^"]*"', lambda m: m.group(1) + '"' + h + '"', s, flags=re.M)
if n != 1:
    sys.exit(f"user '{user}' not found in {path}")
open(path, "w").write(s2)
PY
}
dashboard_yml_sync() {         # wazuh.yml lives in the dashboard's own volume (written by uid 1000, never bind-mounted): keep its API password current
  local vol; vol="$(project)_wazuh-dashboard-config"
  docker volume inspect "$vol" >/dev/null 2>&1 || return 0      # first start: the image writes hosts: from API_PASSWORD itself
  docker run --rm -e PW="$(env_get API_PASSWORD)" -v "$vol:/c" "$ALPINE_IMAGE" sh -c '
    f=/c/wazuh.yml
    if [ -n "$PW" ] && grep -q 1513629884013 "$f" 2>/dev/null; then
      awk '"'"'/1513629884013/ {h=1} h && !d && /^[ \t]+password:/ {sub(/password:.*/, "password: \"" ENVIRON["PW"] "\""); d=1} {print}'"'"' "$f" > "$f.new" && mv "$f.new" "$f"
    fi
    [ -e "$f" ] && chown 1000:1000 "$f" && chmod 600 "$f"
    chown 1000:1000 /c' >/dev/null 2>&1 || warn "could not update wazuh.yml in the dashboard volume"
  return 0
}
set_api_pw_yml() {
  python3 -I - "$DASH_WAZUH_YML" "$1" <<'PY'
import re, sys
path, pw = sys.argv[1:3]
s = open(path).read()
if "__API_PASSWORD__" in s:
    s = s.replace("__API_PASSWORD__", pw)
else:
    s = re.sub(r'^(\s+password:\s*).*$', lambda m: m.group(1) + '"' + pw + '"', s, count=1, flags=re.M)
open(path, "w").write(s)
PY
  dashboard_yml_sync
}
DEMO_USERS=(kibanaro logstash readall snapshotrestore)   # OpenSearch demo users with publicly known passwords
demo_users_present() { local u; for u in "${DEMO_USERS[@]}"; do grep -q "^$u:" "$INTERNAL_USERS" 2>/dev/null && echo "$u"; done; return 0; }
demo_logins_open() {           # demo users whose default password (= user name) still logs in
  local u; for u in "${DEMO_USERS[@]}"; do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 --cacert "$INT_CERT_DIR/root-ca.pem" \
        --resolve "wazuh1.indexer:$(indexer_port):$(env_def INDEXER_BIND 127.0.0.1 | sed 's/^0.0.0.0$/127.0.0.1/')" \
        -u "$u:$u" "$(indexer_base)/_plugins/_security/authinfo" 2>/dev/null)" = 200 ] && echo "$u"
  done; return 0
}
remove_demo_users() {          # drop the demo users from internal_users.yml (+ push it when the indexer runs)
  [ -n "$(demo_users_present)" ] || return 0
  cp "$INTERNAL_USERS" "$STATE_DIR/internal_users.yml.pre-demo-removal" 2>/dev/null
  python3 -I - "$INTERNAL_USERS" "${DEMO_USERS[@]}" <<'PY'
import re, sys
path, users = sys.argv[1], sys.argv[2:]
s = open(path).read()
for u in users:
    s = re.sub(r"(?m)^%s:\n(?:[ \t]+.*\n|[ \t]*\n)*" % re.escape(u), "", s)
s = s.replace("## Demo users\n", "")
open(path, "w").write(s)
PY
  if is_running wazuh1.indexer && [ "$(ix_code)" = 200 ]; then
    securityadmin_users > "$RUN_TMP/secadmin.log" 2>&1 && ok "demo users removed: ${DEMO_USERS[*]}" \
      || { bad "securityadmin failed - see $RUN_TMP/secadmin.log"; return 1; }
  else
    ok "demo users removed from internal_users.yml (applied when the indexer starts)"
  fi
}
securityadmin_users() {        # push internal_users.yml into the running indexer cluster
  dc exec -T wazuh1.indexer bash -c '
    export JAVA_HOME=/usr/share/wazuh-indexer/jdk
    D=/usr/share/wazuh-indexer/config
    bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
      -f "$D/opensearch-security/internal_users.yml" -t internalusers \
      -cacert "$D/certs/root-ca.pem" -cert "$D/certs/admin.pem" -key "$D/certs/admin-key.pem" \
      -h wazuh1.indexer -p 9200 -nhnv -icl'
}

# ============================================================== cluster key / nginx / compose profiles, override and layout migration
ensure_cluster_key() {         # ensure_cluster_key [new]
  python3 -I - "$CLUSTER_DIR" "${1:-keep}" <<'PY'
import glob, re, secrets, sys
d, mode = sys.argv[1:3]
files = [d + "/wazuh_manager.conf"] + sorted(glob.glob(d + "/wazuh_worker*.conf"))
m = re.search(r"<key>([0-9a-f]{32})</key>", open(files[0]).read())
key = secrets.token_hex(16) if (mode == "new" or not m) else m.group(1)
changed = 0
for f in files:
    s = open(f).read()
    s2 = re.sub(r"<key>[0-9a-f]{32}</key>", f"<key>{key}</key>", s.replace("__CLUSTER_KEY__", key))
    if s2 != s:
        open(f, "w").write(s2); changed += 1
print(changed)
PY
}
render_nginx() {
  local n conns ups i
  n="$(active_workers)"; conns="$(env_def NGINX_WORKER_CONNECTIONS 1024)"
  ups=""                                   # the master is always in the template; add active workers
  [ "$n" -ge 1 ] && ups="        server wazuh.worker:1514;"
  for i in 2 3; do [ "$n" -ge "$i" ] && ups+=$'\n'"        server wazuh${i}.worker:1514;"; done
  local tools="" tt; for tt in $(web_tools); do tools+="$(tool_server_block "$tt")"$'\n'; done
  tools+="$(routes_nginx_blocks)"                # proxy routes (vexor proxy)
  python3 -I - "$NGINX_TPL" "$NGINX_CONF" "$conns" "$ups" "$tools" "$(soc_wazuh && echo 1 || echo 0)" <<'PY'
import sys
tpl, out, conns, ups, tools, wz = sys.argv[1:7]
def cut_block(text, start):
    """remove from `start` through the matching closing brace of the first { after it"""
    k = text.find("{", start); depth = 0
    for n in range(k, len(text)):
        depth += {"{": 1, "}": -1}.get(text[n], 0)
        if depth == 0:
            return text[:start] + text[n + 1:]
    return text
t = open(tpl).read()
if "__TOOL_SERVERS__" not in t:    # migrate older templates: a slot for the web tools inside http {}
    i = t.find("\nstream {"); j = t.rfind("\n}", 0, i if i >= 0 else len(t))
    t = t[:j] + "\n    # optional web tools (N8N/GRAFANA/PORTAINER=true in .env) - rendered by vexor\n__TOOL_SERVERS__" + t[j:]
    open(tpl, "w").write(t)
if "error_page 497" not in t:      # migrate older templates: http:// on the https port -> redirect, not 400
    t = t.replace("        listen 8080 ssl;\n",
                  "        listen 8080 ssl;\n"
                  "        # plain http:// sent to this https port -> redirect instead of \"400 Bad Request\"\n"
                  "        error_page 497 =301 https://$http_host$request_uri;\n", 1)
    open(tpl, "w").write(t)
s = t.replace("__NGINX_WORKER_CONNECTIONS__", conns).replace("__WORKER_UPSTREAMS__", ups).replace("__TOOL_SERVERS__", tools.rstrip("\n"))
if wz != "1":                      # SOC=elk: no Wazuh dashboard server, no agent stream
    k = s.find("proxy_pass https://wazuh.dashboard:5601")
    if k >= 0:
        s = cut_block(s, s.rfind("    server {", 0, k))
    k = s.find("\nstream {")
    if k >= 0:
        s = cut_block(s, k + 1)
try:
    if open(out).read() == s:
        sys.exit(0)
except FileNotFoundError:
    pass
open(out, "w").write(s)            # in-place write keeps the bind-mounted inode
PY
  sync_profiles
}
sync_profiles() {              # COMPOSE_PROFILES follows NODE_TYPE (applied) + INDEXER_COUNT + WORKER_COUNT
  local n p=() s; n="$(active_workers)"
  if soc_wazuh; then
    p+=(wazuh)
    is_single || p+=(multi)
    [ "$(indexer_count)" = 3 ] && p+=(ix3)
    [ "$n" -ge 2 ] && p+=(w2)
    [ "$n" -ge 3 ] && p+=(w3)
  fi
  soc_elk && p+=(elk)
  p+=($(enabled_tools))
  s="$(IFS=,; echo "${p[*]}")"
  [ "$(env_get COMPOSE_PROFILES)" = "$s" ] || env_set COMPOSE_PROFILES "$s"
}
migrate_layout() {             # idempotent upgrades of files written by older versions
  ensure_tools_compose; ensure_elk_compose
  python3 -I - "$ROOT/docker-compose.yml" <<'PY'
import re, sys
p = sys.argv[1]; s = open(p).read(); o = s
for n in (2, 3):
    s = re.sub(r"(\n  wazuh%d\.indexer:\n)(?!    profiles:)" % n,
               r'\1    profiles: ["ix3"]   # off when INDEXER_COUNT=1 (vexor indexers 1)\n', s)
# wazuh.worker exists only in node type multi; nginx runs in both (no profile, no worker dependency)
s = re.sub(r"(\n  wazuh\.worker:\n)(?!    profiles:)",
           r'\1    profiles: ["multi"]   # off when NODE_TYPE=single (vexor node-type single)\n', s)
s = re.sub(r'(\n  nginx:\n)    profiles: \["multi"\][^\n]*\n', r'\1', s)
i = s.find("\n  nginx:\n")
if i >= 0:
    j = len(s)
    for nxt in re.finditer(r"\n(  [A-Za-z0-9_.-]+:|[A-Za-z_][A-Za-z0-9_-]*:)\n", s[i + 1:]):
        j = i + 1 + nxt.start(); break
    s = s[:i] + s[i:j].replace("      - wazuh.worker\n", "") + s[j:]
s = re.sub(r"\Ainclude:\n(?:  - .*\n)+\n?", "", s)     # tools/ELK files are listed in COMPOSE_FILE now
# Wazuh services belong to profile "wazuh" (SOC=elk switches them off)
for svc in (r"wazuh\.master", r"wazuh1\.indexer", r"wazuh\.dashboard"):
    s = re.sub(r"(\n  %s:\n)(?!    profiles:)" % svc, r'\1    profiles: ["wazuh"]   # off when SOC=elk (vexor soc)\n', s)
# nginx: ports come from the generated override (they follow SOC), no hard dependencies
i = s.find("\n  nginx:\n")
if i >= 0:
    j = len(s)
    for nxt in re.finditer(r"\n(  [A-Za-z0-9_.-]+:|[A-Za-z_][A-Za-z0-9_-]*:)\n", s[i + 1:]):
        j = i + 1 + nxt.start(); break
    blk = s[i:j]
    blk = re.sub(r"    ports:\n(?:      - .*\n)+", "", blk)
    blk = re.sub(r"    depends_on:\n(?:      - .*\n)+", "", blk)
    s = s[:i] + blk + s[j:]
s = s.replace('"${INDEXER_BIND:-127.0.0.1}:9200:9200"', '"${INDEXER_BIND:-127.0.0.1}:${INDEXER_HOST_PORT:-9200}:9200"')
s = re.sub(r'(\n      - ")(\$\{(?:ENROLL|SYSLOG|API)_PORT:-)', r'\1${BIND_IP:-0.0.0.0}:\2', s)   # published ports listen on BIND_IP
if s != o:
    open(p, "w").write(s)
PY
  [ "$(env_get COMPOSE_FILE)" = "$COMPOSE_FILES" ] || env_set COMPOSE_FILE "$COMPOSE_FILES"
  sync_profiles
  render_override
}
override_content() {           # docker-compose.override.yml: layout + SOC + tools (always written, part of COMPOSE_FILE)
  local one=0 mvol="" nports=""
  soc_wazuh && [ "$(indexer_count)" = 1 ] && one=1
  soc_wazuh && mvol="$(tools_master_volumes)"
  nports="$(tools_nginx_ports)"
  echo "# Managed by vexor - rewritten by: vexor soc | node-type | indexers | tools. Do not edit by hand."
  [ "$one" = 1 ] && echo "# INDEXER_COUNT=1: the master ships alerts only to wazuh1.indexer."
  [ -n "$mvol" ] && echo "# SURICATA/ZEEK=true: the master reads the sensor logs (read-only) + vexor tool rules."
  echo "# nginx ports follow SOC (Wazuh dashboard + agents) and the web tools / Kibana (<NAME>_PORT in .env)."
  echo "services:"
  if [ "$one" = 1 ] || [ -n "$mvol" ]; then
    echo "  wazuh.master:"
    if [ "$one" = 1 ]; then
      echo "    environment:"
      echo "      INDEXER_URL: '\"https://wazuh1.indexer:9200\"'"
    fi
    if [ -n "$mvol" ]; then echo "    volumes:"; printf '%s\n' "$mvol"; fi
  fi
  echo "  nginx:"
  echo "    ports:"
  if soc_wazuh; then
    echo '      - "${BIND_IP:-0.0.0.0}:${PROXY_PORT:-8080}:8080"'
    echo '      - "${BIND_IP:-0.0.0.0}:${AGENT_PORT:-1514}:1514"'
  fi
  [ -n "$nports" ] && printf '%s\n' "$nports"      # SOC=elk always has Kibana here, so the list is never empty
  routes_override ports; routes_override rest      # proxy routes: 443/80 + certs, ACME webroot, host.docker.internal
  return 0
}
render_override() {            # write it only when it changed (docker compose recreates what changed)
  local s; s="$(override_content)"

  [ -f "$OVERRIDE_FILE" ] && [ "$(cat "$OVERRIDE_FILE")" = "$s" ] && return 0
  printf '%s\n' "$s" > "$OVERRIDE_FILE"
}
prune_disabled_containers() {  # stop + remove containers of services the applied layout does not use (volumes kept)
  local svc rm=() en; en=" $(enabled_services | tr '\n' ' ') "
  for svc in wazuh.master wazuh.worker wazuh2.worker wazuh3.worker wazuh1.indexer wazuh2.indexer wazuh3.indexer wazuh.dashboard nginx "${ELK_SERVICES[@]}" "${TOOLS[@]}"; do
    [[ "$en" == *" $svc "* ]] && continue
    [ -n "$(dc_all ps -aq "$svc" 2>/dev/null)" ] && rm+=("$svc")
  done
  [ ${#rm[@]} -gt 0 ] || return 0
  dc_all rm -sf "${rm[@]}" >/dev/null 2>&1 && say "removed containers the current layout does not use (SOC=$(soc), node type $(node_type)): ${rm[*]} (volumes kept)"
}
nginx_reload() {
  is_running nginx || return 0
  if dc exec -T nginx nginx -t -q; then dc exec -T nginx nginx -s reload >/dev/null && ok "nginx reloaded"
  else bad "nginx config test failed - not reloaded"; return 1; fi
}

