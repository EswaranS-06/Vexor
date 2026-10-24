# shellcheck shell=bash
# vexor lib/09-cluster.sh - passwd, agents / cluster, indexer count (3 <-> 1), node type (multi <-> single)
# Sourced by ./vexor in a fixed order (see the loader there); not executable on its own.
# ============================================================== passwords
cmd_passwd() {
  local who="${1:-}" pw="" gen=0; shift || true
  [ "${1:-}" = "--generate" ] && gen=1
  case "$who" in admin|indexer|kibanaserver|dashboard|api|wazuh-wui) ;; *)
    die "usage: vexor passwd <admin|kibanaserver|api> [--generate]
    admin         dashboard login + indexer superuser (INDEXER_PASSWORD)
    kibanaserver  internal dashboard->indexer user (DASHBOARD_PASSWORD)
    api           Wazuh API user wazuh-wui used by the dashboard (API_PASSWORD)" ;;
  esac
  if [ "$gen" = 1 ]; then pw="$(gen_pw)"
  else
    [ -t 0 ] || die "non-interactive: use --generate"
    local p2 why
    read -r -s -p "  New password for $who: " pw; echo
    read -r -s -p "  Repeat: " p2; echo
    [ "$pw" = "$p2" ] || die "passwords differ"
  fi
  why="$(valid_pw "$pw")" || die "Password $why"
  take_lock
  case "$who" in
    admin|indexer|kibanaserver|dashboard)
      local user key
      if [[ "$who" == admin || "$who" == indexer ]]; then user=admin key=INDEXER_PASSWORD; else user=kibanaserver key=DASHBOARD_PASSWORD; fi
      is_running wazuh1.indexer || die "wazuh1.indexer must be running"
      cp "$INTERNAL_USERS" "$RUN_TMP/internal_users.bak"
      local h; h="$(hash_pw "$pw")"; [ -n "$h" ] || die "hashing failed"
      set_user_hash "$user" "$h" || die "could not update internal_users.yml"
      say "Pushing the new user database to the indexer cluster..."
      if ! securityadmin_users > "$RUN_TMP/secadmin.log" 2>&1; then
        cp "$RUN_TMP/internal_users.bak" "$INTERNAL_USERS"
        tail -n 15 "$RUN_TMP/secadmin.log"; die "securityadmin failed - nothing changed"
      fi
      env_set "$key" "$pw"
      ok "indexer user '$user' updated"
      say "Recreating containers that use it..."
      dc up -d >/dev/null 2>&1
      wait_indexer 120 >/dev/null
      if [ "$user" = admin ]; then [ "$(ix_code)" = 200 ] && ok "login with the new admin password works" || warn "admin login check failed (HTTP $(ix_code))"
      else wait_dashboard 240; fi ;;
    api|wazuh-wui)
      env_set API_PASSWORD "$pw"; set_api_pw_yml "$pw"
      say "Recreating master + dashboard (the master applies the API password on start)..."
      dc up -d --force-recreate wazuh.master wazuh.dashboard >/dev/null 2>&1
      API_TOKEN=""; wait_ready_run 180 0 wazuh.master >/dev/null 2>&1
      if api_login; then ok "Wazuh API accepts the new password"; else warn "API login still failing - vexor logs master"; fi ;;
  esac
  [ "$gen" = 1 ] && say "New password: $pw   (stored in .env)"
  chmod 600 "$ENV_FILE"
}

# ============================================================== agents / cluster
cmd_agents() {
  local sub="${1:-list}"; shift || true
  case "$sub" in
    list|ls)
      api GET "/agents?limit=1000&select=id,name,ip,status,os.name,os.version,version,group,node_name,lastKeepAlive&sort=%2Bid" | pj '
items = d.get("data", {}).get("affected_items", [])
fmt = "  %-5s%-24s%-16s%-16s%-10s%-16s%s"
print(fmt % ("ID", "NAME", "IP", "STATUS", "NODE", "VERSION", "OS"))
for a in items:
    o = a.get("os") or {}
    print(fmt % (a.get("id", ""), a.get("name", "")[:23], a.get("ip", ""), a.get("status", ""), a.get("node_name", ""),
                 a.get("version", "-"), (o.get("name", "") + " " + o.get("version", "")).strip()))
print()
print("  %d agent(s)  (000 = the manager itself)" % len(items))' || die "Wazuh API not answering" ;;
    summary)
      api GET /agents/summary/status | pretty ;;
    outdated)
      api GET "/agents/outdated?limit=1000" | pj '
items = d.get("data", {}).get("affected_items", [])
for a in items: print("  %s  %s  %s" % (a.get("id"), a.get("name"), a.get("version")))
print("  %d agent(s) older than the manager" % len(items))' ;;
    remove|rm|delete)
      local ids="${1:-}"; [ -n "$ids" ] || die "usage: vexor agents remove <id[,id...]>"
      confirm "Remove agent(s) $ids? They must re-enroll to report again" || die "Aborted"
      api DELETE "/agents?agents_list=$ids&status=all&older_than=0s" | pj '
dd = d.get("data", {})
print("  removed:", ",".join(dd.get("affected_items", [])) or "-")
for e in dd.get("failed_items", []): print("  failed:", e.get("id"), e.get("error", {}).get("message"))' ;;
    enroll-cmd|install-cmd|cmd) agents_enroll_cmd "$@" ;;
    password|pass) agents_password "$@" ;;
    *) die "usage: vexor agents list|summary|outdated|remove <ids>|enroll-cmd [os]|password on|off|show" ;;
  esac
}
agents_enroll_cmd() {
  local os="all" name="" group="" a
  while [ $# -gt 0 ]; do
    case "$1" in --name) name="${2:?}"; shift ;; --group) group="${2:?}"; shift ;; *) os="$1" ;; esac; shift
  done
  local v h vars pw ap ep
  v="$(cur_version)"; h="$(public_host)"; pw="$(env_get AGENT_ENROLL_PASSWORD)"
  ap="$(env_def AGENT_PORT 1514)"; ep="$(env_def ENROLL_PORT 1515)"
  vars="WAZUH_MANAGER='$h'"
  [ "$ap" != 1514 ] && vars+=" WAZUH_MANAGER_PORT='$ap'"
  [ "$ep" != 1515 ] && vars+=" WAZUH_REGISTRATION_PORT='$ep'"
  [ -n "$pw" ] && vars+=" WAZUH_REGISTRATION_PASSWORD='$pw'"
  [ -n "$group" ] && vars+=" WAZUH_AGENT_GROUP='$group'"
  [ -n "$name" ] && vars+=" WAZUH_AGENT_NAME='$name'"
  hdr "Wazuh agent $v -> manager $h  (agent version must not be newer than the manager)"
  case "$os" in all|linux|deb|debian|ubuntu)
    printf '\n  %sDebian / Ubuntu (amd64; use _arm64.deb on ARM)%s\n' "$C_BD" "$C_0"
    printf '    wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_%s-1_amd64.deb && sudo %s dpkg -i ./wazuh-agent_%s-1_amd64.deb\n' "$v" "$vars" "$v"
    printf '    sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent\n' ;; esac
  case "$os" in all|rpm|rhel|centos|rocky|alma|fedora|amazon)
    printf '\n  %sRHEL / Rocky / Alma / Amazon Linux (x86_64; use .aarch64.rpm on ARM)%s\n' "$C_BD" "$C_0"
    printf '    curl -o wazuh-agent-%s-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-%s-1.x86_64.rpm && sudo %s rpm -ihv wazuh-agent-%s-1.x86_64.rpm\n' "$v" "$v" "$vars" "$v"
    printf '    sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent\n' ;; esac
  case "$os" in all|windows|win)
    printf '\n  %sWindows (admin PowerShell)%s\n' "$C_BD" "$C_0"
    printf '    Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-%s-1.msi -OutFile $env:tmp\\wazuh-agent; msiexec.exe /i $env:tmp\\wazuh-agent /q %s\n' "$v" "$vars"
    printf '    NET START WazuhSvc\n' ;; esac
  case "$os" in all|mac|macos|darwin)
    printf '\n  %smacOS (intel64; use arm64.pkg on Apple silicon)%s\n' "$C_BD" "$C_0"
    printf '    curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-%s-1.intel64.pkg && echo "%s" > /tmp/wazuh_envs && sudo installer -pkg ./wazuh-agent.pkg -target /\n' "$v" "$(sed "s/' WAZUH_/' \&\& WAZUH_/g" <<<"$vars")"
    printf '    sudo /Library/Ossec/bin/wazuh-control start\n' ;; esac
  echo
  say "Options: --name <agent-name>  --group <group>   OS: linux | rpm | windows | macos"
  [ -z "$pw" ] && say "Enrollment is open to anyone who can reach port $ep - protect it: vexor agents password on"
  say "Agent already installed? Reinstalling keeps its old ossec.conf. Point it here: sudo sed -i 's#<address>.*</address>#<address>$h</address>#' /var/ossec/etc/ossec.conf && sudo systemctl restart wazuh-agent"
  if [ -z "$(env_get PUBLIC_HOST)" ] && ip -4 addr show 2>/dev/null | grep -F " $h/" | has dynamic; then
    warn "$h comes from DHCP - when it changes, agents lose the manager. Reserve it in DHCP, use a static IP, or set PUBLIC_HOST to a DNS name"
  fi
  return 0
}
agents_password() {
  local mode="${1:-show}" pw="${2:-}" conf="$CLUSTER_DIR/wazuh_manager.conf"
  case "$mode" in
    show)
      if grep -q '<use_password>yes</use_password>' "$conf"; then say "Enrollment password: ON  ($(env_get AGENT_ENROLL_PASSWORD))"
      else say "Enrollment password: OFF (any host reaching port $(env_def ENROLL_PORT 1515) can enroll)"; fi ;;
    on)
      take_lock
      [ -n "$pw" ] || pw="$(openssl rand -hex 16)"
      [[ "$pw" =~ ^[A-Za-z0-9._+-]{8,128}$ ]] || die "use 8+ chars from A-Z a-z 0-9 . _ + -"
      is_running wazuh.master || die "wazuh.master must be running"
      sed -i 's#<use_password>no</use_password>#<use_password>yes</use_password>#' "$conf"
      dc exec -T wazuh.master bash -c "printf '%s\n' '$pw' > /var/ossec/etc/authd.pass && chown root:wazuh /var/ossec/etc/authd.pass && chmod 640 /var/ossec/etc/authd.pass" \
        || die "could not write authd.pass"
      env_set AGENT_ENROLL_PASSWORD "$pw"
      dc_restart wazuh.master >/dev/null && ok "enrollment password ON: $pw"
      say "Existing agents are not affected. New ones need it (vexor agents enroll-cmd includes it)." ;;
    off)
      take_lock
      sed -i 's#<use_password>yes</use_password>#<use_password>no</use_password>#' "$conf"
      is_running wazuh.master && dc exec -T wazuh.master rm -f /var/ossec/etc/authd.pass
      env_set AGENT_ENROLL_PASSWORD ""
      dc_restart wazuh.master >/dev/null && ok "enrollment password OFF" ;;
    *) die "usage: vexor agents password on [password] | off | show" ;;
  esac
}
# ============================================================== indexer count (3 <-> 1)
# Shrinking keeps every shard: data is moved to wazuh1.indexer, nodes 2+3 leave the
# voting configuration, and only then are they stopped. Growing adds fresh nodes 2+3
# and restores the replica copies.
ix_nodes() { ix GET '/_cat/nodes?h=name&format=json' | pj 'print(" ".join(sorted(n["name"] for n in d)))'; }
ix_health_field() { ix GET /_cluster/health | pj 'print(d[sys.argv[1]])' "$1"; }
ix_shards_on() {               # number of shard copies on the given (space separated) nodes
  ix GET '/_cat/shards?h=node&format=json' | pj '
nodes = set(sys.argv[1].split())
print(sum(1 for s in d if (s.get("node") or "") in nodes))' "$1"
}
ix_explicit_replicas() {       # "index replicas" for indices with a fixed replica count > 0
  ix GET '/_all/_settings/index.number_of_replicas,index.auto_expand_replicas?expand_wildcards=all&flat_settings=true' | pj '
for k, v in sorted(d.items()):
    s = v.get("settings", {})
    r = int(s.get("index.number_of_replicas", 0) or 0)
    a = str(s.get("index.auto_expand_replicas", "false")).lower()
    if r > 0 and a in ("false", "", "none"):
        print(k, r)'
}
ix_set_replicas() {            # ix_set_replicas <index> <n>  (prints nothing, returns curl/API status)
  ix PUT "/$1/_settings?expand_wildcards=all" -d "{\"index\":{\"number_of_replicas\":$2}}" | has '"acknowledged":true'
}
ix_zero_replicas() {           # set every fixed-replica index to 0 copies; saves the old values once
  local idx r saved="$STATE_DIR/indexer-replicas.saved"
  mkdir -p "$STATE_DIR"
  ix_explicit_replicas > "$RUN_TMP/replicas"
  [ -s "$saved" ] || cp "$RUN_TMP/replicas" "$saved"
  while read -r idx r; do
    [ -n "$idx" ] || continue
    if ix_set_replicas "$idx" 0; then say "replicas 0: $idx (was $r)"; else warn "could not change $idx"; fi
  done < "$RUN_TMP/replicas"
}
ix_wait_moved() {              # ix_wait_moved "<nodes>" <timeout-s>: no shards left on them, nothing moving
  local nodes="$1" t="${2:-3600}" i=0 left moving st hj
  while :; do
    left="$(ix_shards_on "$nodes")"
    hj="$(ix GET /_cluster/health)"
    moving="$(pj 'print(d["relocating_shards"] + d["initializing_shards"])' <<<"$hj")"
    st="$(pj 'print(d["status"])' <<<"$hj")"
    say "$(date +%T)  shards still on ${nodes// /+}: ${left:-?}   moving: ${moving:-?}   cluster: ${st:-?}"
    [ "$left" = 0 ] && [ "$moving" = 0 ] && [ "$st" != red ] && return 0
    [ "$i" -ge "$t" ] && return 1
    sleep 10; i=$((i + 10))
  done
}
ix_wait_nodes() {              # ix_wait_nodes <count> <timeout-s>
  local want="$1" t="${2:-600}" i=0 n
  while [ "$i" -lt "$t" ]; do
    n="$(ix_health_field number_of_nodes 2>/dev/null)"
    [ "$n" = "$want" ] && return 0
    say "$(date +%T)  indexer nodes in cluster: ${n:-0}/$want"
    sleep 10; i=$((i + 10))
  done
  return 1
}
ix_wait_status() {             # ix_wait_status <green|yellow> <timeout-s>
  local want="$1" t="${2:-600}" i=0 st
  while [ "$i" -lt "$t" ]; do
    st="$(ix_health_field status 2>/dev/null)"
    [ "$st" = green ] && return 0
    [ "$want" = yellow ] && [ "$st" = yellow ] && return 0
    say "$(date +%T)  cluster: ${st:-unreachable} (waiting for $want)"
    sleep 10; i=$((i + 10))
  done
  return 1
}
indexer_yml_hosts() {          # indexer_yml_hosts <file> <host,host..>: seed hosts; drop bootstrap list
  python3 -I - "$1" "$2" <<'PY'
import re, sys
path, hosts = sys.argv[1], sys.argv[2].split(",")
s = open(path).read()
# cluster.initial_master_nodes is only for the very first bootstrap; once the cluster exists,
# keeping it lets fresh nodes form a SECOND cluster - so it is removed for good.
s = re.sub(r"^cluster\.initial_master_nodes:\n(?:[ \t]+- .*\n)*", "", s, flags=re.M)
block = "discovery.seed_hosts:\n" + "".join(f"        - {h}\n" for h in hosts)
s = re.sub(r"^discovery\.seed_hosts:\n(?:[ \t]+- .*\n)*", lambda m: block, s, flags=re.M)
open(path, "w").write(s)          # in-place write keeps the bind-mounted inode
PY
}
indexer_yml_bootstrap() {      # indexer_yml_bootstrap <file> <host,host..>: seed hosts AND bootstrap list (brand-new cluster only)
  python3 -I - "$1" "$2" <<'PY'
import re, sys
path, hosts = sys.argv[1], sys.argv[2].split(",")
s = open(path).read()
items = "".join(f"        - {h}\n" for h in hosts)
s = re.sub(r"^cluster\.initial_master_nodes:\n(?:[ \t]+- .*\n)*", "", s, flags=re.M)
s = re.sub(r"^discovery\.seed_hosts:\n(?:[ \t]+- .*\n)*",
           lambda m: "cluster.initial_master_nodes:\n" + items + "discovery.seed_hosts:\n" + items, s, flags=re.M)
open(path, "w").write(s)
PY
}
fresh_install_layout() {       # first install (no indexer data yet): bootstrap the indexers for NODE_TYPE
  if docker volume inspect "$(project)_wazuh-indexer-data-1" >/dev/null 2>&1; then
    # existing cluster: keep its layout (a pre-1.1 install without a state file was multi)
    [ -f "$NODE_TYPE_FILE" ] || { mkdir -p "$STATE_DIR"; echo multi > "$NODE_TYPE_FILE"; }
    return 0
  fi
  local t f; t="$(desired_node_type)"
  [ "$t" = single ] && env_set INDEXER_COUNT 1
  if [ "$(indexer_count)" = 1 ]; then
    indexer_yml_bootstrap "$ROOT/config/wazuh_indexer/wazuh1.indexer.yml" wazuh1.indexer
  else
    for f in 1 2 3; do indexer_yml_bootstrap "$ROOT/config/wazuh_indexer/wazuh$f.indexer.yml" wazuh1.indexer,wazuh2.indexer,wazuh3.indexer; done
  fi
  mkdir -p "$STATE_DIR"; echo "$t" > "$NODE_TYPE_FILE"
  sync_profiles; render_override
}
recreate_running_managers() {  # managers pick up changed env/override; stopped ones stay stopped
  local svc run=()
  for svc in $(enabled_managers); do is_running "$svc" && run+=("$svc"); done
  [ ${#run[@]} -gt 0 ] && dc up -d "${run[@]}" >/dev/null 2>&1
  return 0
}
old_indexer_volumes() { project_volumes | grep -E "_wazuh-indexer-data-[23]$" || true; }
indexers_render_check() { layout_render_check "$(node_type)" "$1"; }
layout_render_check() {        # dry-run: render <node-type> <indexer-count> into a temp copy and validate it
  local nt="$1" target="$2" t="$RUN_TMP/layout"
  [ "$nt" = single ] && [ "$target" != 1 ] && { bad "node type single runs exactly 1 indexer (asked for $target)"; return 1; }
  rm -rf "$t"; mkdir -p "$t/config"
  cp "$ROOT/docker-compose.yml" "$t/"; cp "$ENV_FILE" "$t/.env"
  [ -f "$TOOLS_COMPOSE" ] && cp "$TOOLS_COMPOSE" "$t/"
  cp -r "$ROOT/config/wazuh_indexer" "$t/config/"
  (
    ENV_FILE="$t/.env"; OVERRIDE_FILE="$t/docker-compose.override.yml"; ROOT="$t"; NODE_TYPE_FILE="$t/node-type"
    echo "$nt" > "$NODE_TYPE_FILE"
    env_set INDEXER_COUNT "$target"; env_set NODE_TYPE "$nt"; sync_profiles; render_override
    if [ "$target" = 1 ]; then
      indexer_yml_hosts "$t/config/wazuh_indexer/wazuh1.indexer.yml" wazuh1.indexer
    else
      local f; for f in 1 2 3; do indexer_yml_hosts "$t/config/wazuh_indexer/wazuh$f.indexer.yml" wazuh1.indexer,wazuh2.indexer,wazuh3.indexer; done
    fi
    cd "$t" || exit 1
    local svcs want; svcs="$(env -u COMPOSE_PROFILES docker compose --env-file "$t/.env" config --services 2>&1)" || { bad "rendered compose invalid: $svcs"; exit 1; }
    svcs="$(sort <<<"$svcs" | tr '\n' ' ')"; want="$(enabled_services | sort | tr '\n' ' ')"
    [ "$svcs" = "$want" ] && ok "rendered compose ($nt, $target indexer(s)) runs: $svcs" || { bad "rendered compose runs: $svcs  - expected: $want"; exit 1; }
    env -u COMPOSE_PROFILES docker compose --env-file "$t/.env" config --format json 2>/dev/null > "$t/rendered.json" || { bad "compose config --format json failed"; exit 1; }
    python3 -I - "$t/rendered.json" "$nt" "$(env_def AGENT_PORT 1514)" "$(env_def PROXY_PORT 8080)" <<'PY' || exit 1
import json, sys
c, nt, agent, proxy = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3], sys.argv[4]
s = c["services"]
def pub(svc, target):
    return [str(p.get("published")) for p in s.get(svc, {}).get("ports", []) if int(p.get("target", 0)) == target]
print("  ✔ master INDEXER_URL ->", s["wazuh.master"]["environment"]["INDEXER_URL"])
owner = "nginx"
dash = ("nginx", 8080)
errs = []
if agent not in pub(owner, 1514): errs.append(f"agent port {agent} is not published by {owner}")
if proxy not in pub(*dash): errs.append(f"dashboard port {proxy} is not published by {dash[0]}")
if pub("wazuh.master", 1514) or pub("wazuh.dashboard", 5601):
    errs.append("master/dashboard publish direct ports (nginx must own them)")
if "wazuh.worker" in s.get("nginx", {}).get("depends_on", {}):
    errs.append("nginx depends on wazuh.worker (breaks node type single)")
for e in errs: print("  ✘", e)
if errs: sys.exit(1)
print(f"  ✔ agents -> {owner}:{agent}/tcp, browser -> {dash[0]}:{proxy}/tcp")
PY
    python3 -I -c 'import sys
s = open(sys.argv[1]).read()
assert "initial_master_nodes" not in s, "bootstrap list still present"
import itertools
rest = s.split("discovery.seed_hosts:\n")[1].split("\n")
hosts = [l.strip()[2:] for l in itertools.takewhile(lambda l: l.startswith((" ", "\t")), rest)]
print("  ✔ wazuh1.indexer.yml seed hosts:", ", ".join(hosts))' \
      "$t/config/wazuh_indexer/wazuh1.indexer.yml" || exit 1
  )
}
indexers_status() {
  hdr "Indexers: INDEXER_COUNT=$(indexer_count)"
  if [ "$(ix_code)" = 200 ]; then
    say "cluster: $(ix_health_field status)   nodes: $(ix_nodes)"
    ix GET "/_cat/allocation?v&h=node,shards,disk.indices,disk.percent"
    local n; n="$(ix_explicit_replicas | wc -l)"
    say "indices with a fixed replica count > 0: $n   (others auto-expand with the node count)"
    [ -f "$STATE_DIR/indexer-cluster-excluded" ] && warn "a shrink was started but not finished: vexor indexers abort  (or run: vexor indexers 1 again)"
  else
    bad "indexer unreachable (HTTP $(ix_code))"
  fi
  local v; v="$(old_indexer_volumes)"
  [ -n "$v" ] && [ "$(indexer_count)" = 1 ] && say "old data volumes of removed indexers: $(tr '\n' ' ' <<<"$v")  -> vexor indexers cleanup"
  return 0
}
indexers_shrink() {
  local dry=0 nobackup=0 t
  while [ $# -gt 0 ]; do case "$1" in --dry-run) dry=1 ;; --no-backup) nobackup=1 ;; esac; shift; done
  t="$(env_def INDEXER_MOVE_TIMEOUT 3600)"
  [ "$(indexer_count)" = 3 ] || die "INDEXER_COUNT is already 1"
  hdr "Pre-checks"
  [ "$(ix_code)" = 200 ] || die "indexer unreachable (HTTP $(ix_code)) - fix first: vexor doctor"
  local st nodes; st="$(ix_health_field status)"; nodes="$(ix_nodes)"
  if [ -f "$STATE_DIR/indexer-cluster-excluded" ]; then
    warn "resuming an unfinished shrink (allocation exclusion already set)"
  else
    [ "$st" = green ] || die "cluster is $st - it must be green before shrinking (vexor doctor)"
  fi
  ok "cluster $st"
  [ "$nodes" = "wazuh1.indexer wazuh2.indexer wazuh3.indexer" ] || die "expected nodes wazuh1-3.indexer, found: $nodes"
  ok "nodes: $nodes"
  local need free; need="$(ix GET '/_cat/indices?h=pri.store.size&bytes=b&expand_wildcards=all' | awk '{s+=$1} END {printf "%d", s}')"
  free="$(df -B1 --output=avail "$(docker_root)" | tail -1 | tr -d ' ')"
  [ "$free" -gt $(( need * 2 + 1073741824 )) ] && ok "disk: $((need / 1048576)) MB of primary data, $((free / 1073741824)) GB free" \
    || die "not enough free disk on $(docker_root) for moving $((need / 1048576)) MB"
  ok "$(ix_explicit_replicas | wc -l) indices with fixed replicas will be set to 0 (the others auto-expand)"
  cat <<EOF

  Plan  (3 -> 1 indexer, alert data stays available the whole time)
    1. backup                      indexer snapshot + manager state + config$( [ "$nobackup" = 1 ] && echo "  (skipped: --no-backup)")
    2. replicas -> 0               a single node cannot hold replica copies
    3. move shards to wazuh1       allocation exclusion of wazuh2/3, wait until empty
    4. voting exclusion            wazuh2/3 leave the cluster-manager vote (keeps quorum)
    5. configs                     INDEXER_COUNT=1, compose profile ix3 off, master -> wazuh1 only,
                                   wazuh1.indexer.yml seed hosts = wazuh1
    6. stop + remove wazuh2/3      their volumes are KEPT until: vexor indexers cleanup
    7. restart wazuh1, clear exclusions, recreate managers, verify
    8. reminder in $(env_def CLEANUP_REMIND_DAYS 3) days: check health, then delete the old volumes
  Short outage only in step 7 (indexer restart, ~1 min). Roll back before step 5: vexor indexers abort
EOF
  hdr "Dry run: render and validate the 1-indexer layout"
  indexers_render_check 1 || die "layout check failed - nothing changed"
  if [ "$dry" = 1 ]; then ok "dry run finished - nothing was changed"; return 0; fi
  confirm "Reduce the indexer cluster from 3 nodes to 1?" || die "Aborted"
  take_lock
  echo "$(ts) indexers 1 started" >> "$HISTORY_FILE"

  hdr "1/8 Backup"
  if [ "$nobackup" = 1 ]; then warn "skipped"; else backup_run || confirm "Backup had errors. Continue?" || die "Aborted"; fi
  hdr "2/8 Replicas -> 0";              ix_zero_replicas; ok "done"
  hdr "3/8 Moving all shards to wazuh1.indexer"
  ix PUT /_cluster/settings -d '{"persistent":{"cluster.routing.allocation.exclude._name":"wazuh2.indexer,wazuh3.indexer"}}' | has '"acknowledged":true' \
    || die "could not set the allocation exclusion"
  touch "$STATE_DIR/indexer-cluster-excluded"
  ix_wait_moved "wazuh2.indexer wazuh3.indexer" "$t" || die "shards did not move within ${t}s - check: vexor indexer GET /_cluster/allocation/explain ; roll back: vexor indexers abort"
  ok "all shards are on wazuh1.indexer"
  hdr "4/8 Voting exclusion for wazuh2/3"
  ix POST '/_cluster/voting_config_exclusions?node_names=wazuh2.indexer,wazuh3.indexer&timeout=2m' -o /dev/null -w '%{http_code}' | has '^200$' \
    || die "voting exclusion failed - roll back: vexor indexers abort"
  ok "wazuh1.indexer is now the only cluster-manager voter"
  hdr "5/8 Configs"
  local bk; bk="$STATE_DIR/indexer-yml-$(date +%Y%m%d-%H%M%S)"; mkdir -p "$bk"; cp "$ROOT"/config/wazuh_indexer/wazuh*.indexer.yml "$bk/"
  indexer_yml_hosts "$ROOT/config/wazuh_indexer/wazuh1.indexer.yml" wazuh1.indexer
  env_set INDEXER_COUNT 1; sync_profiles; render_override
  ok "INDEXER_COUNT=1 (previous indexer configs saved in $bk)"
  hdr "6/8 Stopping wazuh2/3.indexer"
  dc_all stop wazuh2.indexer wazuh3.indexer >/dev/null 2>&1; dc_all rm -f wazuh2.indexer wazuh3.indexer >/dev/null 2>&1
  ok "stopped and removed (volumes kept)"
  hdr "7/8 Restart wazuh1.indexer + clear exclusions"
  dc_restart wazuh1.indexer >/dev/null 2>&1
  wait_indexer 300 || die "wazuh1.indexer did not come back - see: vexor logs indexer1 ; previous configs: $bk"
  ix DELETE '/_cluster/voting_config_exclusions?wait_for_removal=false' >/dev/null
  ix PUT /_cluster/settings -d '{"persistent":{"cluster.routing.allocation.exclude._name":null}}' >/dev/null
  rm -f "$STATE_DIR/indexer-cluster-excluded"
  recreate_running_managers
  hdr "8/8 Verify"
  ix_wait_status green 300 || { ix_zero_replicas >/dev/null; ix_wait_status green 120; } \
    || warn "cluster not green yet - vexor doctor --fix"
  say "nodes: $(ix_nodes)   cluster: $(ix_health_field status)"
  local svc; for svc in $(enabled_managers); do
    is_running "$svc" || continue
    sleep 5
    dc exec -T "$svc" filebeat test output >/dev/null 2>&1 && ok "$svc filebeat -> indexer OK" || warn "$svc filebeat cannot reach the indexer yet (retry: vexor doctor)"
  done
  reminder_add indexer-cleanup "$(env_def CLEANUP_REMIND_DAYS 3)" \
    "Indexers were reduced to 1 on $(date +%F). If 'vexor doctor' shows no failures, delete the old data of indexer 2+3." \
    "vexor doctor && vexor indexers cleanup"
  echo "$(ts) indexers 1 finished" >> "$HISTORY_FILE"
  ok "Done: 1 indexer. Reminder set for $(date -d "+$(env_def CLEANUP_REMIND_DAYS 3) days" +%F): vexor indexers cleanup"
}
indexers_grow() {
  local dry=0 nobackup=0
  while [ $# -gt 0 ]; do case "$1" in --dry-run) dry=1 ;; --no-backup) nobackup=1 ;; esac; shift; done
  [ "$(indexer_count)" = 1 ] || die "INDEXER_COUNT is already 3"
  is_single && die "node type single uses one indexer - switch the whole layout with: vexor node-type multi"
  hdr "Pre-checks"
  [ "$(ix_code)" = 200 ] || die "indexer unreachable (HTTP $(ix_code))"
  ok "cluster $(ix_health_field status), nodes: $(ix_nodes)"
  local heap avail; heap="$(env_def INDEXER_HEAP 1g)"; avail=$(awk '/MemAvailable/ {printf "%d", $2/1024}' /proc/meminfo)
  local need_mb; need_mb=$(( $(numfmt --from=iec "${heap^^}" 2>/dev/null || echo 1073741824) / 1048576 * 2 * 2 ))
  [ "$avail" -gt "$need_mb" ] && ok "RAM: ${avail} MB available, ~${need_mb} MB needed for 2 more indexers" \
    || warn "RAM: only ${avail} MB available, ~${need_mb} MB needed for 2 more indexers"
  local old; old="$(old_indexer_volumes | tr '\n' ' ')"
  cat <<EOF

  Plan  (1 -> 3 indexers)
    1. backup$( [ "$nobackup" = 1 ] && echo "  (skipped: --no-backup)")
    2. configs: INDEXER_COUNT=3, profile ix3 on, seed hosts wazuh1-3 (no bootstrap list), override removed
    3. delete the obsolete data volumes of the old wazuh2/3 (if still there): ${old:-none}
    4. restart wazuh1, start fresh wazuh2/3 - they join the existing cluster
    5. restore replica copies, recreate managers, wait for green
EOF
  hdr "Dry run: render and validate the 3-indexer layout"
  indexers_render_check 3 || die "layout check failed - nothing changed"
  if [ "$dry" = 1 ]; then ok "dry run finished - nothing was changed"; return 0; fi
  confirm "Grow the indexer cluster from 1 node to 3?" || die "Aborted"
  take_lock
  echo "$(ts) indexers 3 started" >> "$HISTORY_FILE"
  hdr "1/5 Backup"
  if [ "$nobackup" = 1 ]; then warn "skipped"; else backup_run || confirm "Backup had errors. Continue?" || die "Aborted"; fi
  hdr "2/5 Configs"
  local f; for f in 1 2 3; do indexer_yml_hosts "$ROOT/config/wazuh_indexer/wazuh$f.indexer.yml" wazuh1.indexer,wazuh2.indexer,wazuh3.indexer; done
  env_set INDEXER_COUNT 3; sync_profiles; render_override
  ok "INDEXER_COUNT=3"
  hdr "3/5 Old wazuh2/3 volumes"
  if [ -n "$old" ]; then docker volume rm $old >/dev/null && ok "removed (their data was obsolete; everything lives on wazuh1)"; else ok "none"; fi
  hdr "4/5 Restart wazuh1, start wazuh2/3"
  dc_restart wazuh1.indexer >/dev/null 2>&1; wait_indexer 300 || die "wazuh1.indexer did not come back - vexor logs indexer1"
  dc up -d wazuh2.indexer wazuh3.indexer >/dev/null 2>&1
  ix_wait_nodes 3 600 || die "new indexers did not join - vexor logs indexer2 indexer3"
  ok "nodes: $(ix_nodes)"
  hdr "5/5 Replicas + verify"
  local saved="$STATE_DIR/indexer-replicas.saved" idx r
  if [ -s "$saved" ]; then
    while read -r idx r; do [ -n "$idx" ] && ix_set_replicas "$idx" "$r" && say "replicas $r: $idx"; done < "$saved"
    rm -f "$saved"
  fi
  recreate_running_managers
  ix_wait_status green 900 && ok "cluster green" || warn "cluster not green yet (replicas still copying) - check: vexor indexers status"
  reminder_rm indexer-cleanup
  echo "$(ts) indexers 3 finished" >> "$HISTORY_FILE"
  ok "Done: 3 indexers"
}
indexers_abort() {
  [ "$(indexer_count)" = 3 ] || die "configs were already switched to 1 indexer - finish with: vexor indexers 1, or go back with: vexor indexers 3"
  take_lock
  ix DELETE '/_cluster/voting_config_exclusions?wait_for_removal=false' >/dev/null && ok "voting exclusions cleared"
  ix PUT /_cluster/settings -d '{"persistent":{"cluster.routing.allocation.exclude._name":null}}' >/dev/null && ok "allocation exclusion cleared"
  local saved="$STATE_DIR/indexer-replicas.saved" idx r
  if [ -s "$saved" ]; then
    while read -r idx r; do [ -n "$idx" ] && ix_set_replicas "$idx" "$r" && say "replicas $r: $idx"; done < "$saved"
    rm -f "$saved"
  fi
  rm -f "$STATE_DIR/indexer-cluster-excluded"
  ok "back to a normal 3-node cluster (shards rebalance by themselves)"
}
indexers_cleanup() {
  [ "$(indexer_count)" = 1 ] || die "only needed after: vexor indexers 1"
  local v; v="$(old_indexer_volumes)"
  if [ -z "$v" ]; then ok "no old indexer volumes left"; reminder_rm indexer-cleanup; return 0; fi
  local u; for u in $v; do [ -z "$(vol_users "$u")" ] || die "$u is still used by: $(vol_users "$u")"; done
  printf '  %s (%s)\n' $(for u in $v; do echo "$u" "$(du -sh "$(docker volume inspect -f '{{.Mountpoint}}' "$u")" | cut -f1)"; done)
  confirm_word DELETE "Deletes the old data volumes of the removed indexers (all data now lives on wazuh1.indexer)." || die "Aborted"
  take_lock
  docker volume rm $v >/dev/null && ok "removed"
  reminder_rm indexer-cleanup
}
cmd_indexers() {
  local sub="${1:-status}"; shift || true
  case "$sub" in
    status)            indexers_status ;;
    1|shrink)          indexers_shrink "$@" ;;
    3|grow)            indexers_grow "$@" ;;
    abort)             indexers_abort ;;
    cleanup)           indexers_cleanup ;;
    *) die "usage: vexor indexers status | 1 [--dry-run] [--no-backup] | 3 [--dry-run] [--no-backup] | abort | cleanup" ;;
  esac
}

# ============================================================== node type (multi <-> single)
# multi  : wazuh.master + WORKER_COUNT workers, INDEXER_COUNT indexers, dashboard; nginx publishes
#          PROXY_PORT (dashboard) and AGENT_PORT (agent events, balanced over the managers).
# single : wazuh.master, wazuh1.indexer, wazuh.dashboard. The master publishes AGENT_PORT and the
#          dashboard publishes PROXY_PORT with the same certificate - same addresses for agents and browsers.
# Shared by both (never touched by a switch): master volumes (agent keys, rules, decoders, groups, API
# users, integrations), wazuh-indexer-data-1 (every alert, after the shards are moved there), the dashboard
# volumes, .env, config/ and certificates. Worker volumes are kept while single and resync on return.
NT_SHARED_INFO="agent keys + groups, rules/decoders, API users, alerts/archives (wazuh1.indexer), dashboard settings, certificates"
node_type_status() {
  local nt dnt; nt="$(node_type)"; dnt="$(desired_node_type)"
  hdr "Node type: $nt   (.env NODE_TYPE=$dnt)"
  say "$(layout_desc)"
  say "kept for multi : WORKER_COUNT=$(worker_count), indexers 3 (unless: node-type multi --indexers 1)"
  say "always shared  : $NT_SHARED_INFO"
  if is_single; then
    say "agents         : $(public_host):$(env_def AGENT_PORT 1514)/tcp -> nginx -> wazuh.master    enroll :$(env_def ENROLL_PORT 1515)"
    say "dashboard      : https://$(public_host):$(env_def PROXY_PORT 8080) -> nginx -> wazuh.dashboard"
  else
    say "agents         : $(public_host):$(env_def AGENT_PORT 1514)/tcp -> nginx -> master + $(worker_count) worker(s)    enroll :$(env_def ENROLL_PORT 1515)"
    say "dashboard      : https://$(public_host):$(env_def PROXY_PORT 8080) -> nginx -> wazuh.dashboard"
  fi
  if docker_ok; then
    local run; run="$(running_services | sort | tr '\n' ' ')"
    say "running        : ${run:-nothing}"
  fi
  if [ -f "$NODE_SWITCH_FILE" ]; then warn "switch to $(pending_target) not finished - re-run: vexor node-type $(pending_target)"
  elif [ "$nt" != "$dnt" ]; then warn "NODE_TYPE in .env says $dnt - apply with: vexor node-type $dnt"; fi
  hint "switch: vexor node-type single|multi [--dry-run]"
  return 0
}
nt_apply_layout() {            # nt_apply_layout <single|multi>: managers, nginx and ports for the layout
  local target="$1"
  mkdir -p "$STATE_DIR"; echo "$target" > "$NODE_TYPE_FILE"    # from here on every command uses this layout
  sync_profiles; render_override
  if [ "$target" = single ]; then
    render_nginx
    say "nginx now balances agents to the master only; removing the workers (their volumes are kept for multi)"
    nginx_reload >/dev/null 2>&1 || true
    prune_disabled_containers
    say "recreating the master + dashboard (drops any old direct ports), nginx keeps $(env_def AGENT_PORT 1514) and $(env_def PROXY_PORT 8080)"
    run_step "Recreating the master and dashboard" dc up -d --no-deps --force-recreate wazuh.master wazuh.dashboard \
      || die "master/dashboard did not start - see: vexor logs master dashboard ; re-run: vexor node-type single"
    run_step "Starting the remaining containers" dc up -d || die "nginx did not start - see: vexor logs nginx ; re-run: vexor node-type single"
    nginx_reload >/dev/null 2>&1 || true
  else
    say "starting the workers (they resync agent keys, rules and groups from the master)"
    run_step "Recreating the master and dashboard" dc up -d --no-deps --force-recreate wazuh.master wazuh.dashboard \
      || die "master/dashboard did not start - see: vexor logs master dashboard ; re-run: vexor node-type multi"
    prune_disabled_containers
    run_step "Starting the remaining containers" dc up -d || die "workers/nginx did not start - see: vexor logs nginx worker ; re-run: vexor node-type multi"
    render_nginx                    # only now that the workers exist (nginx resolves upstreams on reload)
    nginx_reload >/dev/null 2>&1 || dc up -d --no-deps --force-recreate nginx >/dev/null 2>&1
  fi
  ok "$(layout_desc)"
}
node_type_verify() {
  local want got i svc
  wait_indexer 300 || warn "indexer not ready yet - vexor doctor"
  wait_dashboard 300 || true
  want=$(( $(active_workers) + 1 ))
  wait_ready_run 120 0 $(enabled_managers) >/dev/null 2>&1
  got="$(dc exec -T wazuh.master /var/ossec/bin/cluster_control -l 2>/dev/null | awk 'NR>1 && NF' | wc -l)"
  if [ "${got:-0}" -ge "$want" ]; then ok "manager cluster: $got/$want node(s)"
  else warn "manager cluster: ${got:-0}/$want node(s) - workers may still be syncing (vexor cluster)"; fi
  tcp_open "$(local_ip)" "$(env_def AGENT_PORT 1514)"  && ok "agent port $(env_def AGENT_PORT 1514)/tcp open"  || bad "agent port $(env_def AGENT_PORT 1514) closed - vexor doctor --fix"
  tcp_open "$(local_ip)" "$(env_def ENROLL_PORT 1515)" && ok "enrollment port $(env_def ENROLL_PORT 1515)/tcp open" || bad "enrollment port closed - vexor logs ossec master"
  [ "$(served_fp)" = "$(cert_fp "$(proxy_cert_path)")" ] && ok "port $(env_def PROXY_PORT 8080) serves the same dashboard certificate as before" \
    || warn "port $(env_def PROXY_PORT 8080) serves a different certificate - vexor doctor --fix"
  for svc in $(enabled_managers); do
    is_running "$svc" || continue
    dc exec -T "$svc" filebeat test output >/dev/null 2>&1 && ok "$svc filebeat -> indexer OK" || warn "$svc filebeat cannot reach the indexer yet (vexor doctor)"
  done
  local s; s="$(api GET /agents/summary/status 2>/dev/null | pj '
c = d["data"].get("connection", d["data"])
print("%s active, %s disconnected, %s never connected" % (c.get("active", 0), c.get("disconnected", 0), c.get("never_connected", 0)))')" \
    && ok "agents (same keys as before): $s" || warn "Wazuh API not answering yet"
  say "Agents reconnect by themselves within ~1-2 min (same IP and port). Check: vexor agents list"
}
node_type_switch() {           # node_type_switch <single|multi> [--dry-run] [--no-backup] [--indexers 1|3]
  local target="$1"; shift
  local dry=0 nobackup=0 want_ix=3 cur
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run) dry=1 ;; --no-backup) nobackup=1 ;;
      --indexers) want_ix="${2:-}"; shift ;;
      *) die "unknown option '$1'" ;;
    esac; shift
  done
  [[ "$want_ix" =~ ^(1|3)$ ]] || die "--indexers must be 1 or 3"
  [ "$target" = single ] && want_ix=1
  cur="$(node_type)"
  if [ "$cur" = "$target" ] && [ ! -f "$NODE_SWITCH_FILE" ] && [ "$(indexer_count)" = "$want_ix" ]; then
    [ "$(desired_node_type)" = "$target" ] || env_set NODE_TYPE "$target"
    ok "already node type $target ($(layout_desc))"; return 0
  fi
  preflight
  hdr "Pre-checks: $cur -> $target"
  if [ "$(ix_code)" != 200 ]; then
    say "the indexer is not answering - starting the current layout ($cur) first, the data is moved while it runs"
    render_nginx; render_override; prune_disabled_containers
    dc up -d >/dev/null 2>&1; wait_indexer 300 || die "indexer unreachable (HTTP $(ix_code)) - fix first: vexor doctor"
  fi
  ok "indexer cluster $(ix_health_field status), nodes: $(ix_nodes)"
  if [ "$target" = single ] && [ "$(indexer_count)" = 3 ]; then
    local st; st="$(ix_health_field status)"
    [ "$st" = green ] || [ -f "$STATE_DIR/indexer-cluster-excluded" ] \
      || die "indexer cluster is $st - it must be green before the data can be moved to one node (vexor doctor --fix)"
  fi
  if [ "$target" = multi ]; then
    local avail need; avail=$(awk '/MemAvailable/ {printf "%d", $2/1048576}' /proc/meminfo 2>/dev/null); avail="${avail:-0}"
    need=$(( $(ram_want_gb multi) - $(ram_want_gb single) ))
    [ "$avail" -ge "$need" ] && ok "RAM: ${avail} GB available (~${need} GB more needed for multi)" \
      || warn "RAM: only ${avail} GB available, multi needs ~${need} GB more - lower INDEXER_HEAP or use --indexers 1"
  fi
  local a; for a in "${MASTER_STATE_VOLUMES[@]}" wazuh-indexer-data-1; do
    docker volume inspect "$(project)_$a" >/dev/null 2>&1 || warn "volume $(project)_$a not found (fresh stack?)"
  done
  ok "shared data stays in place: $NT_SHARED_INFO"
  if [ "$target" = single ]; then
    cat <<EOF

  Plan  ($cur -> single: 1 manager, 1 indexer, dashboard behind nginx)
    1. backup                   indexer snapshot + manager state + config$( [ "$nobackup" = 1 ] && echo "  (skipped: --no-backup)")
    2. indexers 3 -> 1          $( [ "$(indexer_count)" = 3 ] && echo "move every shard to wazuh1, then remove indexer 2+3 (volumes kept)" || echo "already 1 - nothing to move")
    3. managers                 remove $(worker_count) worker(s) (volumes kept); nginx stays in front and
                                sends agents ($(env_def AGENT_PORT 1514)) to the master, browsers ($(env_def PROXY_PORT 8080)) to the dashboard
    4. verify                   ports, certificate, filebeat, agents reconnect (same keys, same address)
  Downtime: about 1-2 min while the master and the dashboard are recreated (agents buffer events meanwhile).
EOF
  else
    cat <<EOF

  Plan  ($cur -> multi: master + $(worker_count) worker(s), $want_ix indexer(s), dashboard behind nginx)
    1. backup                   indexer snapshot + manager state + config$( [ "$nobackup" = 1 ] && echo "  (skipped: --no-backup)")
    2. managers                 workers start, nginx balances agents over master + workers
                                (workers resync agent keys, rules and groups from the master)
    3. indexers                 $( [ "$want_ix" = 3 ] && [ "$(indexer_count)" = 1 ] && echo "1 -> 3: fresh indexer 2+3 join, replica copies restored" || echo "stay at $(indexer_count)")
    4. verify                   ports, certificate, cluster, filebeat, agents reconnect
  Downtime: about 1-2 min while the master and the dashboard are recreated.
EOF
  fi
  hdr "Dry run: render and validate the target layout"
  layout_render_check "$target" "$want_ix" || die "layout check failed - nothing changed"
  if [ "$dry" = 1 ]; then ok "dry run finished - nothing was changed"; return 0; fi
  confirm "Switch the stack from $cur to $target?" || die "Aborted"
  take_lock
  local relayout=0                                             # managers/nginx/ports need (re)applying
  { [ "$cur" != "$target" ] || [ -f "$NODE_SWITCH_FILE" ]; } && relayout=1
  mkdir -p "$STATE_DIR"; echo "$target" > "$NODE_SWITCH_FILE"
  env_set NODE_TYPE "$target"
  echo "$(ts) node-type $target started (from $cur)" >> "$HISTORY_FILE"
  local yes_before="$ASSUME_YES"; ASSUME_YES=1                 # the steps below were confirmed above

  hdr "1/4 Backup"
  if [ "$nobackup" = 1 ]; then warn "skipped"; else backup_run || { ASSUME_YES="$yes_before"; confirm "Backup had errors. Continue?" || die "Aborted"; ASSUME_YES=1; }; fi
  if [ "$target" = single ]; then
    hdr "2/4 Indexers -> 1"
    if [ "$(indexer_count)" = 3 ]; then indexers_shrink --no-backup; else ok "already 1 indexer"; fi
    hdr "3/4 Managers + dashboard -> single"
    if [ "$relayout" = 1 ]; then nt_apply_layout single; else ok "already single"; fi
  else
    hdr "2/4 Managers + nginx -> multi"
    if [ "$relayout" = 1 ]; then nt_apply_layout multi; else ok "already multi"; fi
    hdr "3/4 Indexers"
    if [ "$want_ix" = 3 ] && [ "$(indexer_count)" = 1 ]; then indexers_grow --no-backup; else ok "keeping $(indexer_count) indexer(s)"; fi
  fi
  ASSUME_YES="$yes_before"
  hdr "4/4 Verify"
  node_type_verify
  rm -f "$NODE_SWITCH_FILE"
  echo "$(ts) node-type $target finished" >> "$HISTORY_FILE"
  ok "Done: $(layout_desc)"
  if [ "$target" = single ] && [ -n "$(old_indexer_volumes)" ]; then
    say "Old indexer 2+3 volumes are kept (vexor indexers cleanup frees the disk; going back to multi recreates them anyway)."
  fi
  return 0
}
cmd_node_type() {
  soc_wazuh || die "SOC=$(soc) runs no Wazuh - node types apply to Wazuh (vexor soc wazuh|both)"
  local sub="${1:-status}"; shift || true
  case "${sub,,}" in
    status|show) node_type_status ;;
    single|multi) node_type_switch "${sub,,}" "$@" ;;
    *) die "usage: vexor node-type [status] | single [--dry-run] [--no-backup] | multi [--indexers 1|3] [--dry-run] [--no-backup]" ;;
  esac
}

