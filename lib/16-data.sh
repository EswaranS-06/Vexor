# shellcheck shell=bash
# vexor lib/16-data.sh - ELK extras, retention / log pruning, backup / restore, volumes
# Sourced by ./vexor in a fixed order (see the loader there); not executable on its own.
# ============================================================== ELK extras
elk_search() {                 # elk search [query] [-n N] [--index P]
  local q="*" n=20 idx="vexor-*"
  [ $# -gt 0 ] && [[ "$1" != -* ]] && { q="$1"; shift; }
  while [ $# -gt 0 ]; do case "$1" in -n) n="${2:?}"; shift ;; --index) idx="${2:?}"; shift ;; esac; shift; done
  es_curl GET "/$idx/_search?allow_no_indices=true" -d "$(python3 -I -c 'import json,sys; print(json.dumps({"size": int(sys.argv[2]), "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}], "query": {"query_string": {"query": sys.argv[1]}}}))' "$q" "$n")" \
    | python3 -I -c '
import json, sys
d = json.load(sys.stdin)
if "error" in d:
    print("  error:", d["error"].get("reason", d["error"])); sys.exit(1)
hits = d["hits"]["hits"]
print("  %s matches (newest %d shown)" % (d["hits"]["total"]["value"], len(hits)))
for h in reversed(hits):
    s = h["_source"]
    if "rule" in s: txt = "lvl %s %s" % (s["rule"].get("level"), s["rule"].get("description"))
    elif "alert" in s: txt = "sev %s %s" % (s["alert"].get("severity"), s["alert"].get("signature"))
    elif s.get("event_type"): txt = "%s %s -> %s" % (s["event_type"], s.get("src_ip"), s.get("dest_ip"))
    else: txt = json.dumps({k: v for k, v in s.items() if not k.startswith(("@", "event", "log", "host", "tags"))})[:160]
    print("  %s  %-24s %s" % (s.get("@timestamp", "")[:19].replace("T", " "), h["_index"][:24], txt))'
}
elk_beats_config() {
  hdr "Ship logs from another machine into ELK (Filebeat / Elastic Agent -> Logstash)"
  if logstash_tls_on; then
    cat <<EOF
  # filebeat.yml on the sending machine (copy the CA first: vexor elk beats-ca > /etc/filebeat/vexor-ca.crt)
  output.logstash:
    hosts: ["$(public_host):$(env_def LOGSTASH_BEATS_PORT 55044)"]
    ssl.enabled: true
    ssl.certificate_authorities: ["/etc/filebeat/vexor-ca.crt"]
  # events land in vexor-beats-* (Kibana data view "Vexor - Beats / Elastic Agent")
EOF
  else
    cat <<EOF
  # filebeat.yml on the sending machine
  output.logstash:
    hosts: ["$(public_host):$(env_def LOGSTASH_BEATS_PORT 55044)"]
  # events land in vexor-beats-* (Kibana data view "Vexor - Beats / Elastic Agent")
EOF
    hint "the Beats input has no TLS: set LOGSTASH_BEATS_TLS=true, vexor config apply, then update the senders"
  fi
}
cmd_cluster() {
  is_running wazuh.master || die "wazuh.master is not running"
  dc exec -T wazuh.master /var/ossec/bin/cluster_control -l
  echo
  dc exec -T wazuh.master /var/ossec/bin/cluster_control -i 2>/dev/null | head -n 40
}

# ============================================================== retention / logs pruning
# RETENTION_DAYS (default 30, 0 = keep forever) is the one setting. INDEX_RETENTION_DAYS (Wazuh) and
# ELK_RETENTION_DAYS (Elasticsearch) override it for their backend when they hold a number.
retention_days() {             # retention_days KEY -> days for one backend; fails when the value is not a whole number
  local v; v="$(env_def "$1" "$(env_def RETENTION_DAYS 30)")"
  [[ "$v" =~ ^[0-9]+$ ]] || return 1
  echo "$v"
}
retention_expect() {           # retention_expect DAYS -> the min age a live policy must show (none = no policy)
  if [ "$1" = 0 ]; then echo none; else echo "${1}d"; fi
}
retention_words() {            # retention_words DAYS -> wording for status and doctor
  if [ "$1" = 0 ]; then echo "kept forever"; else echo "deleted after $1 days"; fi
}
ism_policy_body() {            # ISM policy: delete Wazuh alert and archive indices $1 days after they were created
  cat <<JSON
{"policy":{"description":"Delete Wazuh alert/archive indices after $1 days","default_state":"hot",
 "states":[{"name":"hot","actions":[],"transitions":[{"state_name":"delete","conditions":{"min_index_age":"$1d"}}]},
           {"name":"delete","actions":[{"delete":{}}],"transitions":[]}],
 "ism_template":[{"index_patterns":["wazuh-alerts-*","wazuh-archives-*"],"priority":100}]}}
JSON
}
ism_policy_age() {             # min_index_age of the live Wazuh policy ("none" when it is missing)
  ix GET "/_plugins/_ism/policies/$ISM_POLICY" 2>/dev/null \
    | pj 'print(d["policy"]["states"][0]["transitions"][0]["conditions"]["min_index_age"])' 2>/dev/null || echo none
}
ism_covered() {                # "managed of total": wazuh-alerts-* / wazuh-archives-* indices under the policy
  ix GET "/_plugins/_ism/explain/wazuh-alerts-*,wazuh-archives-*" 2>/dev/null \
    | pj 'idx = {k: v for k, v in d.items() if k != "total_managed_indices" and isinstance(v, dict)}
print(sum(1 for v in idx.values() if v.get("index.plugins.index_state_management.policy_id") == sys.argv[1]), "of", len(idx))' "$ISM_POLICY" 2>/dev/null || echo "?"
}
retention_apply() {            # Wazuh indexer: ISM policy, attached to wazuh-alerts-* and wazuh-archives-* (0 days = remove it)
  local days body resp seq pri pat
  days="$(retention_days INDEX_RETENTION_DAYS)" || { warn "INDEX_RETENTION_DAYS / RETENTION_DAYS must be a whole number of days"; return 1; }
  if [ "$days" = 0 ]; then
    for pat in 'wazuh-alerts-*' 'wazuh-archives-*'; do
      ix POST "/_plugins/_ism/remove/$pat" >/dev/null 2>&1 || true
    done
    ix DELETE "/_plugins/_ism/policies/$ISM_POLICY" >/dev/null 2>&1 || true
    ok "Wazuh indices kept forever (retention 0: policy '$ISM_POLICY' removed)"
    return 0
  fi
  body="$(ism_policy_body "$days")"
  resp="$(ix GET "/_plugins/_ism/policies/$ISM_POLICY")"
  seq="$(pj 'print(d.get("_seq_no","") if "policy" in d else "")' <<<"$resp" || true)"
  pri="$(pj 'print(d.get("_primary_term","") if "policy" in d else "")' <<<"$resp" || true)"
  if [ -n "$seq" ]; then
    ix PUT "/_plugins/_ism/policies/$ISM_POLICY?if_seq_no=$seq&if_primary_term=$pri" -d "$body" >/dev/null || return 1
    ok "retention policy updated: delete alert/archive indices after $days days"
  else
    ix PUT "/_plugins/_ism/policies/$ISM_POLICY" -d "$body" | has '"_id"' || return 1
    ok "retention policy created: delete alert/archive indices after $days days"
  fi
  for pat in 'wazuh-alerts-*' 'wazuh-archives-*'; do
    ix POST "/_plugins/_ism/add/$pat" -d "{\"policy_id\":\"$ISM_POLICY\"}" >/dev/null 2>&1 || true
  done
  # existing indices keep the policy version they were attached with: move them to the new one
  for pat in 'wazuh-alerts-*' 'wazuh-archives-*'; do
    ix POST "/_plugins/_ism/change_policy/$pat" -d "{\"policy_id\":\"$ISM_POLICY\"}" >/dev/null 2>&1 || true
  done
  return 0
}
retention_purge() {            # vexor retention purge: delete DOCUMENTS inside the Wazuh indices (the indices themselves stay)
  local older="" idx="wazuh-alerts-*,wazuh-archives-*" agent="" rule="" q="" sca=0 dry=0 compact=0 body n
  while [ $# -gt 0 ]; do
    case "$1" in
      --older-than) older="${2:?days}"; shift ;;
      --index)      idx="${2:?pattern}"; shift ;;
      --agent)      agent="${2:?agent name}"; shift ;;
      --rule-id)    rule="${2:?rule id}"; shift ;;
      --query)      q="${2:?lucene query}"; shift ;;
      --sca)        sca=1 ;;
      --dry-run)    dry=1 ;;
      --compact)    compact=1 ;;
      *) die "unknown option $1 - vexor retention purge [--older-than DAYS] [--agent NAME] [--rule-id ID] [--sca] [--query LUCENE] [--index PATTERN] [--dry-run] [--compact]" ;;
    esac; shift
  done
  [ -n "$older$agent$rule$q" ] || [ "$sca" = 1 ] || die "give at least one filter: --older-than, --agent, --rule-id, --sca or --query (deleting every document is not offered)"
  [[ -z "$older" || "$older" =~ ^[0-9]+$ ]] || die "--older-than must be a whole number of days"
  [[ -z "$rule" || "$rule" =~ ^[0-9]+$ ]] || die "--rule-id must be a number"
  soc_wazuh || die "Wazuh is off (SOC=$(soc))"
  [ "$(ix_code)" = 200 ] || die "Wazuh indexer unreachable"
  body="$(python3 -I - "$older" "$agent" "$rule" "$q" "$sca" <<'PY'
import json, sys
older, agent, rule, q, sca = sys.argv[1:6]
must = []
if older: must.append({"range": {"timestamp": {"lt": f"now-{older}d"}}})
if agent: must.append({"match_phrase": {"agent.name": agent}})
if rule:  must.append({"term": {"rule.id": rule}})
if sca == "1": must.append({"exists": {"field": "data.sca"}})
if q:     must.append({"query_string": {"query": q}})
print(json.dumps({"query": {"bool": {"filter": must}}}))
PY
)"
  n="$(ix POST "/${idx}/_count?ignore_unavailable=true&allow_no_indices=true" -d "$body" | pj 'print(d.get("count", 0))')"
  say "documents matching in $idx: ${n:-0}"
  [ "${n:-0}" -gt 0 ] || { ok "nothing to delete"; return 0; }
  [ "$dry" = 1 ] && { say "dry run - nothing deleted"; return 0; }
  take_lock
  confirm "Delete $n document(s) from $idx? The indices stay, the documents cannot be restored" || die "Aborted"
  ix POST "/${idx}/_delete_by_query?conflicts=proceed&refresh=true&wait_for_completion=true&ignore_unavailable=true&allow_no_indices=true" -d "$body" \
    | pj 'print("deleted", d.get("deleted", 0), "documents, version conflicts", d.get("version_conflicts", 0), "failures", len(d.get("failures", [])))' | sed 's/^/  /'
  if [ "$compact" = 1 ]; then
    ix POST "/${idx}/_forcemerge?only_expunge_deletes=true&ignore_unavailable=true&allow_no_indices=true" >/dev/null && ok "deleted documents compacted, disk space is freed"
  else say "disk space is freed when Wazuh merges segments; --compact does it now"; fi
}
cmd_retention() {              # vexor retention [status|apply]: deletion policies for Wazuh and Elasticsearch data
  local rc=0 wd ed ri re
  case "${1:-status}" in
    apply)
      take_lock
      if soc_wazuh; then
        if [ "$(ix_code)" = 200 ]; then retention_apply || rc=1; else warn "Wazuh indexer unreachable - skipped"; rc=1; fi
      fi
      if soc_elk; then
        if [ "$(es_code /_cluster/health)" = 200 ]; then elk_retention_apply || rc=1; else warn "Elasticsearch unreachable - skipped"; rc=1; fi
      fi
      [ "$rc" = 0 ] || die "retention apply did not finish (see above)" ;;
    status|show)
      ri="$(env_get INDEX_RETENTION_DAYS)"; re="$(env_get ELK_RETENTION_DAYS)"
      say "RETENTION_DAYS=$(env_def RETENTION_DAYS 30) (0 = keep forever)   INDEX_RETENTION_DAYS=${ri:-unset}   ELK_RETENTION_DAYS=${re:-unset}"
      say "MANAGER_LOG_RETENTION_DAYS=$(env_def MANAGER_LOG_RETENTION_DAYS 30)   SNAPSHOT_RETENTION_DAYS=$(env_def SNAPSHOT_RETENTION_DAYS 14)"
      if soc_wazuh; then
        wd="$(retention_days INDEX_RETENTION_DAYS)" || wd=""
        if [ -z "$wd" ]; then warn "Wazuh: INDEX_RETENTION_DAYS / RETENTION_DAYS is not a whole number"
        elif [ "$(ix_code)" != 200 ]; then warn "Wazuh indexer unreachable"
        elif [ "$(ism_policy_age)" = "$(retention_expect "$wd")" ]; then
          ok "Wazuh: $(retention_words "$wd") (policy '$ISM_POLICY', indices under it: $(ism_covered))"
        else warn "Wazuh: policy is $(ism_policy_age), expected $(retention_expect "$wd") (vexor retention apply)"; fi
      fi
      if soc_elk; then
        ed="$(retention_days ELK_RETENTION_DAYS)" || ed=""
        if [ -z "$ed" ]; then warn "ELK: ELK_RETENTION_DAYS / RETENTION_DAYS is not a whole number"
        elif [ "$(es_code /_cluster/health)" != 200 ]; then warn "Elasticsearch not answering"
        elif [ "$(elk_policy_age)" = "$(retention_expect "$ed")" ]; then
          ok "ELK vexor-* indices: $(retention_words "$ed") (ILM policy 'vexor-retention', indices under it: $(elk_covered))"
        else warn "ELK: ILM policy is $(elk_policy_age), expected $(retention_expect "$ed") (vexor retention apply)"; fi
      fi
      if soc_wazuh && [ "$(ix_code)" = 200 ]; then
        hdr "Alert / archive indices (oldest first)"
        ix GET "/_cat/indices/wazuh-alerts-*,wazuh-archives-*?v&s=index&h=index,docs.count,store.size,creation.date.string" | head -n 60
        hdr "Total size"
        ix GET "/_cat/indices/wazuh-*?h=store.size&bytes=b" | awk '{s+=$1} END {printf "  %.2f GB (all wazuh-* indices, incl. replicas)\n", s/1073741824}'
      fi ;;
    purge) shift; retention_purge "$@" ;;
    *) die "usage: vexor retention status|apply|purge  (sets: vexor config set RETENTION_DAYS 60; 0 = keep forever; purge deletes documents, not indices)" ;;
  esac
}
prune_logs() {
  local days svc; days="$(env_def MANAGER_LOG_RETENTION_DAYS 30)"
  for svc in $(enabled_managers); do
    is_running "$svc" || continue
    say "[$svc] deleting rotated logs older than $days days"
    dc exec -T "$svc" bash -c "
      for d in alerts archives firewall api cluster; do
        [ -d /var/ossec/logs/\$d ] && find /var/ossec/logs/\$d -type f \( -name '*.gz' -o -name '*.json' -o -name '*.log' -o -name '*.sum' \) \
          -mtime +$days -print -delete
      done; true" | sed 's/^/    /'
  done
}

# ============================================================== backup / restore
ES_SNAP_REPO="vexor-backup"
es_snapshot_dir() { local d; d="$(backup_dir)/es-snapshots"; mkdir -p "$d"; chown 1000:0 "$d"; chmod 770 "$d"; echo "$d"; }
es_snapshot_register() {
  es_snapshot_dir >/dev/null
  es_curl PUT "/_snapshot/$ES_SNAP_REPO" -d '{"type":"fs","settings":{"location":"/usr/share/elasticsearch/snapshots","compress":true}}' 2>/dev/null | has '"acknowledged":true'
}
es_snapshot_run() {            # es_snapshot_run <stamp>: vexor-* + Kibana saved objects (data views, dashboards)
  soc_elk || return 0
  [ "$(es_code /_cluster/health)" = 200 ] || { warn "Elasticsearch not reachable - ELK snapshot skipped"; return 1; }
  es_snapshot_register || { bad "Elasticsearch snapshot repository could not be registered (path.repo; recreate elasticsearch: vexor restart elasticsearch)"; return 1; }
  local r st
  r="$(es_curl PUT "/_snapshot/$ES_SNAP_REPO/es-snap-$1?wait_for_completion=true" --max-time 7200 \
        -d '{"indices":"vexor-*","ignore_unavailable":true,"include_global_state":false,"feature_states":["kibana"]}' 2>/dev/null)"
  st="$(pj 'print(d.get("snapshot",{}).get("state","FAILED"))' <<<"$r" 2>/dev/null || echo FAILED)"
  if [ "$st" = SUCCESS ]; then ok "Elasticsearch snapshot es-snap-$1 (vexor-* + Kibana saved objects)"
  else bad "Elasticsearch snapshot: $st $(head -c 300 <<<"$r")"; return 1; fi
}
es_snapshot_prune() {          # es_snapshot_prune <cutoff-epoch>
  soc_elk && [ "$(es_code "/_snapshot/$ES_SNAP_REPO")" = 200 ] || return 0
  es_curl GET "/_snapshot/$ES_SNAP_REPO/_all" 2>/dev/null | pj '
for s in d.get("snapshots", []):
    if int(s.get("end_time_in_millis", 0)) // 1000 < int(sys.argv[1]): print(s["snapshot"])' "$1" | while read -r id; do
    [ -n "$id" ] && es_curl DELETE "/_snapshot/$ES_SNAP_REPO/$id" >/dev/null 2>&1 && say "pruned Elasticsearch snapshot $id"
  done
}
snapshot_register() {
  local dir; dir="$(backup_dir)/snapshots"; mkdir -p "$dir"; chown 1000:1000 "$dir"
  ix PUT "/_snapshot/$SNAP_REPO" -d '{"type":"fs","settings":{"location":"/mnt/snapshots","compress":true}}' | has '"acknowledged":true'
}
backup_run() {
  local keep dir stamp p vol r state
  keep="$(env_def SNAPSHOT_RETENTION_DAYS 14)"; dir="$(backup_dir)"; stamp="$(date +%Y%m%d-%H%M%S)"; p="$(project)"
  mkdir -p "$dir/config" "$dir/snapshots"
  hdr "Backup $stamp -> $dir"
  if [ "$(ix_code)" = 200 ]; then
    snapshot_register || warn "snapshot repository registration failed"
    r="$(ix PUT "/_snapshot/$SNAP_REPO/snap-$stamp?wait_for_completion=true" --max-time 7200 \
          -d '{"indices":"wazuh-*","ignore_unavailable":true,"include_global_state":false}')"
    state="$(pj 'print(d.get("snapshot",{}).get("state","FAILED"))' <<<"$r" || echo FAILED)"
    if [ "$state" = SUCCESS ]; then ok "indexer snapshot snap-$stamp"
    else bad "indexer snapshot: $state $(head -c 300 <<<"$r")"; fi
  else
    warn "indexer unreachable - snapshot skipped"
  fi
  for vol in "${MASTER_STATE_VOLUMES[@]}" n8n-data grafana-data portainer-data; do
    docker volume inspect "${p}_${vol}" >/dev/null 2>&1 || continue
    docker run --rm -v "${p}_${vol}:/data:ro" -v "$dir/config:/backup" "$ALPINE_IMAGE" \
      tar czf "/backup/${vol}-${stamp}.tar.gz" -C /data . && ok "volume $vol"
  done
  es_snapshot_run "$stamp" || true
  local extra=(); [ -d "$DET_HIST" ] && extra+=(.state/detection-history)   # versions of config/wazuh_custom (vexor wazuh rules history)
  tar czf "$dir/config/stack-config-${stamp}.tar.gz" -C "$ROOT" config .env docker-compose.yml generate-indexer-certs.yml vexor lib "${extra[@]}" 2>/dev/null \
    && ok "stack config (.env, config/ with config/wazuh_custom, certs)"
  chmod 600 "$dir"/config/*"${stamp}"* 2>/dev/null
  # retention
  find "$dir/config" -name '*.tar.gz' -mtime "+$keep" -print -delete | sed 's/^/  pruned /'
  if [ "$(ix_code)" = 200 ]; then
    local cutoff; cutoff=$(date -d "-${keep} days" +%s)
    ix GET "/_cat/snapshots/$SNAP_REPO?h=id,end_epoch&format=json" | pj '
for s in d:
    if int(s.get("end_epoch") or 0) < int(sys.argv[1]): print(s["id"])' "$cutoff" | while read -r id; do
      [ -n "$id" ] && ix DELETE "/_snapshot/$SNAP_REPO/$id" >/dev/null && say "pruned snapshot $id"
    done
  fi
  es_snapshot_prune "$(date -d "-${keep} days" +%s)"
  ok "backup $stamp done (keeping $keep days)"
}
cmd_backup() {
  local sub="${1:-run}"; shift || true
  case "$sub" in
    run|now)  take_lock; backup_run ;;
    register) take_lock; snapshot_register && ok "snapshot repository '$SNAP_REPO' registered" || die "failed (is the indexer up?)" ;;
    list|ls)
      hdr "Indexer snapshots"
      if [ "$(ix_code)" = 200 ]; then ix GET "/_cat/snapshots/$SNAP_REPO?v&h=id,status,start_time,duration,indices,total_shards"; else warn "indexer unreachable"; fi
      if soc_elk && [ "$(es_code "/_snapshot/$ES_SNAP_REPO")" = 200 ]; then
        hdr "Elasticsearch snapshots"
        es_curl GET "/_cat/snapshots/$ES_SNAP_REPO?v&h=id,status,start_time,duration,indices" 2>/dev/null
      fi
      hdr "Config / manager backups ($(backup_dir)/config)"
      ls -1t "$(backup_dir)/config" 2>/dev/null | head -n 40 | sed 's/^/  /'
      hint "restore: vexor backup restore-snapshot <id> | restore-manager <stamp> | restore-config <file>" ;;
    restore-snapshot)
      local snap="${1:-}" idx="wazuh-alerts-*,wazuh-archives-*" rename=0; shift || true
      while [ $# -gt 0 ]; do case "$1" in --indices) idx="${2:?}"; shift ;; --rename) rename=1 ;; esac; shift; done
      [ -n "$snap" ] || die "usage: vexor backup restore-snapshot <snapshot-id> [--indices 'wazuh-alerts-4.x-2026.10.*'] [--rename]"
      [ "$rename" = 1 ] || warn "indices that already exist and are open will make the restore fail - use --rename to restore as restored-<name>"
      confirm "Restore $idx from $snap?" || die "Aborted"
      take_lock
      local body; body="$(python3 -I -c 'import json,sys
b={"indices":sys.argv[1],"ignore_unavailable":True,"include_global_state":False,"include_aliases":False}
if sys.argv[2]=="1": b.update(rename_pattern="(.+)", rename_replacement="restored-$1")
print(json.dumps(b))' "$idx" "$rename")"
      ix POST "/_snapshot/$SNAP_REPO/$snap/_restore?wait_for_completion=true" --max-time 7200 -d "$body" | pretty ;;
    restore-es)
      soc_elk || die "ELK is off (SOC=$(soc))"
      local snap="${1:-}" idx="vexor-*" rename=0 kib=0; shift || true
      while [ $# -gt 0 ]; do case "$1" in --indices) idx="${2:?}"; shift ;; --rename) rename=1 ;; --kibana) kib=1 ;; esac; shift; done
      [ -n "$snap" ] || die "usage: vexor backup restore-es <es-snap-id> [--indices 'vexor-zeek-*'] [--rename] [--kibana]   (ids: vexor backup list)"
      [ "$rename" = 1 ] || warn "open indices with the same name make the restore fail - use --rename to restore as restored-<name>"
      confirm "Restore $idx$( [ "$kib" = 1 ] && echo ' and the Kibana saved objects') from $snap?" || die "Aborted"
      take_lock
      local body; body="$(python3 -I -c 'import json,sys
b={"indices":sys.argv[1],"ignore_unavailable":True,"include_global_state":False,"include_aliases":False}
if sys.argv[2]=="1": b.update(rename_pattern="(.+)", rename_replacement="restored-$1")
b["feature_states"]=["kibana"] if sys.argv[3]=="1" else ["none"]
print(json.dumps(b))' "$idx" "$rename" "$kib")"
      es_curl POST "/_snapshot/$ES_SNAP_REPO/$snap/_restore?wait_for_completion=true" --max-time 7200 -d "$body" | pretty ;;
    restore-manager)
      local stamp="${1:-}" dir f vol; dir="$(backup_dir)/config"
      [ -n "$stamp" ] || die "usage: vexor backup restore-manager <stamp>   (e.g. 20261015-013000, see: vexor backup list)"
      ls "$dir"/*-"$stamp".tar.gz >/dev/null 2>&1 || die "no backups with stamp $stamp in $dir"
      confirm_word RESTORE "Overwrites the master's agent keys, rules, decoders, groups and API config with backup $stamp." || die "Aborted"
      take_lock
      dc stop wazuh.master
      for vol in "${MASTER_STATE_VOLUMES[@]}"; do
        f="$dir/${vol}-${stamp}.tar.gz"; [ -f "$f" ] || continue
        vol_restore_raw "$(project)_${vol}" "$f" && ok "restored $vol"
      done
      dc up -d wazuh.master && ok "master restarted" ;;
    restore-config)
      local file="${1:-}"; [ -f "$file" ] || die "usage: vexor backup restore-config <stack-config-STAMP.tar.gz>"
      confirm_word RESTORE "Overwrites .env, config/ (incl. certificates) and docker-compose.yml with $file." || die "Aborted"
      take_lock
      local pre; pre="$(backup_dir)/config/stack-config-pre-restore-$(date +%Y%m%d-%H%M%S).tar.gz"
      tar czf "$pre" -C "$ROOT" config .env docker-compose.yml && chmod 600 "$pre" && ok "current config saved to $pre"
      tar xzf "$file" -C "$ROOT" --exclude=vexor --exclude=lib && ok "config restored - apply with: vexor restart" ;;
    *) die "usage: vexor backup [run]|list|register|restore-snapshot|restore-manager|restore-config" ;;
  esac
}

# ============================================================== volumes
vol_full() { case "$1" in "$(project)"_*) echo "$1" ;; *) echo "$(project)_$1" ;; esac; }
vol_users() { docker ps -a --filter "volume=$1" --format '{{.Names}}' 2>/dev/null | tr '\n' ' '; }
vol_restore_raw() {
  docker run --rm -v "$1:/data" -v "$(dirname "$2"):/backup:ro" "$ALPINE_IMAGE" \
    sh -c 'find /data -mindepth 1 -delete && tar xzf "/backup/$1" -C /data' _ "$(basename "$2")"
}
project_volumes() { docker volume ls -q --filter "label=com.docker.compose.project=$(project)" 2>/dev/null | sort; }
# ---- disks Docker uses (vexor disk, install/doctor checks) ----
disk_paths() {                 # role<TAB>path of everything Docker or Vexor writes to
  local v mp
  printf 'docker\t%s\n' "$(docker_root)"
  [ -d /var/lib/containerd ] && printf 'images\t%s\n' /var/lib/containerd      # containerd image store (Docker 29+ default)
  mp="$(project_volumes | xargs -r docker volume inspect -f '{{.Mountpoint}}' 2>/dev/null)"
  for v in $mp; do printf 'volumes\t%s\n' "$v"; done
  printf 'volumes\t%s\n' "$(docker_root)/volumes"
  printf 'backups\t%s\n' "$(backup_dir)"
  printf 'checkout\t%s\n' "$ROOT"
}
disk_rows() {                  # disk_rows tsv|json: one row per filesystem (df -P), roles merged
  disk_paths | python3 -I -c '
import json, os, subprocess, sys
fmt = sys.argv[1]
rows, order = {}, []
for line in sys.stdin:
    role, _, path = line.rstrip("\n").partition("\t")
    while path and not os.path.exists(path):      # a path that does not exist yet (backups/) -> its parent
        path = os.path.dirname(path)
    if not path:
        continue
    try:
        out = subprocess.run(["df", "-P", "-B1", "--", path], capture_output=True, text=True, check=True).stdout.splitlines()[1]
    except (subprocess.CalledProcessError, IndexError, OSError):
        continue
    f = out.split(None, 5)
    if len(f) < 6:
        continue
    mount = f[5]
    if mount not in rows:
        rows[mount] = {"mount": mount, "size": int(f[1]), "used": int(f[2]), "avail": int(f[3]), "pct": int(f[4].rstrip("%") or 0), "roles": []}
        order.append(mount)
    if role not in rows[mount]["roles"]:
        rows[mount]["roles"].append(role)
res = [rows[m] for m in order]
if fmt == "json":
    print(json.dumps({"filesystems": res}))
else:
    for r in res:
        print("\t".join(str(x) for x in (r["mount"], r["size"], r["used"], r["avail"], r["pct"], ",".join(r["roles"]))))
' "$1"
}
hum() {                        # bytes -> 12.3 GB
  python3 -I -c '
import sys
n = float(sys.argv[1] or 0)
for u in ("B", "KB", "MB", "GB", "TB"):
    if n < 1024 or u == "TB":
        print("%d %s" % (n, u) if u == "B" else "%.1f %s" % (n, u)); break
    n /= 1024' "$1"
}
disk_preflight() {             # disk_preflight [quiet]: every disk Docker uses must have free space (install refuses; start only warns)
  local quiet="${1:-}" warn_gb min_gb mount size used avail pct roles gb bad_n=0
  warn_gb="$(env_def DISK_WARN_FREE_GB 15)"; min_gb="$(env_def DISK_MIN_FREE_GB 5)"
  while IFS=$'\t' read -r mount size used avail pct roles; do
    gb=$(( avail / 1073741824 ))
    if [ "$gb" -lt "$min_gb" ]; then bad "disk $mount ($roles): ${gb} GB free, at least ${min_gb} GB needed"; bad_n=1
    elif [ "$gb" -lt "$warn_gb" ]; then warn "disk $mount ($roles): ${gb} GB free - ${warn_gb} GB or more is recommended (images, indexers; the Wazuh vulnerability feed alone needs about 13 GB per manager)"
    elif [ "$quiet" != quiet ]; then ok "disk $mount ($roles): ${gb} GB free"; fi
  done < <(disk_rows tsv)
  if [ "$bad_n" = 1 ]; then
    hint "free space, move Docker's data root, or set WAZUH_VULN_DETECTION=false (saves about 13 GB per manager); vexor disk shows every disk"
    [ "$quiet" = quiet ] && return 0
    [ "${INSTALL_FORCE:-0}" = 1 ] && { warn "continuing because of --force"; return 0; }
    die "not enough free disk space (override with: vexor install --force)"
  fi
  return 0
}
cmd_disk() {
  local json=0 a; for a in "$@"; do case "$a" in --json) json=1 ;; *) die "usage: vexor disk [--json]" ;; esac; done
  docker_ok || die "Docker daemon is not running"
  if [ "$json" = 1 ]; then disk_rows json; return 0; fi
  local mount size used avail pct roles warn_pct fail_pct col
  warn_pct="$(env_def DISK_WARN_PCT 85)"; fail_pct="$(env_def DISK_FAIL_PCT 95)"
  hdr "Filesystems Docker and Vexor use"
  printf '  %-26s %9s %9s %9s %5s  %s\n' MOUNT SIZE USED AVAIL USE% USES
  while IFS=$'\t' read -r mount size used avail pct roles; do
    col=""; [ "$pct" -ge "$warn_pct" ] && col="$C_Y"; [ "$pct" -ge "$fail_pct" ] && col="$C_R"
    printf '  %-26s %9s %9s %9s %s%4s%%%s  %s\n' "$mount" "$(hum "$size")" "$(hum "$used")" "$(hum "$avail")" "$col" "$pct" "$C_0" "$roles"
  done < <(disk_rows tsv)
  local vb=0 mp b ib=0 ref
  for mp in $(project_volumes | xargs -r docker volume inspect -f '{{.Mountpoint}}' 2>/dev/null); do
    b="$(du -sb "$mp" 2>/dev/null | cut -f1)"; vb=$(( vb + ${b:-0} ))
  done
  for ref in $(dc_all config --images 2>/dev/null | sort -u); do
    b="$(docker image inspect -f '{{.Size}}' "$ref" 2>/dev/null)"; ib=$(( ib + ${b:-0} ))
  done
  hdr "Vexor's own data (project $(project))"
  say "volumes: $(project_volumes | wc -l) volume(s), $(hum "$vb")      (vexor volumes ls | orphans)"
  say "images : $(hum "$ib") for the configured versions      (vexor images prune removes old versions)"
  say "roles: docker = Docker root dir, images = containerd store, volumes = volume data, backups = BACKUP_DIR, checkout = this folder"
  say "The Wazuh vulnerability feed needs about 13 GB per manager: WAZUH_VULN_DETECTION=false turns it off."
}
# ---- unused volumes / old images ----
volume_report() {              # TSV volume<TAB>orphan|tool<TAB>reason - project volumes no service of the current layout uses
  local cur="$RUN_TMP/cfg.cur.json" all="$RUN_TMP/cfg.all.json"
  dc config --format json > "$cur" 2>/dev/null && dc_all config --format json > "$all" 2>/dev/null || return 1
  python3 -I - "$cur" "$all" "$(project_volumes | tr '\n' ' ')" "${TOOLS[*]}" "$(node_type)" <<'PY'
import json, sys
cur, allc, vols, tools, ntype = json.load(open(sys.argv[1])), json.load(open(sys.argv[2])), sys.argv[3].split(), set(sys.argv[4].split()), sys.argv[5]
def users(cfg):
    top = cfg.get("volumes") or {}
    m = {}
    for svc, d in (cfg.get("services") or {}).items():
        for v in d.get("volumes") or []:
            if v.get("type") == "volume" and v.get("source"):
                name = (top.get(v["source"]) or {}).get("name") or v["source"]
                m.setdefault(name, set()).add(svc)
    return m
used, known = users(cur), users(allc)
for v in vols:
    if v in used:
        continue
    owners = sorted(known.get(v, []))
    if not owners:
        print(f"{v}\torphan\tno service in the configuration uses it")
    elif set(owners) <= tools:
        print(f"{v}\ttool\t{' '.join(owners)} is switched off (data kept)")
    else:
        print(f"{v}\torphan\t{' '.join(owners)} not used with node type {ntype} / this SOC")
PY
}
volume_orphans() {             # TSV volume<TAB>bytes<TAB>reason<TAB>users - volumes nothing in the current layout uses (tool data excluded)
  local v kind why mp b
  volume_report > "$RUN_TMP/volrep" || return 1
  while IFS=$'\t' read -r v kind why; do
    [ "$kind" = orphan ] || continue
    mp="$(docker volume inspect -f '{{.Mountpoint}}' "$v" 2>/dev/null)"; b="$(du -sb "$mp" 2>/dev/null | cut -f1)"
    printf '%s\t%s\t%s\t%s\n' "$v" "${b:-0}" "$why" "$(vol_users "$v")"
  done < "$RUN_TMP/volrep"
}
volumes_orphans_cmd() {        # vexor volumes orphans: list; returns 0 and sets nothing else
  local rows v b why users total=0
  rows="$(volume_orphans)" || die "cannot read the compose configuration (vexor config validate)"
  [ -n "$rows" ] || { ok "no unused volumes: every volume of project $(project) belongs to a service of the current layout"; return 0; }
  printf '  %-44s %10s  %s\n' VOLUME SIZE WHY
  while IFS=$'\t' read -r v b why users; do
    printf '  %-44s %10s  %s%s\n' "$v" "$(hum "$b")" "$why" "${users:+  [in use by container: ${users% }]}"
    total=$(( total + b ))
  done <<<"$rows"
  say "$(wc -l <<<"$rows") unused volume(s), $(hum "$total") - remove with: vexor volumes prune"
}
volumes_prune_cmd() {
  local rows v b why users total=0 cand=()
  rows="$(volume_orphans)" || die "cannot read the compose configuration (vexor config validate)"
  while IFS=$'\t' read -r v b why users; do
    [ -n "$v" ] || continue
    if [ -n "${users// /}" ]; then warn "skipping $v: used by container ${users% } (vexor down first)"; continue; fi
    printf '  %-44s %10s  %s\n' "$v" "$(hum "$b")" "$why"
    cand+=("$v"); total=$(( total + b ))
  done <<<"$rows"
  [ ${#cand[@]} -gt 0 ] || { ok "nothing to prune"; return 0; }
  confirm_word DELETE "Permanently deletes the ${#cand[@]} unused volume(s) above ($(hum "$total")). Only volumes of project $(project) are touched." || die "Aborted"
  take_lock
  docker volume rm "${cand[@]}" >/dev/null && ok "removed ${#cand[@]} volume(s), freed about $(hum "$total")"
}
image_prune_candidates() {     # TSV ref<TAB>id<TAB>size - old versions of the stack's images: not configured now, not used by a container
  local keep keepids usedids repos
  keep="$(dc_all config --images 2>/dev/null | sort -u)"; [ -n "$keep" ] || return 1
  keepids="$(echo "$keep" | xargs -r docker image inspect -f '{{.Id}}' 2>/dev/null)"
  usedids="$(docker ps -aq --no-trunc 2>/dev/null | xargs -r docker inspect -f '{{.Image}}' 2>/dev/null)"
  repos="$(echo "$keep" | sed -E 's/@.*$//; s#:[^:/]*$##' | sort -u)"
  docker images --no-trunc --format '{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}' 2>/dev/null \
    | python3 -I -c '
import sys
repos, keep, keepids, usedids = (set(x.split()) for x in sys.argv[1:5])
for line in sys.stdin:
    repo, tag, iid, size = line.rstrip("\n").split("\t")
    if repo not in repos or tag == "<none>" or f"{repo}:{tag}" in keep or iid in keepids or iid in usedids:
        continue
    print(f"{repo}:{tag}\t{iid}\t{size}")' "$repos" "$keep" "$keepids" "$usedids"
}
images_prune() {
  docker_ok || die "Docker daemon is not running"
  local cand n ref id size
  cand="$(image_prune_candidates)" || die "cannot read the compose configuration (vexor config validate)"
  [ -n "$cand" ] || { ok "no old image versions to remove"; return 0; }
  printf '  %-60s %s\n' IMAGE SIZE
  while IFS=$'\t' read -r ref id size; do printf '  %-60s %s\n' "$ref" "$size"; done <<<"$cand"
  n="$(wc -l <<<"$cand")"
  confirm "Remove these $n old image(s) of the Vexor stack (configured versions and images used by containers are kept)?" || { say "kept"; return 0; }
  while IFS=$'\t' read -r ref id size; do
    if docker image rm "$ref" >/dev/null 2>&1; then say "removed $ref"; else warn "could not remove $ref (in use?)"; fi
  done <<<"$cand"
  ok "old images removed"
}
images_prune_offer() {         # end of an upgrade: ask on a tty only
  [ "$ASSUME_YES" = 0 ] && [ -t 0 ] || return 0
  local n; n="$(image_prune_candidates 2>/dev/null | wc -l)"
  [ "$n" -gt 0 ] || return 0
  say "$n old image version(s) of the stack are no longer used"
  images_prune
}
cmd_images() {
  case "${1:-}" in
    prune) take_lock; images_prune ;;
    *) die "usage: vexor images prune [--yes]   (removes old image versions of this stack after an upgrade)" ;;
  esac
}
cmd_volumes() {
  local sub="${1:-ls}"; shift || true
  case "$sub" in
    ls|list)
      printf '  %-44s %9s  %s\n' VOLUME SIZE "USED BY"
      local v mp
      for v in $(project_volumes); do
        mp="$(docker volume inspect -f '{{.Mountpoint}}' "$v")"
        printf '  %-44s %9s  %s\n' "$v" "$(du -sh "$mp" 2>/dev/null | cut -f1)" "$(vol_users "$v")"
      done
      hint "location: $(docker_root)/volumes" ;;
    backup)
      local target="${1:-}" stop=0 out stamp v vols=(); shift || true
      while [ $# -gt 0 ]; do case "$1" in --stop) stop=1 ;; --out) out="${2:?}"; shift ;; esac; shift; done
      [ -n "$target" ] || die "usage: vexor volumes backup <volume|all> [--stop] [--out DIR]"
      take_lock
      stamp="$(date +%Y%m%d-%H%M%S)"; out="${out:-$(backup_dir)/volumes/$stamp}"; mkdir -p "$out"
      if [ "$target" = all ]; then mapfile -t vols < <(project_volumes); else vols=("$(vol_full "$target")"); fi
      if [ "$stop" = 0 ] && running_services | has .; then
        warn "containers are running: indexer data copied live may be inconsistent (use --stop, or 'vexor backup' for snapshots)"
      fi
      [ "$stop" = 1 ] && { touch "$STATE_DIR/stopped"; dc_all stop; }
      for v in "${vols[@]}"; do
        docker volume inspect "$v" >/dev/null 2>&1 || { bad "no such volume $v"; continue; }
        docker run --rm -v "$v:/data:ro" -v "$out:/backup" "$ALPINE_IMAGE" tar czf "/backup/$v.tar.gz" -C /data . \
          && ok "$v -> $out/$v.tar.gz ($(du -h "$out/$v.tar.gz" | cut -f1))"
      done
      chmod 600 "$out"/*.tar.gz 2>/dev/null
      [ "$stop" = 1 ] && { rm -f "$STATE_DIR/stopped"; dc up -d >/dev/null && ok "stack started again"; } ;;
    restore)
      local v f users; v="$(vol_full "${1:-}")"; f="${2:-}"
      [ -n "${1:-}" ] && [ -f "$f" ] || die "usage: vexor volumes restore <volume> <file.tar.gz>"
      users="$(vol_users "$v")"
      confirm_word RESTORE "Replaces all content of $v with $f${users:+ (stops: $users)}." || die "Aborted"
      take_lock
      local c; for c in $users; do docker stop "$c" >/dev/null; done
      docker volume inspect "$v" >/dev/null 2>&1 || docker volume create --label "com.docker.compose.project=$(project)" "$v" >/dev/null
      vol_restore_raw "$v" "$(readlink -f "$f")" && ok "restored $v"
      for c in $users; do docker start "$c" >/dev/null; done ;;
    rm|remove)
      local v users; v="$(vol_full "${1:-}")"; [ -n "${1:-}" ] || die "usage: vexor volumes rm <volume>"
      users="$(vol_users "$v")"; [ -z "$users" ] || die "$v is used by: $users (stop/remove those first)"
      confirm_word DELETE "Permanently deletes volume $v." || die "Aborted"
      docker volume rm "$v" && ok "removed $v" ;;
    orphans|unused) volumes_orphans_cmd ;;
    prune) volumes_prune_cmd ;;
    *) die "usage: vexor volumes ls | orphans | backup <vol|all> [--stop] [--out DIR] | restore <vol> <file> | rm <vol> | prune [--yes]" ;;
  esac
}

