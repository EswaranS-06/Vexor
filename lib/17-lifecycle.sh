# shellcheck shell=bash
# vexor lib/17-lifecycle.sh - reset, uninstall / fresh install, update
# Sourced by ./vexor in a fixed order (see the loader there); not executable on its own.
# ============================================================== reset
cmd_reset() {
  local level="${1:-}"; level="${level#--}"
  if [ -z "$level" ]; then
    [ -t 0 ] || die "usage: vexor reset containers|data|full|purge"
    cat <<EOF
  1) containers  remove containers + network; all data kept            (like: down)
  2) data        + delete ALL volumes: agents, alerts, indices, manager state
  3) full        + new certificates, passwords and cluster key (fresh install; local dashboard CA is kept)
  4) purge       + remove systemd units and Wazuh images (backups are never deleted)
EOF
    local a; read -r -p "  Choose 1-4: " a
    case "$a" in 1) level=containers ;; 2) level=data ;; 3) level=full ;; 4) level=purge ;; *) die "Aborted" ;; esac
  fi
  case "$level" in containers|data|full|purge) ;; *) die "usage: vexor reset containers|data|full|purge" ;; esac
  if [ "$level" = containers ]; then cmd_down; return; fi

  confirm_word DELETE "reset '$level' permanently deletes all Wazuh data on this host (agents, alerts, indices, manager rules)." || die "Aborted"
  take_lock
  if [ "$(ix_code)" = 200 ] && [ "$ASSUME_YES" = 0 ] && confirm "Take a backup first (recommended)?"; then backup_run; fi
  mkdir -p "$STATE_DIR"; touch "$STATE_DIR/stopped"
  hdr "Removing containers and volumes"
  dc_all down -v --remove-orphans
  local v left; left="$(project_volumes)"
  for v in $left; do docker volume rm "$v" >/dev/null 2>&1 && say "removed $v"; done
  # the next install bootstraps a new indexer cluster for NODE_TYPE in .env
  rm -f "$NODE_TYPE_FILE" "$NODE_SWITCH_FILE" "$STATE_DIR/indexer-cluster-excluded" "$STATE_DIR/indexer-replicas.saved"
  ok "data deleted (next install uses NODE_TYPE=$(desired_node_type) from .env)"

  if [ "$level" = full ] || [ "$level" = purge ]; then
    hdr "Resetting certificates, passwords, cluster key"
    local bk; bk="$(backup_dir)/reset-$(date +%Y%m%d-%H%M%S)"; mkdir -p "$bk"
    cp -a "$ENV_FILE" "$bk/.env"
    [ -d "$INT_CERT_DIR" ] && mv "$INT_CERT_DIR" "$bk/" && mkdir -p "$INT_CERT_DIR"
    cp -a "$INTERNAL_USERS" "$DASH_WAZUH_YML" "$bk/" 2>/dev/null
    local k; for k in INDEXER_PASSWORD DASHBOARD_PASSWORD API_PASSWORD; do env_set "$k" CHANGE_ME; done
    env_set AGENT_ENROLL_PASSWORD ""
    sed -i 's#<use_password>yes</use_password>#<use_password>no</use_password>#' "$CLUSTER_DIR/wazuh_manager.conf"
    ensure_cluster_key new >/dev/null
    rm -f "$STATE_DIR/passwords-applied" "$STATE_DIR/previous_version"
    ok "old .env + certificates saved in $bk"
  fi
  if [ "$level" = purge ]; then
    hdr "Purging"
    daemon_uninstall
    docker image rm "wazuh/wazuh-manager:$(cur_version)" "wazuh/wazuh-indexer:$(cur_version)" "wazuh/wazuh-dashboard:$(cur_version)" \
      "$(env_def NGINX_IMAGE nginx:stable)" wazuh/wazuh-certs-generator:0.0.4 2>/dev/null | sed 's/^/  /'
    ok "purged (backups kept in $(backup_dir))"
  fi
  rm -f "$STATE_DIR/stopped"
  say ""
  say "Start fresh with: ${C_BD}vexor install${C_0}"
}

# ============================================================== uninstall / fresh install
# Scoped to the compose projects $(project) and $(project)-certs (the certificate generator).
# Generated files are deleted only inside the checkout, and never when git tracks them.
LC_RUNTIME=(.env .state backups reports tools-data config/tools config/elk docker-compose.override.yml
            config/nginx/nginx.conf config/nginx/letsencrypt config/nginx/certs config/wazuh_indexer_ssl_certs
            config/nginx/routes.json config/nginx/routes-certs config/nginx/acme config/wazuh_custom)
LC_CONTAINERS=(); LC_NETWORKS=(); LC_VOLUMES=(); LC_IMAGES=(); LC_IMAGES_KEPT=(); LC_FILES=()
lc_projects() { echo "$(project) $(project)-certs"; }
lc_in() { local x="$1" y; shift; for y in "$@"; do [ "$x" = "$y" ] && return 0; done; return 1; }
lc_git() { git -c safe.directory="$ROOT" -C "$ROOT" "$@"; }
lc_git_mode() {                # git: spare tracked files | plain: no .git (tarball) | unsafe: .git that git cannot read
  if [ ! -e "$ROOT/.git" ]; then echo plain
  elif command -v git >/dev/null && lc_git rev-parse --git-dir >/dev/null 2>&1; then echo git
  else echo unsafe; fi
}
lc_runtime_paths() {           # lc_runtime_paths [--keep-backups]: generated paths that exist (relative to ROOT)
  local mode rel bd f list=(); mode="$(lc_git_mode)"
  [ "$mode" = unsafe ] && return 0
  for rel in "${LC_RUNTIME[@]}"; do [ "${1:-}" = --keep-backups ] && [ "$rel" = backups ] && continue; list+=("$rel"); done
  bd="$(backup_dir)"
  [ "${1:-}" != --keep-backups ] && [[ "$bd" == "$ROOT"/* ]] && list+=("${bd#"$ROOT"/}")
  for f in "$ROOT"/support-*.tar.gz; do [ -e "$f" ] && list+=("${f#"$ROOT"/}"); done
  for rel in $(printf '%s\n' "${list[@]}" | sort -u); do
    [ -e "$ROOT/$rel" ] || [ -L "$ROOT/$rel" ] || continue
    if [ "$mode" = git ]; then
      if [ -n "$(lc_git ls-files -- "$rel" | head -1)" ]; then
        lc_git ls-files -o -- "$rel"            # tracked content inside (.gitkeep): only untracked files go
      else echo "$rel"; fi
    elif [ -d "$ROOT/$rel" ] && [ -n "$(find "$ROOT/$rel" -name .gitkeep -print -quit)" ]; then
      (cd "$ROOT" && find "$rel" -type f ! -name .gitkeep)
    else echo "$rel"; fi
  done
}
lc_compose_images() {          # images the stack's compose files reference
  docker_ok || return 0
  { [ -f "$ENV_FILE" ] && dc_all config --images 2>/dev/null
    (cd "$ROOT" && docker compose -f "$CERTGEN_FILE" config --images 2>/dev/null); } | sort -u
}
lc_foreign_users() {           # names of containers outside our projects that use image $1
  local p n; docker ps -a --filter "ancestor=$1" --format '{{.Label "com.docker.compose.project"}}|{{.Names}}' 2>/dev/null \
    | while IFS='|' read -r p n; do lc_in "$p" "$(project)" "$(project)-certs" || printf '%s ' "$n"; done
}
lc_collect() {                 # lc_collect <volumes 0|1> <images 0|1> <files none|all|keep-backups>
  local want_vols="$1" want_imgs="$2" files="$3" p c v img users
  LC_CONTAINERS=(); LC_NETWORKS=(); LC_VOLUMES=(); LC_IMAGES=(); LC_IMAGES_KEPT=(); LC_FILES=()
  if docker_ok; then
    for p in $(lc_projects); do
      mapfile -t -O "${#LC_CONTAINERS[@]}" LC_CONTAINERS < <(docker ps -aq --filter "label=com.docker.compose.project=$p" 2>/dev/null)
      mapfile -t -O "${#LC_NETWORKS[@]}" LC_NETWORKS < <(docker network ls --filter "label=com.docker.compose.project=$p" --format '{{.Name}}' 2>/dev/null)
      [ "$want_vols" = 1 ] && mapfile -t -O "${#LC_VOLUMES[@]}" LC_VOLUMES < <(docker volume ls -q --filter "label=com.docker.compose.project=$p" 2>/dev/null)
    done
    if [ "$want_vols" = 1 ]; then   # + anonymous volumes that only our containers use
      for c in "${LC_CONTAINERS[@]}"; do
        for v in $(docker inspect -f '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}} {{end}}{{end}}' "$c" 2>/dev/null); do
          [[ "$v" =~ ^[0-9a-f]{64}$ ]] || continue
          lc_in "$v" "${LC_VOLUMES[@]}" && continue
          users="$(docker ps -a --filter "volume=$v" --format '{{.Label "com.docker.compose.project"}}' 2>/dev/null \
                   | while read -r p; do lc_in "$p" "$(project)" "$(project)-certs" || echo x; done)"
          [ -z "$users" ] && LC_VOLUMES+=("$v")
        done
      done
    fi
    if [ "$want_imgs" = 1 ]; then
      for img in $( { lc_compose_images; for c in "${LC_CONTAINERS[@]}"; do docker inspect -f '{{.Config.Image}}' "$c" 2>/dev/null; done; } | sort -u); do
        docker image inspect "$img" >/dev/null 2>&1 || continue
        users="$(lc_foreign_users "$img")"
        if [ -n "$users" ]; then LC_IMAGES_KEPT+=("$img (used by: ${users% })"); else LC_IMAGES+=("$img"); fi
      done
    fi
  fi
  case "$files" in
    all)          mapfile -t LC_FILES < <(lc_runtime_paths) ;;
    keep-backups) mapfile -t LC_FILES < <(lc_runtime_paths --keep-backups) ;;
  esac
}
lc_units() {                   # what `daemon install` wrote: units, completion, login message, PATH link
  local f
  for f in "$SYSTEMD_DIR/$UNIT.service" "$SYSTEMD_DIR/$UNIT"-*.service "$SYSTEMD_DIR/$UNIT"-*.timer \
           /etc/bash_completion.d/vexor /etc/update-motd.d/99-vexor; do [ -e "$f" ] && echo "$f"; done
  [ "$(readlink -f /usr/local/bin/vexor 2>/dev/null)" = "$SELF" ] && echo /usr/local/bin/vexor
  return 0
}
lc_size() { du -sh "$1" 2>/dev/null | cut -f1; }
lc_count() {                   # number of things lc_collect found, + units with $1=units
  local n=$(( ${#LC_CONTAINERS[@]} + ${#LC_NETWORKS[@]} + ${#LC_VOLUMES[@]} + ${#LC_IMAGES[@]} + ${#LC_FILES[@]} ))
  [ "${1:-}" = units ] && n=$(( n + $(lc_units | wc -l) ))
  echo "$n"
}
lc_plan() {                    # print what lc_collect found (+ units)
  local x mp units; units="$(lc_units)"
  if [ -n "$units" ]; then say "${C_BD}systemd units, PATH link, completion:${C_0}"; printf '%s\n' "$units" | sed 's/^/    /'; fi
  if [ ${#LC_CONTAINERS[@]} -gt 0 ]; then
    say "${C_BD}containers (${#LC_CONTAINERS[@]}):${C_0}"
    for x in "${LC_CONTAINERS[@]}"; do say "  $(docker inspect -f '{{.Name}}' "$x" 2>/dev/null | sed 's#^/##')"; done
  fi
  if [ ${#LC_NETWORKS[@]} -gt 0 ]; then say "${C_BD}networks:${C_0}"; for x in "${LC_NETWORKS[@]}"; do say "  $x"; done; fi
  if [ ${#LC_VOLUMES[@]} -gt 0 ]; then
    say "${C_BD}volumes (${#LC_VOLUMES[@]}) - agents, alerts, indices, tool data:${C_0}"
    for x in "${LC_VOLUMES[@]}"; do
      mp="$(docker volume inspect -f '{{.Mountpoint}}' "$x" 2>/dev/null)"
      say "  $(printf '%-56s %s' "$x" "$(lc_size "$mp")")"
    done
  fi
  if [ ${#LC_IMAGES[@]} -gt 0 ]; then say "${C_BD}images:${C_0}"; for x in "${LC_IMAGES[@]}"; do say "  $x"; done; fi
  if [ ${#LC_IMAGES_KEPT[@]} -gt 0 ]; then say "${C_BD}images kept:${C_0}"; for x in "${LC_IMAGES_KEPT[@]}"; do say "  $x"; done; fi
  if [ ${#LC_FILES[@]} -gt 0 ]; then
    say "${C_BD}files in $ROOT:${C_0}"
    for x in "${LC_FILES[@]}"; do say "  $(printf '%-56s %s' "$x" "$(lc_size "$ROOT/$x")")"; done
  fi
  return 0
}
lc_remove() {                  # remove what lc_collect found (units are separate)
  local x n
  if [ ${#LC_CONTAINERS[@]} -gt 0 ]; then
    n=0; for x in "${LC_CONTAINERS[@]}"; do docker rm -f "$x" >/dev/null 2>&1 && n=$((n + 1)); done
    ok "removed $n container(s)"
  fi
  if [ ${#LC_NETWORKS[@]} -gt 0 ]; then
    n=0; for x in "${LC_NETWORKS[@]}"; do if docker network rm "$x" >/dev/null 2>&1; then n=$((n + 1)); else warn "network $x not removed (in use?)"; fi; done
    ok "removed $n network(s)"
  fi
  if [ ${#LC_VOLUMES[@]} -gt 0 ]; then
    n=0; for x in "${LC_VOLUMES[@]}"; do if docker volume rm "$x" >/dev/null 2>&1; then n=$((n + 1)); else warn "volume $x not removed (in use?)"; fi; done
    ok "removed $n volume(s)"
  fi
  if [ ${#LC_IMAGES[@]} -gt 0 ]; then
    n=0
    for x in "${LC_IMAGES[@]}"; do
      if [ -n "$(lc_foreign_users "$x")" ]; then warn "image $x kept (used by another container now)"
      elif docker image rm "$x" >/dev/null 2>&1; then n=$((n + 1))
      else warn "image $x not removed"; fi
    done
    ok "removed $n image(s)"
  fi
  if [ ${#LC_FILES[@]} -gt 0 ]; then
    for x in "${LC_FILES[@]}"; do
      [ -n "$x" ] && [[ "$x" != /* && "$x" != *..* ]] || continue     # relative paths inside the checkout only
      rm -rf -- "${ROOT:?}/$x"
    done
    ok "removed ${#LC_FILES[@]} generated file(s)/folder(s)"
  fi
  return 0
}
cmd_uninstall() {
  local keep=0 imgs=0 a files=all bd
  for a in "$@"; do
    case "$a" in
      --keep-data) keep=1 ;;
      --images)    imgs=1 ;;
      *) die "usage: vexor uninstall [--keep-data] [--images] [--yes]" ;;
    esac
  done
  take_lock
  docker_ok || warn "Docker is not running: containers, networks, volumes and images are not checked"
  if [ "$keep" = 0 ] && [ "$(lc_git_mode)" = unsafe ]; then
    warn "$ROOT has .git but git cannot read it: generated files are kept (install git, or delete them by hand)"
  fi
  [ "$keep" = 1 ] && files=none
  lc_collect "$((1 - keep))" "$imgs" "$files"
  hdr "Uninstall Vexor (compose projects $(lc_projects | sed 's/ / and /'))"
  if [ "$(lc_count units)" = 0 ]; then ok "nothing to remove - already clean"; return 0; fi
  lc_plan
  say ""
  if [ "$keep" = 1 ]; then say "kept (--keep-data): volumes, .env, certificates, .state, backups"
  else
    say "${C_R}Volumes and generated files are deleted for good${C_0} (--keep-data keeps them)."
    bd="$(backup_dir)"; [[ "$bd" == "$ROOT"/* ]] || say "kept: backups in $bd (outside the checkout)"
  fi
  [ "$imgs" = 1 ] || say "images are kept (--images removes them)"
  say "never touched: other compose projects, git-tracked files, anything outside $ROOT"
  say ""
  confirm "Remove all of the above?" || die "Aborted"
  hdr "Removing"
  if [ -n "$(lc_units)" ]; then
    daemon_uninstall
    [ "$(readlink -f /usr/local/bin/vexor 2>/dev/null)" = "$SELF" ] && rm -f /usr/local/bin/vexor
    rm -f /etc/bash_completion.d/vexor /etc/update-motd.d/99-vexor
  fi
  lc_remove
  say ""
  if [ "$keep" = 1 ]; then ok "uninstalled; data kept - start again with: ${C_BD}vexor install${C_0}"
  else ok "uninstalled - reinstall any time with: ${C_BD}vexor install${C_0}"; fi
}
lc_existing() {                # what an earlier install left (one line each; empty = nothing)
  local n=0 p
  [ -f "$ENV_FILE" ] && echo ".env (passwords and settings)"
  [ -f "$INT_CERT_DIR/root-ca.pem" ] && echo "internal certificates ($INT_CERT_DIR)"
  [ -n "$(find "$PROXY_CERT_DIR" -type f ! -name .gitkeep -print -quit 2>/dev/null)" ] && echo "dashboard certificate ($PROXY_CERT_DIR)"
  [ -n "$(find "$STATE_DIR" -mindepth 1 -print -quit 2>/dev/null)" ] && echo "state ($STATE_DIR)"
  if docker_ok; then
    for p in $(lc_projects); do n=$(( n + $(docker volume ls -q --filter "label=com.docker.compose.project=$p" 2>/dev/null | wc -l) )); done
    [ "$n" -gt 0 ] && echo "$n Docker volume(s) of project $(project) (agents, alerts, indices)"
  fi
  return 0
}
lc_fresh() {                   # lc_fresh <0|1>: 1 = install --fresh; 0 = ask reuse/clean when a setup exists (tty only)
  local forced="$1" found a
  found="$(lc_existing)"
  [ -n "$found" ] || return 0
  if [ "$forced" = 0 ]; then
    [ -t 0 ] && [ "$ASSUME_YES" = 0 ] || return 0           # no tty or --yes: reuse, as before
    hdr "Existing setup found"
    printf '%s\n' "$found" | sed 's/^/    /'
    say "Reuse keeps passwords, certificates and data. Start clean deletes them (backups are kept)."
    read -r -p "  [R]euse (default) / start [c]lean: " a
    [[ "$a" =~ ^[cC] ]] || { ok "reusing the existing setup"; return 0; }
  else
    hdr "Fresh install: removing the existing setup"
    printf '%s\n' "$found" | sed 's/^/    /'
  fi
  [ "$(lc_git_mode)" = unsafe ] && die "$ROOT has .git but git cannot read it - install git, or delete the generated files by hand"
  # volumes go too: the indexers keep the old password hashes, which the new .env would not match
  lc_collect 1 0 keep-backups
  lc_plan
  confirm_word DELETE "Deletes the containers, volumes (agents, alerts, indices) and generated files above. Backups are kept." || die "Aborted"
  lc_remove
  ok "clean - continuing with a new install"
}

# ============================================================== update
latest_versions() {            # stable 4.x versions, newest first
  local out
  out="$(curl -fsSL --max-time 15 "https://api.github.com/repos/wazuh/wazuh-docker/releases?per_page=100" 2>/dev/null | python3 -I -c '
import json, re, sys
vs = set()
for r in json.load(sys.stdin):
    if r.get("draft") or r.get("prerelease"): continue
    m = re.fullmatch(r"v?(4)\.(\d+)\.(\d+)", r.get("tag_name", ""))
    if m: vs.add(tuple(map(int, m.groups())))
for v in sorted(vs, reverse=True): print("%d.%d.%d" % v)' 2>/dev/null)"
  if [ -z "$out" ]; then
    out="$(curl -fsSL --max-time 15 "https://hub.docker.com/v2/repositories/wazuh/wazuh-manager/tags?page_size=100&name=4." 2>/dev/null | python3 -I -c '
import json, re, sys
vs = {tuple(map(int, t["name"].split("."))) for t in json.load(sys.stdin).get("results", []) if re.fullmatch(r"4\.\d+\.\d+", t["name"])}
for v in sorted(vs, reverse=True): print("%d.%d.%d" % v)' 2>/dev/null)"
  fi
  printf '%s\n' "$out" | sed '/^$/d'
}
cmd_update() {
  local sub="${1:-check}"; shift || true
  case "$sub" in
    check)
      local cur latest newer; cur="$(cur_version)"
      say "Configured version : $cur"
      is_running wazuh.master && say "Running managers   : $(dc exec -T wazuh.master /var/ossec/bin/wazuh-control info -v 2>/dev/null | tr -d '\r')"
      latest="$(latest_versions)"
      [ -n "$latest" ] || die "Could not reach GitHub/Docker Hub to check versions"
      newer="$(awk -v c="$cur" 'BEGIN{split(c,a,".")} {split($0,b,"."); if (b[1]*1e6+b[2]*1e3+b[3] > a[1]*1e6+a[2]*1e3+a[3]) print}' <<<"$latest")"
      say "Latest stable 4.x  : $(head -1 <<<"$latest")"
      if [ -n "$newer" ]; then
        warn "Update available: $(tr '\n' ' ' <<<"$newer")"
        say "Release notes: https://github.com/wazuh/wazuh-docker/releases/tag/v$(head -1 <<<"$newer")"
        if [ -t 0 ] && [ "$ASSUME_YES" = 0 ] && confirm "Upgrade to $(head -1 <<<"$newer") now?"; then update_apply "$(head -1 <<<"$newer")"; fi
      else
        ok "Up to date"
      fi ;;
    apply|upgrade) update_apply "$@" ;;
    rollback)
      local prev; prev="$(cat "$STATE_DIR/previous_version" 2>/dev/null)"; [ -n "$prev" ] || die "No previous version recorded"
      warn "Rolling back to $prev. If the indexer already migrated its data to the newer version it may refuse to start;"
      warn "in that case restore indices from the snapshot taken before the upgrade (vexor backup list)."
      confirm "Roll back $(cur_version) -> $prev?" || die "Aborted"
      take_lock
      env_set WAZUH_VERSION "$prev"; rm -f "$STATE_DIR/previous_version"
      run_step "Stopping the stack" dc_all down && run_step "Starting on $prev" dc up -d && wait_indexer 300 && wait_dashboard 240 ;;
    images|pull)
      take_lock
      hdr "Re-pulling images for $(cur_version) + $(env_def NGINX_IMAGE nginx:stable)"
      PULL_ALL=1 pull_image_list $(dc config --images 2>/dev/null | sort -u) && run_step "Recreating containers where the image changed" dc up -d
      docker image prune -f >/dev/null
      images_prune_offer ;;
    *) die "usage: vexor update [check] | apply [VERSION|latest] [--no-backup] [--force] | rollback | images" ;;
  esac
}
update_apply() {
  local target="" force=0 nobackup=0 cur
  while [ $# -gt 0 ]; do case "$1" in --force) force=1 ;; --no-backup) nobackup=1 ;; *) target="$1" ;; esac; shift; done
  cur="$(cur_version)"
  if [ -z "$target" ] || [ "$target" = latest ]; then
    target="$(latest_versions | head -1)"
    [ -n "$target" ] || die "Could not determine the latest version - pass one: vexor update apply 4.14.9"
  fi
  target="${target#v}"
  [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Version must look like 4.14.9"
  [ "$target" = "$cur" ] && { ok "Already on $cur"; return 0; }
  if ver_gt "$cur" "$target" && [ "$force" = 0 ]; then
    die "Downgrade $cur -> $target is not supported by the indexer. Use 'update rollback' right after a failed upgrade, or --force."
  fi
  if [ "${target%%.*}" != 4 ] && [ "$force" = 0 ]; then
    die "$target is not 4.x. Major upgrades change the deployment layout - follow the official migration guide."
  fi
  hdr "Upgrade Wazuh $cur -> $target"
  say "Release notes: https://github.com/wazuh/wazuh-docker/releases/tag/v$target"
  [ "$(cut -d. -f1,2 <<<"$cur")" != "$(cut -d. -f1,2 <<<"$target")" ] && \
    warn "Minor version change: compare config/ with the v$target files in wazuh/wazuh-docker (multi-node/config) for new settings."
  confirm "Continue? The stack is down for a few minutes" || die "Aborted"
  take_lock
  hdr "Pulling images (before any downtime)"
  PULL_ALL=1 pull_image_list wazuh/wazuh-manager:$target wazuh/wazuh-indexer:$target wazuh/wazuh-dashboard:$target \
    || die "images wazuh/*:$target not available - see the output above"
  PULL_ALL=1 pull_image_list "$(env_def NGINX_IMAGE nginx:stable)" || warn "nginx image pull failed (keeping current)"
  if [ "$nobackup" = 0 ]; then
    if [ "$(ix_code)" = 200 ]; then backup_run || { confirm "Backup failed. Continue anyway?" || die "Aborted"; }
    else confirm "Indexer unreachable - continue WITHOUT a backup?" || die "Aborted"; fi
  fi
  mkdir -p "$STATE_DIR"; echo "$cur" > "$STATE_DIR/previous_version"
  env_set WAZUH_VERSION "$target"
  sed -i -E "s/(CERT_TOOL_VERSION=)[0-9.]+/\1$(cut -d. -f1,2 <<<"$target")/" "$CERTGEN_FILE"
  hdr "Restarting on $target"
  run_step "Stopping the stack" dc_all down && render_nginx && run_step "Starting on $target" dc up -d || die "start failed - roll back with: vexor update rollback"
  if wait_stack; then
    post_start
    ok "Upgraded to $target"
    is_running wazuh.master && dc exec -T wazuh.master /var/ossec/bin/cluster_control -l
    say "Agents can be upgraded from the dashboard (Agents -> Upgrade) or: vexor api PUT '/agents/upgrade?agents_list=all'"
    images_prune_offer
  else
    bad "Stack not healthy after upgrade - inspect: vexor doctor | roll back: vexor update rollback"
    return 1
  fi
}

