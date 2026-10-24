# shellcheck shell=bash
# vexor lib/07-certs.sh - certificates (local CA, Let's Encrypt, internal certs)
# Sourced by ./vexor in a fixed order (see the loader there); not executable on its own.
# ============================================================== certificates
cert_days_left() {
  local end; end="$(openssl x509 -enddate -noout -in "$1" 2>/dev/null | cut -d= -f2)" || return 0
  [ -n "$end" ] && echo $(( ($(date -d "$end" +%s) - $(date +%s)) / 86400 ))
}
cert_sans() { openssl x509 -noout -ext subjectAltName -in "$1" 2>/dev/null | tail -n +2 | tr ',' '\n' | sed 's/^ *//'; }
cert_covers() { cert_sans "$1" | has -ixF -e "IP Address:$2" -e "DNS:$2"; }   # cert_covers <cert> <name-or-ip>
cert_fp() { openssl x509 -noout -fingerprint -sha256 -in "$1" 2>/dev/null | cut -d= -f2; }
served_fp() {
  echo | timeout 5 openssl s_client -connect "$(local_ip):$(env_def PROXY_PORT 8080)" -servername "$(public_host)" 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2
}
proxy_cert_path() { local p; p="$(env_get PROXY_CERT)"; abspath "${p:-./config/wazuh_indexer_ssl_certs/wazuh.dashboard.pem}"; }
cert_default_names() {
  { public_host; host_ips; hostname -s 2>/dev/null; hostname -f 2>/dev/null; echo localhost; echo 127.0.0.1
    env_get CERT_EXTRA_SANS | tr ', ' '\n\n'; } | sed '/^$/d' | awk '!seen[$0]++'
}
san_string() {
  local n out=() re_ip='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
  for n in "$@"; do
    if [[ "$n" =~ $re_ip ]] || [[ "$n" == *:* ]]; then out+=("IP:$n"); else out+=("DNS:$n"); fi
  done
  local IFS=,; echo "${out[*]}"
}
local_ca_ensure() {            # the local CA (config/nginx/certs/ca.pem, 10 years): created once, then kept
  local ca="$PROXY_CERT_DIR/ca.pem" cakey="$PROXY_CERT_DIR/ca-key.pem"
  mkdir -p "$PROXY_CERT_DIR"; chmod 700 "$PROXY_CERT_DIR"
  if [ ! -s "$ca" ] || [ ! -s "$cakey" ]; then
    openssl req -x509 -new -nodes -newkey rsa:4096 -sha256 -days 3650 -keyout "$cakey" -out "$ca" \
      -subj "/O=Wazuh Stack/CN=Wazuh Local CA ($(hostname -s 2>/dev/null))" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -addext "subjectKeyIdentifier=hash" >/dev/null 2>&1 || { bad "CA creation failed"; return 1; }
    chmod 600 "$cakey"
    ok "local CA created (10 years): $ca"
  fi
}
local_ca_sign() {              # local_ca_sign <cert-out> <key-out> <days> <name ..>: new key + cert from the local CA (cert file = cert + CA)
  local out="$1" keyout="$2" days="$3" tmp ca="$PROXY_CERT_DIR/ca.pem"; shift 3
  tmp="$(mktemp -d "${RUN_TMP:-/tmp}/sign.XXXXXX")"
  cat > "$tmp/ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=$(san_string "$@")
EOF
  openssl req -new -nodes -newkey rsa:2048 -sha256 -keyout "$tmp/key.pem" -out "$tmp/req.csr" \
      -subj "/O=Wazuh Stack/CN=$1" >/dev/null 2>&1 \
    && openssl x509 -req -in "$tmp/req.csr" -CA "$ca" -CAkey "$PROXY_CERT_DIR/ca-key.pem" -CAserial "$PROXY_CERT_DIR/ca.srl" -CAcreateserial \
      -days "$days" -sha256 -extfile "$tmp/ext" -out "$tmp/crt.pem" >/dev/null 2>&1 \
    || { rm -rf "$tmp"; bad "certificate signing failed"; return 1; }
  cat "$tmp/crt.pem" "$ca" > "$out"
  install -m 600 "$tmp/key.pem" "$keyout"
  rm -rf "$tmp"
}
cert_issue_local() {           # cert_issue_local [name ...]  - local CA (kept) + new server cert
  local names=() days ca
  if [ $# -gt 0 ]; then names=("$@"); else mapfile -t names < <(cert_default_names); fi
  days="$(env_def CERT_DAYS 397)"; ca="$PROXY_CERT_DIR/ca.pem"
  local_ca_ensure || return 1
  local_ca_sign "$PROXY_CERT_DIR/server.pem" "$PROXY_CERT_DIR/server-key.pem" "$days" "${names[@]}" || return 1
  install -m 644 "$ca" "$PROXY_CERT_DIR/ca.crt"
  openssl x509 -in "$ca" -outform der -out "$PROXY_CERT_DIR/ca.cer"
  env_set PROXY_CERT ./config/nginx/certs/server.pem
  env_set PROXY_KEY ./config/nginx/certs/server-key.pem
  env_set PROXY_CERT_MODE local
  ok "dashboard certificate for: ${names[*]}  ($days days)"
}
apply_proxy_cert() {           # nginx serves PROXY_CERT (dashboard + tools) in both node types
  local svc; svc="$(proxy_svc)"
  if ! is_running "$svc"; then say "$svc not running - new certificate is used on next start"; return 0; fi
  dc up -d --no-deps --force-recreate "$svc" >/dev/null 2>&1 || { bad "$svc failed to start with the new certificate"; return 1; }
  sleep 2
  if [ "$(served_fp)" = "$(cert_fp "$(proxy_cert_path)")" ]; then ok "$svc now serves the new certificate"
  else warn "$svc restarted, but the served certificate differs - check: vexor logs $svc"; fi
}
ca_install_help() {
  local ip; ip="$(public_host)"
  cat <<EOF

  ${C_BD}Trust the CA once on every PC that opens the dashboard${C_0} (the warning then disappears):
    Copy it:   scp root@$ip:$PROXY_CERT_DIR/ca.crt .        (or: vexor cert serve-ca)

    Windows (Edge/Chrome)   admin PowerShell:  Import-Certificate -FilePath .\\ca.crt -CertStoreLocation Cert:\\LocalMachine\\Root
                            or double-click ca.cer -> Install -> Local Machine -> "Trusted Root Certification Authorities"
    macOS                   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt
    Ubuntu/Debian           sudo cp ca.crt /usr/local/share/ca-certificates/wazuh-local-ca.crt && sudo update-ca-certificates
    Firefox                 Settings -> Privacy & Security -> Certificates -> View -> Authorities -> Import ca.crt
    Domain-wide (AD)        Group Policy -> Public Key Policies -> Trusted Root Certification Authorities -> Import

  Then open:  https://$ip:$(env_def PROXY_PORT 8080)   (use a name/IP listed by: vexor cert status)
EOF
}
cmd_cert() {
  local sub="${1:-status}"; shift || true
  case "$sub" in
    status)
      local pc mode d; pc="$(proxy_cert_path)"; mode="$(cert_mode)"
      hdr "Dashboard certificate (port $(env_def PROXY_PORT 8080))  -  mode: $mode"
      if [ -f "$pc" ]; then
        printf '  %-10s %s\n' "file" "$pc"
        printf '  %-10s %s\n' "subject" "$(openssl x509 -noout -subject -in "$pc" | sed 's/^subject= *//')"
        printf '  %-10s %s\n' "issuer" "$(openssl x509 -noout -issuer -in "$pc" | sed 's/^issuer= *//')"
        printf '  %-10s %s\n' "names" "$(cert_sans "$pc" | tr '\n' ' ')"
        d="$(cert_days_left "$pc")"
        printf '  %-10s %s (%s days)\n' "expires" "$(openssl x509 -noout -enddate -in "$pc" | cut -d= -f2)" "$d"
        if is_running "$(proxy_svc)"; then
          [ "$(served_fp)" = "$(cert_fp "$pc")" ] && ok "$(proxy_svc) serves this certificate on port $(env_def PROXY_PORT 8080)" \
            || warn "$(proxy_svc) serves a different certificate (fix: vexor doctor --fix, or vexor cert renew --force)"
        fi
        cert_covers "$pc" "$(public_host)" || warn "PUBLIC_HOST=$(public_host)$([ -z "$(env_get PUBLIC_HOST)" ] && echo " (detected)") is not in the certificate names - vexor cert create"
        [ "$mode" = default ] && hint "self-signed for 'wazuh.dashboard': run vexor cert create to remove the browser warning"
      else
        bad "certificate file missing: $pc"
      fi
      hdr "Internal certificates ($INT_CERT_DIR)"
      local f
      for f in "$INT_CERT_DIR"/*.pem; do
        [ -f "$f" ] || continue; [[ "$f" == *-key.pem ]] && continue
        printf '  %-28s %s days\n' "$(basename "$f")" "$(cert_days_left "$f")"
      done ;;
    create|local)
      take_lock
      local names=("$@")
      [ ${#names[@]} -gt 0 ] || mapfile -t names < <(cert_default_names)
      hdr "Issuing a dashboard certificate from the local CA"
      say "Names: ${names[*]}"
      say "Add more with: vexor cert create <name-or-ip> ...   or CERT_EXTRA_SANS in .env"
      cert_issue_local "${names[@]}" && apply_proxy_cert && ca_install_help ;;
    export-ca)
      [ -f "$PROXY_CERT_DIR/ca.crt" ] || die "No local CA yet - run: vexor cert create"
      if [ -n "${1:-}" ]; then mkdir -p "$1"; cp "$PROXY_CERT_DIR/ca.crt" "$PROXY_CERT_DIR/ca.cer" "$1/"; ok "copied ca.crt + ca.cer to $1"; fi
      say "CA certificate: $PROXY_CERT_DIR/ca.crt  (PEM)   $PROXY_CERT_DIR/ca.cer  (DER, Windows)"
      say "SHA256 fingerprint: $(cert_fp "$PROXY_CERT_DIR/ca.crt")"
      ca_install_help ;;
    serve-ca)
      [ -f "$PROXY_CERT_DIR/ca.crt" ] || die "No local CA yet - run: vexor cert create"
      local port="${1:-8081}" dir="$RUN_TMP/ca-web"
      mkdir -p "$dir"; cp "$PROXY_CERT_DIR/ca.crt" "$PROXY_CERT_DIR/ca.cer" "$dir/"
      say "Download from another PC:  http://$(public_host):$port/ca.crt   (Windows: ca.cer)"
      say "Only the public CA certificate is served. Ctrl-C to stop."
      python3 -I -m http.server "$port" --bind "$(bind_ip)" --directory "$dir" ;;
    import)
      local crt="${1:-}" key="${2:-}" chain="${3:-}"
      [ -f "$crt" ] && [ -f "$key" ] || die "usage: vexor cert import <cert.pem> <key.pem> [chain.pem]"
      take_lock
      openssl x509 -noout -in "$crt" 2>/dev/null || die "$crt is not a PEM certificate"
      openssl pkey -noout -in "$key" 2>/dev/null || die "$key is not a PEM private key (must not be password protected)"
      [ "$(openssl x509 -noout -pubkey -in "$crt" | sha256sum)" = "$(openssl pkey -pubout -in "$key" 2>/dev/null | sha256sum)" ] \
        || die "certificate and key do not match"
      mkdir -p "$PROXY_CERT_DIR"; chmod 700 "$PROXY_CERT_DIR"
      cat "$crt" ${chain:+"$chain"} > "$PROXY_CERT_DIR/custom-fullchain.pem"
      install -m 600 "$key" "$PROXY_CERT_DIR/custom-key.pem"
      env_set PROXY_CERT ./config/nginx/certs/custom-fullchain.pem
      env_set PROXY_KEY ./config/nginx/certs/custom-key.pem
      env_set PROXY_CERT_MODE custom
      ok "imported (expires in $(cert_days_left "$crt") days; names: $(cert_sans "$crt" | tr '\n' ' '))"
      apply_proxy_cert ;;
    letsencrypt|le)
      local domain="${1:-}" email="" staging="" dns=0; shift || true
      while [ $# -gt 0 ]; do case "$1" in --email) email="${2:?}"; shift ;; --staging) staging="--staging" ;; --dns) dns=1 ;; esac; shift; done
      [ -n "$domain" ] || die "usage: vexor cert letsencrypt <domain> [--email you@x] [--staging] [--dns]"
      take_lock
      cert_letsencrypt "$domain" "$email" "$staging" "$dns" ;;
    renew)
      take_lock
      cert_renew "${1:-}" ;;
    use-default|default)
      take_lock
      env_unset PROXY_CERT; env_unset PROXY_KEY; env_set PROXY_CERT_MODE default
      ok "back to the built-in self-signed certificate"; apply_proxy_cert ;;
    internal-regen)
      confirm_word REGEN "Re-issues ALL internal node certificates and restarts the whole stack (old ones are kept in backups/)." || die "Aborted"
      take_lock
      local bk; bk="$(backup_dir)/certs-$(date +%Y%m%d-%H%M%S)"; mkdir -p "$(dirname "$bk")"
      dc_all stop
      mv "$INT_CERT_DIR" "$bk" && ok "old certificates moved to $bk"
      gen_internal_certs || { bad "generation failed - restoring old certificates"; rm -rf "$INT_CERT_DIR"; mv "$bk" "$INT_CERT_DIR"; dc up -d; exit 1; }
      run_step "Recreating all containers with the new certificates" dc up -d --force-recreate && wait_indexer 300 && wait_dashboard 240 ;;
    *) die "usage: vexor cert status|create|export-ca|serve-ca|import|letsencrypt|renew|use-default|internal-regen" ;;
  esac
}
cert_letsencrypt() {
  local domain="$1" email="$2" staging="$3" dns="$4" img="${LE_IMAGE:-certbot/certbot:latest}"
  local reg=(--register-unsafely-without-email); [ -n "$email" ] && reg=(-m "$email")
  hdr "Let's Encrypt certificate for $domain"
  say "By continuing you accept the Let's Encrypt Subscriber Agreement."
  mkdir -p "$LE_DIR"
  if [ "$dns" = 1 ]; then
    say "DNS-01: certbot will ask you to create a TXT record (works for servers not reachable from the internet)."
    docker run --rm -it -v "$LE_DIR:/etc/letsencrypt" "$img" certonly --manual --preferred-challenges dns \
      --agree-tos "${reg[@]}" $staging -d "$domain" || die "certbot failed"
  else
    port_listening 80 && die "Port 80 is in use - HTTP-01 needs it free (or use --dns)"
    say "HTTP-01: $domain must resolve to this server and port 80 must be reachable from the internet."
    docker run --rm -p 80:80 -v "$LE_DIR:/etc/letsencrypt" "$img" certonly --standalone --non-interactive \
      --agree-tos "${reg[@]}" $staging -d "$domain" || die "certbot failed (DNS record / port 80 forwarding?)"
  fi
  le_install "$domain" || die "issued, but files not found under $LE_DIR/live/$domain"
  env_set LE_DOMAIN "$domain"; [ -n "$email" ] && env_set LE_EMAIL "$email"
  env_set PUBLIC_HOST "$domain"
  ok "PUBLIC_HOST set to $domain"
  [ "$dns" = 1 ] && warn "manual DNS certificates cannot auto-renew - repeat this command before expiry (90 days)"
  apply_proxy_cert
}
le_install() {
  local live="$LE_DIR/live/$1"
  [ -f "$live/fullchain.pem" ] || return 1
  mkdir -p "$PROXY_CERT_DIR"; chmod 700 "$PROXY_CERT_DIR"
  cp -L "$live/fullchain.pem" "$PROXY_CERT_DIR/le-fullchain.pem"
  install -m 600 "$(readlink -f "$live/privkey.pem")" "$PROXY_CERT_DIR/le-key.pem"
  env_set PROXY_CERT ./config/nginx/certs/le-fullchain.pem
  env_set PROXY_KEY ./config/nginx/certs/le-key.pem
  env_set PROXY_CERT_MODE letsencrypt
}
cert_renew() {
  local force=0; [ "${1:-}" = "--force" ] && force=1
  local mode pc d; mode="$(cert_mode)"; pc="$(proxy_cert_path)"; d="$(cert_days_left "$pc")"
  case "$mode" in
    local)
      if [ "$force" = 1 ] || [ "${d:-0}" -lt 30 ]; then
        log "renewing local dashboard certificate ($d days left)"
        cert_issue_local && apply_proxy_cert
      else say "dashboard certificate valid for $d more days - nothing to do"; fi ;;
    letsencrypt)
      local domain; domain="$(env_get LE_DOMAIN)"
      if [ "$force" = 1 ] || [ "${d:-0}" -lt 30 ]; then
        log "renewing Let's Encrypt certificate for $domain ($d days left)"
        port_listening 80 && { bad "port 80 busy - cannot renew"; return 1; }
        local extra=(); [ "$force" = 1 ] && extra=(--force-renewal)
        docker run --rm -p 80:80 -v "$LE_DIR:/etc/letsencrypt" "${LE_IMAGE:-certbot/certbot:latest}" renew --standalone --non-interactive \
          "${extra[@]}" || { bad "certbot renew failed"; return 1; }
        le_install "$domain" && apply_proxy_cert
      else say "Let's Encrypt certificate valid for $d more days - nothing to do"; fi ;;
    custom)  [ "${d:-0}" -lt 30 ] && warn "custom dashboard certificate expires in $d days - import a new one" || say "custom certificate valid for $d days" ;;
    default) say "built-in self-signed certificate ($d days left) - nothing to renew" ;;
  esac
  local f fd
  for f in "$INT_CERT_DIR"/*.pem; do
    [[ "$f" == *-key.pem ]] && continue
    fd="$(cert_days_left "$f")"; [ -n "$fd" ] && [ "$fd" -lt 30 ] && warn "internal cert $(basename "$f") expires in $fd days - vexor cert internal-regen"
  done
  return 0
}

