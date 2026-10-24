# shellcheck shell=bash
# vexor lib/08-proxy.sh - proxy routes (vexor proxy)
# Sourced by ./vexor in a fixed order (see the loader there); not executable on its own.
# ============================================================== proxy routes (vexor proxy)
# Named hosts (soc.example.com, 192.168.1.10) -> a Vexor service or something on this host / the LAN.
# Routes live in config/nginx/routes.json; render_nginx adds one server block per route on the
# ROUTES_HTTPS_PORT / ROUTES_HTTP_PORT listeners (published only while a route exists). Every change is
# tested with `nginx -t` before nginx reloads, and rolled back when the test fails.
ROUTE_TLS_MODES="local letsencrypt off"
routes_count() { local n=0; [ -s "$ROUTES_FILE" ] && n="$(grep -c '"host":' "$ROUTES_FILE" 2>/dev/null)"; echo "${n:-0}"; }
routes_https_port() { env_def ROUTES_HTTPS_PORT 443; }
routes_http_port() { env_def ROUTES_HTTP_PORT 80; }
is_ipv4() {
  local o='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
  [[ "$1" =~ ^$o\.$o\.$o\.$o$ ]]
}
proxy_valid_host() {           # proxy_valid_host <host>: lower-case DNS name with 2+ labels (no wildcard) or IPv4
  local h="$1" re_dn='^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$'
  [ -n "$h" ] && [ ${#h} -le 253 ] || return 1
  [ -z "$(printf '%s' "$h" | LC_ALL=C tr -d 'a-z0-9.-')" ] || return 1      # only these bytes reach nginx.conf
  is_ipv4 "$h" && return 0
  [[ "$h" =~ $re_dn ]]
}
proxy_valid_size() { [[ "$1" =~ ^[0-9]{1,5}[kmg]?$ ]]; }        # nginx client_max_body_size: 0 = no limit
proxy_https_default() {        # services that speak HTTPS on that port (a bare service:port then means https://)
  case "$1" in wazuh.dashboard:5601|portainer:9443|wazuh.master:55000|wazuh*.indexer:9200) return 0 ;; esac
  return 1
}
proxy_target() {               # proxy_target <target> -> "<kind> <upstream>"; kind = service | host | lan; 1 = invalid
  local t="${1,,}" scheme="" rest name port
  [ -z "$(printf '%s' "$t" | LC_ALL=C tr -d 'a-z0-9.:/_-')" ] || return 1
  case "$t" in http://*) scheme=http; rest="${t#http://}" ;; https://*) scheme=https; rest="${t#https://}" ;; *) rest="$t" ;; esac
  rest="${rest%/}"
  [[ "$rest" =~ ^([a-z0-9][a-z0-9._-]{0,62}):([0-9]{1,5})$ ]] || return 1
  name="${BASH_REMATCH[1]}"; port=$((10#${BASH_REMATCH[2]}))
  [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || return 1
  if [[ "$name" =~ ^(localhost|host|host\.docker\.internal)$ ]] || { is_ipv4 "$name" && [[ "$name" == 127.* ]]; }; then
    echo "host ${scheme:-http}://host.docker.internal:$port"
  elif is_ipv4 "$name"; then
    [ "$name" = 0.0.0.0 ] && return 1
    echo "lan ${scheme:-http}://$name:$port"
  elif [[ "$name" =~ ^[0-9.]+$ ]]; then
    return 1                                                   # 999.1.1.1 and friends
  else
    [ -z "$scheme" ] && { proxy_https_default "$name:$port" && scheme=https || scheme=http; }
    echo "service $scheme://$name:$port"
  fi
}
compose_services() { (cd "$ROOT" && PUBLIC_HOST="$(public_host)" COMPOSE_PROFILES='*' docker compose config --services 2>/dev/null); }   # every service, any profile
proxy_svc_ports() {            # service:port suggestions for the console / completion (enabled services only)
  local en; en=" $(enabled_services | tr '\n' ' ') "
  local s; for s in wazuh.dashboard:5601 kibana:5601 n8n:5678 grafana:3000 portainer:9443 elasticsearch:9200 wazuh.master:55000; do
    [[ "$en" == *" ${s%%:*} "* ]] && echo "$s"
  done
  return 0
}
routes_py() {                  # routes_py <op> [args]: the one place that reads/writes routes.json
  python3 -I - "$ROUTES_FILE" "$ROUTES_CERT_DIR" "$@" <<'PY'
import json, os, re, subprocess, sys, tempfile, time
path, certs, op, args = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
HOST = re.compile(r"^(?=.{1,253}$)(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)$")
UP = re.compile(r"^https?://[a-z0-9][a-z0-9._-]{0,62}:\d{1,5}$")
SIZE = re.compile(r"^\d{1,5}[kmg]?$")
IP = re.compile(r"^[0-9.]+$")
def load():
    try:
        d = json.load(open(path))
    except FileNotFoundError:
        return []
    except ValueError as e:
        sys.exit(f"routes file is not valid JSON: {path}: {e}")
    return [r for r in d.get("routes", []) if isinstance(r, dict)]
def sane(r):           # a hand-edited file must not inject anything into nginx.conf
    return (HOST.match(str(r.get("host", ""))) and UP.match(str(r.get("upstream", ""))) and SIZE.match(str(r.get("max_body", "")))
            and r.get("tls") in ("local", "letsencrypt", "off") and r.get("kind") in ("service", "host", "lan"))
def save(routes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".routes.", dir=os.path.dirname(path))
    with os.fdopen(fd, "w") as f:
        json.dump({"version": 1, "routes": sorted(routes, key=lambda r: r["host"])}, f, indent=2)
        f.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
def cert_of(h):
    return os.path.join(certs, h + ".pem"), os.path.join(certs, h + "-key.pem")
def cert_info(h):
    crt, key = cert_of(h)
    if not (os.path.isfile(crt) and os.path.isfile(key)):
        return {"exists": False}
    out = subprocess.run(["openssl", "x509", "-noout", "-enddate", "-issuer", "-ext", "subjectAltName", "-in", crt],
                         capture_output=True, text=True).stdout
    end = re.search(r"notAfter=(.*)", out)
    iss = re.search(r"issuer=\s*(.*)", out)
    sans = re.findall(r"(?:DNS|IP Address):([^,\s]+)", out)
    info = {"exists": True, "issuer": iss.group(1).strip() if iss else "", "names": sans}
    if end:
        t = subprocess.run(["date", "-d", end.group(1), "+%s"], capture_output=True, text=True).stdout.strip()
        if t.isdigit():
            info["expires"] = int(t)
            info["days"] = (int(t) - int(time.time())) // 86400
    info["covers"] = h in sans
    return info
routes = load()
if op == "tsv":                   # host target tls websocket max_body
    for r in routes:
        print("\t".join(str(r.get(k, "")) for k in ("host", "target", "tls", "websocket", "max_body")))
elif op == "get":
    m = [r for r in routes if r.get("host") == args[0]]
    if not m:
        sys.exit(1)
    print(json.dumps(m[0]))
elif op == "field":
    m = [r for r in routes if r.get("host") == args[0]]
    if not m:
        sys.exit(1)
    print(m[0].get(args[1], ""))
elif op == "put":                 # put host target kind upstream tls websocket(0|1) max_body
    h, target, kind, up, tls, ws, size = args
    old = next((r for r in routes if r.get("host") == h), {})
    r = {"host": h, "target": target, "kind": kind, "upstream": up, "tls": tls, "websocket": ws == "1", "max_body": size,
         "created": old.get("created", int(time.time())), "updated": int(time.time())}
    if not sane(r):
        sys.exit("refusing to store an invalid route")
    save([x for x in routes if x.get("host") != h] + [r])
elif op == "del":
    save([x for x in routes if x.get("host") != args[0]])
elif op == "render":              # nginx server blocks: render <https-port> <http-port>
    https_port, http_port = args[0], args[1]
    sfx = "" if https_port == "443" else ":" + https_port
    if not routes:
        sys.exit(0)
    good = [r for r in routes if sane(r)]
    for r in routes:
        if not sane(r):
            print(f"invalid route skipped: {r.get('host')!r}", file=sys.stderr)
    tls_ok = lambda r: r["tls"] != "off" and cert_info(r["host"])["exists"]
    ip_tls = [r for r in good if IP.match(r["host"]) and tls_ok(r)]
    default_crt = ("/etc/nginx/routes-certs/%s.pem" % ip_tls[0]["host"], "/etc/nginx/routes-certs/%s-key.pem" % ip_tls[0]["host"]) if ip_tls \
        else ("/etc/nginx/certs/proxy.pem", "/etc/nginx/certs/proxy-key.pem")
    acme = "        location /.well-known/acme-challenge/ { root /var/www/acme; default_type text/plain; }\n"
    print("    # ---- proxy routes (vexor proxy) - default servers: unknown host names get no answer (444)")
    print("    server {\n        listen 80 default_server;\n        server_name _;\n" + acme + "        location / { return 444; }\n    }")
    print("    server {\n        listen 443 ssl default_server;\n        server_name _;")
    print(f"        ssl_certificate     {default_crt[0]};\n        ssl_certificate_key {default_crt[1]};")
    print("        ssl_protocols       TLSv1.2 TLSv1.3;\n        return 444;\n    }")
    for r in good:
        h, up = r["host"], r["upstream"]
        loc = ["        location / {"]
        if r["kind"] == "service":     # resolved at request time: nginx starts while the service is down
            loc += ["            resolver 127.0.0.11 valid=30s ipv6=off;", f"            set $route_upstream {up};", "            proxy_pass $route_upstream;"]
        else:                          # an address (host.docker.internal comes from extra_hosts)
            loc += [f"            proxy_pass {up};"]
        loc += ["            proxy_ssl_verify off;",
                "            proxy_http_version 1.1;",
                "            proxy_set_header Host              $http_host;",
                "            proxy_set_header X-Real-IP         $remote_addr;",
                "            proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;",
                "            proxy_set_header X-Forwarded-Proto $scheme;",
                "            proxy_set_header X-Forwarded-Host  $http_host;"]
        if r.get("websocket"):
            loc += ["            proxy_set_header Upgrade           $http_upgrade;",
                    "            proxy_set_header Connection        $connection_upgrade;",
                    "            proxy_read_timeout 3600s;"]
        else:
            loc += ['            proxy_set_header Connection        "";', "            proxy_read_timeout 300s;"]
        loc += ["        }"]
        loc = "\n".join(loc) + "\n"
        print(f"    # ---- route: {h} -> {r['target']}  (tls {r['tls']})")
        common = f"        server_name {h};\n        client_max_body_size {r['max_body']};\n"
        if r["tls"] == "off":
            print("    server {\n        listen 80;\n" + common + acme + loc + "    }")
        elif tls_ok(r):
            print("    server {\n        listen 443 ssl;\n" + common +
                  f"        ssl_certificate     /etc/nginx/routes-certs/{h}.pem;\n        ssl_certificate_key /etc/nginx/routes-certs/{h}-key.pem;\n"
                  "        ssl_protocols       TLSv1.2 TLSv1.3;\n" + loc + "    }")
            print("    server {\n        listen 80;\n" + common + acme + f"        location / {{ return 301 https://$host{sfx}$request_uri; }}\n    }}")
        else:                          # no certificate yet: only the ACME challenge answers
            print("    server {\n        listen 80;\n" + common + acme +
                  f"        location / {{ default_type text/plain; return 503 \"no certificate for {h} yet - vexor proxy cert {h}\\n\"; }}\n    }}")
elif op == "json":                # json <https-port> <http-port> <nginx-running 0|1> <rendered-conf> <ca-file> <suggestions>
    https_port, http_port, running, conf, ca, sugg = args
    try:
        rendered = open(conf).read()
    except OSError:
        rendered = ""
    out = []
    for r in routes:
        h = r.get("host", "")
        c = cert_info(h) if r.get("tls") != "off" else {"exists": False}
        if not sane(r):
            st = "invalid"
        elif r.get("tls") != "off" and not c["exists"]:
            st = "no-cert"
        elif r.get("tls") != "off" and "days" not in c:
            st = "bad-cert"
        elif r.get("tls") != "off" and c.get("days", 0) < 0:
            st = "expired"
        elif f"# ---- route: {h} " not in rendered:
            st = "not-rendered"
        elif running != "1":
            st = "nginx-down"
        else:
            st = "active"
        tls = r.get("tls") != "off"
        port = https_port if tls else http_port
        url = ("https://" if tls else "http://") + h + ("" if port == ("443" if tls else "80") else ":" + port) + "/"
        out.append({**{k: r.get(k) for k in ("host", "target", "kind", "upstream", "tls", "websocket", "max_body", "created", "updated")},
                    "cert": c, "status": st, "url": url})
    print(json.dumps({"routes": out, "https_port": https_port, "http_port": http_port, "nginx_running": running == "1",
                      "ca": os.path.isfile(ca), "suggestions": [s for s in sugg.split() if s]}))
else:
    sys.exit(f"unknown op {op}")
PY
}
routes_nginx_blocks() { [ "$(routes_count)" -gt 0 ] || return 0; routes_py render "$(routes_https_port)" "$(routes_http_port)"; }
routes_override() {            # nginx additions in docker-compose.override.yml while a route exists
  [ "$(routes_count)" -gt 0 ] || return 0
  case "${1:-}" in
    ports)
      echo '      - "${BIND_IP:-0.0.0.0}:${ROUTES_HTTPS_PORT:-443}:443"'
      echo '      - "${BIND_IP:-0.0.0.0}:${ROUTES_HTTP_PORT:-80}:80"' ;;
    rest)
      echo "    volumes:"
      echo "      - ./config/nginx/routes-certs:/etc/nginx/routes-certs:ro"
      echo "      - ./config/nginx/acme:/var/www/acme:ro"
      echo "    extra_hosts:"
      echo '      - "host.docker.internal:host-gateway"' ;;
  esac
}
route_exists() { routes_py get "$1" >/dev/null 2>&1; }
route_field() { routes_py field "$1" "$2" 2>/dev/null; }
route_cert() { echo "$ROUTES_CERT_DIR/$1.pem"; }
route_key() { echo "$ROUTES_CERT_DIR/$1-key.pem"; }
route_url() {
  local h="$1" tls="$2" p
  if [ "$tls" = off ]; then p="$(routes_http_port)"; [ "$p" = 80 ] && p="" ; echo "http://$h${p:+:$p}/"
  else p="$(routes_https_port)"; [ "$p" = 443 ] && p=""; echo "https://$h${p:+:$p}/"; fi
}
nginx_image() { env_def NGINX_IMAGE nginx:stable; }
proxy_nginx_test() {           # proxy_nginx_test <recreate 0|1>: nginx -t on the rendered config (output on failure)
  local out
  if [ "$1" = 0 ] && is_running nginx; then
    out="$(dc exec -T nginx nginx -t 2>&1)" && return 0
  else                         # new mounts/ports: test in a one-off container of the nginx service (no ports published)
    docker image inspect "$(nginx_image)" >/dev/null 2>&1 || { warn "nginx image not present - config not tested"; return 0; }
    out="$(dc run --rm --no-deps -T --entrypoint nginx nginx -t 2>&1)" && return 0
  fi
  printf '%s\n' "$out" | grep -E 'emerg|error|failed' | sed 's/^/      /' | tail -5
  return 1
}
proxy_ports_free() {           # the first route publishes ROUTES_*_PORT: refuse when something else holds them
  local p k v
  for p in "$(routes_https_port)" "$(routes_http_port)"; do
    [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || die "ROUTES_HTTPS_PORT / ROUTES_HTTP_PORT must be port numbers"
    for k in PROXY_PORT AGENT_PORT ENROLL_PORT API_PORT KIBANA_PORT N8N_PORT GRAFANA_PORT PORTAINER_PORT CONSOLE_PORT; do
      v="$(env_get "$k")"; [ "$v" = "$p" ] && die "port $p is $k - set another ROUTES_HTTPS_PORT/ROUTES_HTTP_PORT: vexor config set ROUTES_HTTPS_PORT 8443"
    done
    if port_listening "$p" && ! host_published nginx "$([ "$p" = "$(routes_https_port)" ] && echo 443 || echo 80)"; then
      die "port $p is already in use on this host ($(ss -Hltnp "( sport = :$p )" 2>/dev/null | grep -o 'users:(("[^"]*' | head -1 | cut -d'"' -f2)) - free it or set ROUTES_$([ "$p" = "$(routes_https_port)" ] && echo HTTPS || echo HTTP)_PORT in .env"
    fi
  done
}
proxy_apply() {                # proxy_apply [routes-backup]: render, test, reload/recreate nginx; on failure restore everything
  local bak="${1:-}" d recreate=0
  d="$(mktemp -d "${RUN_TMP:-/tmp}/proxy.XXXXXX")"
  [ -f "$NGINX_CONF" ] && cp -p "$NGINX_CONF" "$d/nginx.conf"
  [ -f "$OVERRIDE_FILE" ] && cp -p "$OVERRIDE_FILE" "$d/override.yml"
  mkdir -p "$ROUTES_CERT_DIR" "$ACME_DIR"; chmod 700 "$ROUTES_CERT_DIR"; chmod 755 "$ACME_DIR"
  render_nginx; render_override
  cmp -s "$OVERRIDE_FILE" "$d/override.yml" || recreate=1
  if ! docker_ok; then warn "Docker is not running - nginx picks the routes up on its next start"; return 0; fi
  if [ "$recreate" = 0 ] && ! is_running nginx; then say "nginx is not running - the routes are used on its next start (vexor start)"; return 0; fi
  if proxy_nginx_test "$recreate"; then
    if [ "$recreate" = 1 ]; then
      if ! is_running nginx; then say "nginx is not running - the routes are used on its next start (vexor start)"; return 0; fi
      if run_step "recreating nginx (route ports $(routes_https_port)/$(routes_http_port))" dc up -d --no-deps nginx; then return 0; fi
      bad "nginx did not start with the new ports - rolling back"
    else
      dc exec -T nginx nginx -s reload >/dev/null 2>&1 && { sleep 1; ok "nginx reloaded (config tested)"; return 0; }   # reload is async
      bad "nginx reload failed - rolling back"
    fi
  else
    bad "nginx rejected the new configuration - rolled back, nginx keeps running with the previous one"
  fi
  if [ -n "$bak" ] && [ -f "$bak" ]; then cp "$bak" "$ROUTES_FILE"; elif [ "$bak" = none ]; then rm -f "$ROUTES_FILE"; fi
  [ -f "$d/nginx.conf" ] && cat "$d/nginx.conf" > "$NGINX_CONF"      # in place: the file is bind-mounted
  [ -f "$d/override.yml" ] && cat "$d/override.yml" > "$OVERRIDE_FILE"
  if [ "$recreate" = 1 ] && [ -n "$(svc_cid nginx)" ]; then dc up -d --no-deps nginx >/dev/null 2>&1; fi
  return 1
}
routes_backup() {              # routes_backup -> a copy of routes.json to restore on failure ("none" = there was none)
  if [ -f "$ROUTES_FILE" ]; then cp -p "$ROUTES_FILE" "$RUN_TMP/routes.json.bak"; echo "$RUN_TMP/routes.json.bak"; else echo none; fi
}
proxy_issue_local() {          # proxy_issue_local <host>: certificate from the local CA (SAN = DNS or IP)
  local h="$1"
  local_ca_ensure || return 1
  [ -s "$PROXY_CERT_DIR/ca.crt" ] || install -m 644 "$PROXY_CERT_DIR/ca.pem" "$PROXY_CERT_DIR/ca.crt"
  [ -s "$PROXY_CERT_DIR/ca.cer" ] || openssl x509 -in "$PROXY_CERT_DIR/ca.pem" -outform der -out "$PROXY_CERT_DIR/ca.cer"
  mkdir -p "$ROUTES_CERT_DIR"; chmod 700 "$ROUTES_CERT_DIR"
  local_ca_sign "$RUN_TMP/route.pem" "$RUN_TMP/route-key.pem" "$(env_def CERT_DAYS 397)" "$h" || return 1
  install -m 600 "$RUN_TMP/route-key.pem" "$(route_key "$h")"
  install -m 644 "$RUN_TMP/route.pem" "$(route_cert "$h")"
  rm -f "$RUN_TMP/route.pem" "$RUN_TMP/route-key.pem"
  ok "certificate for $h from the local CA ($(env_def CERT_DAYS 397) days)"
}
le_public_name() {             # false for names Let's Encrypt can never validate (private / reserved suffixes, single labels)
  local h="${1,,}"
  [[ "$h" == *.* ]] || return 1
  case ".${h##*.}" in
    .lab|.local|.lan|.internal|.home|.corp|.test|.localhost|.invalid|.example|.intranet|.private|.localdomain|.home.arpa|.arpa) return 1 ;;
  esac
  [[ "$h" == *.home.arpa ]] && return 1
  return 0
}
proxy_issue_le() {             # proxy_issue_le <host> [force]: Let's Encrypt via http-01 on ROUTES_HTTP_PORT (nginx answers it)
  local h="$1" force="${2:-0}" img="${LE_IMAGE:-certbot/certbot:latest}" reg=(--register-unsafely-without-email) extra=(--keep-until-expiring)
  is_ipv4 "$h" && { bad "Let's Encrypt does not issue certificates for IP addresses here - use --tls local"; return 1; }
  le_public_name "$h" || { bad "Let's Encrypt cannot issue for $h (.${h##*.} is not a public domain) - use --tls local"; return 1; }
  getent hosts "$h" >/dev/null 2>&1 || warn "$h does not resolve from this server - Let's Encrypt will not find it either (add an A record first)"
  is_running nginx || { bad "nginx must run to answer the Let's Encrypt challenge (vexor start)"; return 1; }
  host_published nginx 80 || { bad "nginx does not publish ROUTES_HTTP_PORT yet"; return 1; }
  [ "$(routes_http_port)" = 80 ] || warn "Let's Encrypt connects to port 80 - forward public port 80 to ROUTES_HTTP_PORT=$(routes_http_port)"
  [ -n "$(env_get LE_EMAIL)" ] && reg=(-m "$(env_get LE_EMAIL)")
  [ "$force" = 1 ] && extra=(--force-renewal)
  mkdir -p "$ACME_DIR" "$LE_DIR"; chmod 755 "$ACME_DIR"
  say "$h must resolve to this server and port 80 must be reachable from the internet."
  pull_image_list "$img" || { bad "could not download $img"; return 1; }   # so a failure shows certbot's own error, not pull progress
  run_step "Let's Encrypt certificate for $h (http-01)" docker run --rm -v "$LE_DIR:/etc/letsencrypt" -v "$ACME_DIR:/var/www/acme" "$img" \
    certonly --webroot -w /var/www/acme --non-interactive --agree-tos "${reg[@]}" --cert-name "$h" -d "$h" "${extra[@]}" \
    || { hint "check: DNS A record of $h -> this server, port 80 forwarded, vexor proxy show $h"; return 1; }
  local live="$LE_DIR/live/$h"
  [ -f "$live/fullchain.pem" ] || { bad "issued, but $live/fullchain.pem is missing"; return 1; }
  mkdir -p "$ROUTES_CERT_DIR"; chmod 700 "$ROUTES_CERT_DIR"
  install -m 600 "$(readlink -f "$live/privkey.pem")" "$(route_key "$h")"
  install -m 644 "$(readlink -f "$live/fullchain.pem")" "$(route_cert "$h")"
  ok "Let's Encrypt certificate for $h installed ($(cert_days_left "$(route_cert "$h")") days)"
}
proxy_issue() {                # proxy_issue <host> <tls> [force]
  case "$2" in
    local) proxy_issue_local "$1" ;;
    letsencrypt) proxy_issue_le "$1" "${3:-0}" ;;
    *) return 0 ;;
  esac
}
proxy_dns_check() {            # proxy_dns_check <host>: prints a problem (empty = resolves to this machine / is one of its IPs)
  local h="$1" addrs a mine
  if is_ipv4 "$h"; then host_has_ip "$h" || echo "$h is not an address of this machine (NAT? then clients must reach it)"; return 0; fi
  addrs="$(getent ahostsv4 "$h" 2>/dev/null | awk '{print $1}' | sort -u)"
  [ -n "$addrs" ] || { echo "$h does not resolve (no DNS record)"; return 0; }
  mine=" $(host_ips | tr '\n' ' ') $(primary_ip) 127.0.0.1 "
  is_ipv4 "$(public_host)" && mine+="$(public_host) "
  for a in $addrs; do [[ "$mine" == *" $a "* ]] && return 0; done
  echo "$h resolves to $(echo "$addrs" | tr '\n' ' ')- not an address of this machine"
}
proxy_parse_opts() {           # sets P_TLS P_WS P_SIZE P_TARGET from --tls/--websocket/--no-websocket/--max-body/--target
  while [ $# -gt 0 ]; do
    case "$1" in
      --tls) P_TLS="${2:-}"; shift ;;
      --tls=*) P_TLS="${1#--tls=}" ;;
      --websocket|--ws) P_WS=1 ;;
      --no-websocket|--no-ws) P_WS=0 ;;
      --max-body) P_SIZE="${2:-}"; shift ;;
      --max-body=*) P_SIZE="${1#--max-body=}" ;;
      --target) P_TARGET="${2:-}"; shift ;;
      --target=*) P_TARGET="${1#--target=}" ;;
      *) die "unknown option '$1' - see: vexor help (proxy)" ;;
    esac
    shift
  done
  P_SIZE="${P_SIZE,,}"; P_TLS="${P_TLS,,}"
  [[ " $ROUTE_TLS_MODES " == *" $P_TLS "* ]] || die "--tls must be local, letsencrypt or off"
  proxy_valid_size "$P_SIZE" || die "--max-body like 100m, 512k, 1g or 0 (no limit)"
}
proxy_check_target() {         # proxy_check_target <target>: sets P_KIND P_UP or dies
  local r svc
  r="$(proxy_target "$1")" || die "target '$1' is not valid - use service:port (n8n:5678, wazuh.dashboard:5601) or [http(s)://]IP:PORT"
  P_KIND="${r%% *}"; P_UP="${r#* }"
  if [ "$P_KIND" = service ]; then
    svc="${P_UP#*://}"; svc="${svc%:*}"
    compose_services | has -xF "$svc" || die "no service '$svc' in the compose config - services: $(compose_services | tr '\n' ' ')"
    enabled_services | has -xF "$svc" || warn "$svc is not enabled in the current settings - the route answers 502 until it runs"
  fi
  [ "$P_KIND" = host ] && hint "host targets are reached via host.docker.internal: the program must listen on the Docker bridge or 0.0.0.0, not only 127.0.0.1"
  return 0
}
proxy_ls() {
  local json=0 a; for a in "$@"; do [ "$a" = --json ] && json=1; done
  local running=0; is_running nginx 2>/dev/null && running=1
  local j; j="$(routes_py json "$(routes_https_port)" "$(routes_http_port)" "$running" "$NGINX_CONF" "$PROXY_CERT_DIR/ca.crt" "$(proxy_svc_ports | tr '\n' ' ')")" || return 1
  [ "$json" = 1 ] && { printf '%s\n' "$j"; return 0; }
  hdr "Proxy routes  (https :$(routes_https_port), http :$(routes_http_port) on $(bind_ip))"
  python3 -I -c '
import json, sys
d = json.loads(sys.argv[1])
if not d["routes"]:
    print("  no routes - add one: vexor proxy add soc.example.com wazuh.dashboard:5601"); sys.exit()
fmt = "  {:<30} {:<26} {:<12} {:<14} {:<4} {:<6} {}"
print(fmt.format("HOST", "TARGET", "TLS", "CERTIFICATE", "WS", "BODY", "STATUS"))
for r in d["routes"]:
    c = r["cert"]
    days = c.get("days", "?")
    cert = "-" if r["tls"] == "off" else ("missing" if not c.get("exists") else "unreadable" if days == "?" else f"{days} days")
    print(fmt.format(r["host"], r["target"], r["tls"], cert, "yes" if r["websocket"] else "no", r["max_body"], r["status"]))
' "$j"
}
proxy_show() {
  local h="${1,,}" tls crt p
  [ -n "$h" ] || die "usage: vexor proxy show <host>"
  route_exists "$h" || die "no route for $h (vexor proxy ls)"
  tls="$(route_field "$h" tls)"; crt="$(route_cert "$h")"
  hdr "Route $h"
  printf '  %-12s %s\n' "url" "$(route_url "$h" "$tls")"
  printf '  %-12s %s  (%s)\n' "target" "$(route_field "$h" target)" "$(route_field "$h" upstream)"
  printf '  %-12s %s\n' "tls" "$tls" "websocket" "$([ "$(route_field "$h" websocket)" = True ] && echo yes || echo no)" "max body" "$(route_field "$h" max_body)"
  if [ "$tls" != off ]; then
    if [ -f "$crt" ]; then
      printf '  %-12s %s\n' "certificate" "$crt"
      printf '  %-12s %s\n' "issuer" "$(openssl x509 -noout -issuer -in "$crt" | sed 's/^issuer= *//')"
      printf '  %-12s %s (%s days)\n' "expires" "$(openssl x509 -noout -enddate -in "$crt" | cut -d= -f2)" "$(cert_days_left "$crt")"
      cert_covers "$crt" "$h" || warn "the certificate does not name $h - vexor proxy cert $h --renew"
    else warn "no certificate yet - vexor proxy cert $h"; fi
  fi
  grep -q "# ---- route: $h " "$NGINX_CONF" 2>/dev/null && ok "rendered in nginx.conf" || warn "not in nginx.conf yet - vexor proxy apply"
  p="$(proxy_dns_check "$h")"
  if [ -n "$p" ]; then warn "$p"; is_ipv4 "$h" || hint "create a DNS A record: $h -> $(public_host)  (or a hosts-file line on the client)"
  else ok "DNS: $h points to this machine"; fi
  [ "$tls" = local ] && hint "browsers trust it once the local CA is installed: vexor cert export-ca (or the console's Proxy page)"
  return 0
}
proxy_add_edit() {             # proxy_add_edit add|edit <host> [target] [opts]
  local mode="$1" h="${2:-}" bak first=0 old_tls="" old_target=""; shift 2 || true
  h="${h,,}"
  proxy_valid_host "$h" || die "'$h' is not a valid host - a domain like soc.example.com or an IPv4 address (no wildcard, spaces or quotes)"
  P_TARGET="" P_TLS=local P_WS=0 P_SIZE=100m
  if [ "$mode" = add ]; then
    [ $# -ge 1 ] && [[ "$1" != --* ]] || die "usage: vexor proxy add <host> <target> [--tls local|letsencrypt|off] [--websocket] [--max-body SIZE]"
    P_TARGET="$1"; shift
    route_exists "$h" && die "a route for $h exists - change it with: vexor proxy edit $h ..."
  else
    route_exists "$h" || die "no route for $h (vexor proxy ls)"
    old_target="$(route_field "$h" target)"; old_tls="$(route_field "$h" tls)"
    P_TARGET="$old_target"; P_TLS="$old_tls"; P_SIZE="$(route_field "$h" max_body)"
    [ "$(route_field "$h" websocket)" = True ] && P_WS=1
  fi
  proxy_parse_opts "$@"
  proxy_check_target "$P_TARGET"
  [ "$P_TLS" = letsencrypt ] && is_ipv4 "$h" && die "Let's Encrypt needs a domain name - use --tls local for an IP address"
  [ "$P_TLS" = letsencrypt ] && ! le_public_name "$h" && die "Let's Encrypt only issues certificates for public internet domains; '$h' ends in .${h##*.}, a private name it cannot reach - use --tls local (and install the CA certificate once on your devices), or a domain you own"
  if [ "$P_TLS" != off ] && is_ipv4 "$h"; then
    local other; other="$(routes_py tsv | awk -F'\t' -v h="$h" '$1 != h && $1 ~ /^[0-9.]+$/ && $3 != "off" {print $1; exit}')"
    [ -z "$other" ] || die "only one IP-address route can use TLS (clients send no name for an IP, so nginx cannot tell them apart; $other has it) - use a DNS name"
  fi
  take_lock
  [ "$(routes_count)" = 0 ] && { first=1; proxy_ports_free; }
  bak="$(routes_backup)"
  routes_py put "$h" "$P_TARGET" "$P_KIND" "$P_UP" "$P_TLS" "$P_WS" "$P_SIZE" || die "could not save the route"
  if [ "$P_TLS" = local ] && { [ ! -f "$(route_cert "$h")" ] || [ "$old_tls" != local ]; }; then
    proxy_issue_local "$h" || { [ "$bak" = none ] && rm -f "$ROUTES_FILE" || cp "$bak" "$ROUTES_FILE"; die "route not saved"; }
  fi
  proxy_apply "$bak" || die "route not saved - nginx still runs the previous configuration"
  ok "route $h -> $P_TARGET ($P_UP)  tls $P_TLS$([ "$P_WS" = 1 ] && echo ', websocket')$([ "$first" = 1 ] && echo "; nginx now listens on $(routes_https_port)/$(routes_http_port)")"
  if [ "$P_TLS" = letsencrypt ] && { [ ! -f "$(route_cert "$h")" ] || [ "$old_tls" != letsencrypt ]; }; then
    if proxy_issue_le "$h"; then proxy_apply || true
    else warn "the route answers 503 on http until it has a certificate - retry: vexor proxy cert $h"; fi
  fi
  say "Open: $(route_url "$h" "$P_TLS")"
  local p; p="$(proxy_dns_check "$h")"
  [ -n "$p" ] && { warn "$p"; is_ipv4 "$h" || hint "point DNS at this server: an A record $h -> $(public_host)"; }
  [ "$P_TLS" = local ] && [ "$mode" = add ] && hint "trust the local CA once per device: vexor cert export-ca (Proxy page in the console: Download CA)"
  return 0
}
proxy_rm() {
  local h="${1,,}" bak
  [ -n "$h" ] || die "usage: vexor proxy rm <host>"
  route_exists "$h" || die "no route for $h (vexor proxy ls)"
  confirm "Remove the route $h ($(route_field "$h" target))?" || die "Aborted"
  take_lock
  bak="$(routes_backup)"
  routes_py del "$h" || die "could not save the routes"
  proxy_apply "$bak" || die "route kept - nginx still runs the previous configuration"
  rm -f "$(route_cert "$h")" "$(route_key "$h")"
  ok "route $h removed$([ "$(routes_count)" = 0 ] && echo "; ports $(routes_https_port)/$(routes_http_port) are no longer published")"
}
proxy_cert_cmd() {
  local h="${1:-}" renew=0 tls d; h="${h,,}"
  [ "${2:-}" = --renew ] || [ "${2:-}" = --force ] && renew=1
  [ -n "$h" ] || die "usage: vexor proxy cert <host> [--renew]"
  route_exists "$h" || die "no route for $h (vexor proxy ls)"
  tls="$(route_field "$h" tls)"
  [ "$tls" = off ] && die "$h uses plain HTTP (--tls off) - switch it: vexor proxy edit $h --tls local"
  if [ "$renew" = 0 ] && [ -f "$(route_cert "$h")" ]; then
    d="$(cert_days_left "$(route_cert "$h")")"
    if [ "${d:-0}" -ge 30 ] && cert_covers "$(route_cert "$h")" "$h"; then say "certificate of $h is valid for $d more days - re-issue with: vexor proxy cert $h --renew"; return 0; fi
  fi
  take_lock
  proxy_issue "$h" "$tls" "$renew" || die "certificate not issued"
  proxy_apply || die "nginx rejected the configuration - previous one kept"
}
proxy_cert_file() {            # public files only: the local CA, or a route's certificate (never a key)
  local a="${1:-}" what="${2:-cert}" f
  if [ "$a" = ca ] && [ -z "${2:-}" ]; then what=ca; a=""; fi
  a="${a,,}"
  case "$what" in
    ca) f="$PROXY_CERT_DIR/ca.crt"; [ -f "$f" ] || f="$PROXY_CERT_DIR/ca.pem"
        [ -f "$f" ] || die "no local CA yet - add a route with --tls local, or: vexor cert create" ;;
    cert) [ -n "$a" ] || die "usage: vexor proxy cert-file <host> [ca|cert]"
          route_exists "$a" || die "no route for $a"
          [ "$(route_field "$a" tls)" = off ] && die "$a uses plain HTTP (--tls off) - it has no certificate"
          f="$(route_cert "$a")"; [ -f "$f" ] || die "no certificate for $a yet - vexor proxy cert $a" ;;
    *) die "usage: vexor proxy cert-file <host> [ca|cert]" ;;
  esac
  echo "$f"
}
proxy_renew_due() {            # maintenance: renew route certificates with < 30 days left, then reload nginx once
  local h tls d n=0
  [ "$(routes_count)" -gt 0 ] || return 0
  while IFS=$'\t' read -r h _ tls _ _; do
    [ "$tls" = off ] && continue
    d="$(cert_days_left "$(route_cert "$h")")"
    [ -n "$d" ] && [ "$d" -ge 30 ] && continue
    log "renewing the certificate of route $h (${d:-no} days left)"
    proxy_issue "$h" "$tls" 1 && n=$((n + 1))
  done < <(routes_py tsv)
  [ "$n" -gt 0 ] && proxy_apply
  return 0
}
proxy_doctor() {               # doctor: routes render, certificates, DNS
  hdr "Proxy routes ($(routes_count))"
  local h target tls d p crt
  routes_py tsv >/dev/null 2>&1 || { d_fail "routes file unreadable: $ROUTES_FILE" "fix the JSON or restore it from a backup (vexor backup restore-config)"; return 0; }
  if is_running nginx; then
    if host_published nginx 443 && host_published nginx 80; then d_pass "nginx publishes the route ports $(routes_https_port)/$(routes_http_port)"
    else d_fail "nginx does not publish the route ports $(routes_https_port)/$(routes_http_port)" "vexor doctor --fix   (or: vexor proxy apply)"
         d_fix "re-render nginx + recreate it with the route ports" && proxy_apply >/dev/null; fi
  fi
  while IFS=$'\t' read -r h target tls _ _; do
    if grep -q "# ---- route: $h " "$NGINX_CONF" 2>/dev/null; then d_pass "route $h -> $target rendered"
    else d_fail "route $h is not in nginx.conf" "vexor proxy apply"; d_fix "render nginx + reload" && proxy_apply >/dev/null; fi
    if [ "$tls" != off ]; then
      crt="$(route_cert "$h")"
      if [ ! -f "$crt" ] || [ ! -f "$(route_key "$h")" ]; then d_fail "route $h has no certificate" "vexor proxy cert $h"
        [ "$tls" = local ] && d_fix "issue it from the local CA" && proxy_issue_local "$h" >/dev/null && proxy_apply >/dev/null
      else
        d="$(cert_days_left "$crt")"
        if [ -z "$d" ]; then d_fail "certificate of $h is unreadable" "vexor proxy cert $h --renew"
        elif [ "$d" -lt 0 ]; then d_fail "certificate of $h EXPIRED" "vexor proxy cert $h --renew"
        elif [ "${d:-0}" -lt 21 ]; then d_warn "certificate of $h expires in $d days" "vexor proxy cert $h --renew"
        elif ! cert_covers "$crt" "$h"; then d_warn "certificate of $h does not name $h" "vexor proxy cert $h --renew"
        else d_pass "certificate of $h ($tls) valid for $d days"; fi
      fi
    fi
    p="$(proxy_dns_check "$h")"
    if [ -n "$p" ]; then d_warn "$p" "$(is_ipv4 "$h" && echo "use an address of this machine" || echo "DNS: an A record $h -> $(public_host) (behind NAT: the public IP that forwards $(routes_https_port)/$(routes_http_port) here)")"
    else d_pass "$h resolves to this machine"; fi
  done < <(routes_py tsv 2>/dev/null)
}
cmd_proxy() {
  local sub="${1:-ls}"; shift || true
  case "$sub" in
    ls|list|status) proxy_ls "$@" ;;
    show) proxy_show "$@" ;;
    add) proxy_add_edit add "$@" ;;
    edit|set) proxy_add_edit edit "$@" ;;
    rm|remove|del|delete) proxy_rm "$@" ;;
    cert) proxy_cert_cmd "$@" ;;
    cert-file) proxy_cert_file "$@" ;;
    apply) take_lock; proxy_apply && ok "proxy routes applied ($(routes_count))" ;;
    *) die "usage: vexor proxy ls [--json] | show <host> | add <host> <target> [--tls local|letsencrypt|off] [--websocket] [--max-body SIZE] | edit <host> [...] | rm <host> | cert <host> [--renew] | cert-file <host> [ca|cert] | apply" ;;
  esac
}

