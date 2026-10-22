# vexor: command reference

`vexor` is one bash script that manages the whole stack described in [README.md](README.md): Wazuh, ELK, n8n, Suricata, Zeek, Grafana and Portainer. It handles setup, what runs, alert forwarding between the stacks, certificates, passwords, agents, upgrades, backups, troubleshooting and self-healing.

```
vexor <command> [subcommand] [options]
```

---

## Contents

- [Installation](#installation) · [Conventions](#conventions) · [Change management](#change-management)
- Stack commands: [Wazuh](#wazuh) · [ELK](#elk) · [n8n](#n8n) · [Suricata](#suricata) · [Zeek](#zeek) · [other tools](#other-tools) · [console](#console)
- Platform commands: [setup](#setup) · [run](#run) · [what runs](#what-runs) · [troubleshoot](#troubleshoot) · [update](#update) · [certificates](#certificates) · [proxy routes](#proxy-routes) · [security](#security) · [data](#data) · [health automation](#health-automation) · [automation](#automation)
- [What `doctor --fix` repairs](#what-doctor---fix-repairs) · [Files and state](#files-and-state) · [Exit codes](#exit-codes) · [Extending vexor](#extending-vexor)

---

## Installation

The script lives in the repository root, next to `docker-compose.yml` and `.env`:

```bash
sudo ./vexor install          # first time; creates .env from .env.example
sudo ./vexor daemon install   # /usr/local/bin/vexor, completion, boot service, timers, login summary
```

It needs bash 4.4+, Docker Engine with Compose v2, `python3`, `openssl`, `curl`, `ss`, `flock`, and systemd for the daemon.

When `install` finds an earlier setup, it asks whether to reuse it or start clean. `install --fresh` starts clean without asking. `sudo vexor uninstall` removes everything Vexor added (see [Data](#data)).

---

## Conventions

| Topic | Behaviour |
|---|---|
| **Root** | Every command except `help`, `version` and `completion` needs root; a non-root user is re-run through `sudo`. |
| **Global options** | `-y` / `--yes` answers every prompt. `-q` / `--quiet` prints less. `--no-color` gives plain output for scripts and logs. `--verbose` (or `VEXOR_VERBOSE=1`) streams the full docker output instead of the one-line progress view. |
| **Service names** | Full names (`wazuh.master`) or aliases: `master`, `worker`, `worker2`, `worker3`, `indexer1`–`indexer3`, `dashboard`, `nginx`, and the groups `managers` and `indexers`. ELK and tool services use their own names (`kibana`, `logstash`, `n8n`, `suricata` …). |
| **Confirmation** | Risky actions ask `[y/N]`; destructive ones make you type `DELETE`, `RESTORE` or `REGEN`. `--yes` skips both. |
| **Locking** | Commands that change something take `/run/lock/vexor.lock`. Interactive commands wait up to 3 minutes for a running watchdog or health check. |
| **Idempotent** | `install`, `start`, `config apply`, `tools apply`, `soc …`, `n8n connect` and `daemon install` are safe to repeat. |
| **History** | Every changing command is logged to `.state/history.log`, secrets masked. |
| **Self-migration** | On every run `vexor` upgrades what older versions wrote: new `.env` keys, compose layout, the old `wazuhctl` names and units, and the Shuffle settings (replaced by n8n in 1.2.0). |
| **Settings** | Read from `.env`. A key defined twice resolves to its last definition, as in Docker Compose. |
| **Addresses** | An empty `PUBLIC_HOST` is detected each time `vexor` runs and never saved, so a moved machine needs no edit; `doctor` warns when the certificates no longer cover the current address. Published ports listen on `BIND_IP` (default `0.0.0.0`). |

---

## Change management

Disk settings: `DISK_WARN_PCT` (85) and `DISK_FAIL_PCT` (95) are the `doctor` limits for every disk Docker uses. `vexor install` warns below `DISK_WARN_FREE_GB` (15) and refuses below `DISK_MIN_FREE_GB` (5) free space on any of them; `vexor install --force` installs anyway. `WAZUH_VULN_DETECTION` (default `false`) switches Wazuh vulnerability detection in every manager; its CVE feed needs about 13 GB per manager in the `*-wazuh-queue` volume. `vexor config apply` recreates the managers; switching it off also deletes the downloaded feed (`/var/ossec/queue/vd`), and `vexor doctor --fix` removes one left from earlier.

After editing `.env`: `vexor config validate`, then `vexor config apply`, then `vexor doctor`. Never use `down -v` or `reset` to apply settings, because they delete the data volumes.

| You changed | Apply with | Downtime |
|---|---|---|
| Plain values (ports, heap, log rotation, images) | `vexor config apply` | only the changed containers |
| `SOC` | `vexor soc <wazuh\|elk\|both>` | 1–3 min (ELK first start) |
| `NODE_TYPE` / `WORKER_COUNT` | `vexor node-type …` / `vexor scale …` | about 1–2 min |
| Tool flags, `SNIFF_INTERFACE`, `ZEEK_WAZUH_LOGS` | `vexor tools apply` | the master is recreated when sensor sources change |
| `N8N_ALERT_LEVEL`, `N8N_ALERT_GROUPS`, webhook path | `vexor n8n connect …` | managers are recreated (about 30 s) |
| Passwords | `vexor passwd …`, `vexor elk reset-password` | dependent containers |
| `WAZUH_VERSION` | `vexor update apply <version>` | a few minutes |
| `PUBLIC_HOST`, certificate names | `vexor cert create` | nginx (seconds) |
| `BIND_IP` (address the published ports listen on) | `vexor config apply` | containers with published ports |
| Timer times | `vexor daemon install` | none |
| `config/wazuh_cluster/*.conf` | edit every manager file → `vexor restart managers` | managers are **recreated** |
| `config/nginx/nginx.conf.tpl` | `vexor config apply` | none (reload) |

---

## Wazuh

Available when `SOC` is `wazuh` or `both`.

| Command | Description |
|---|---|
| `wazuh [status]` | Indexer cluster health, nodes, disk, Wazuh indices, shards, manager cluster, master daemons, API version. |
| `wazuh alerts [-n N] [--level N] [--grep TEXT]` | Newest alerts from every manager, merged and sorted, in local time. |
| `wazuh logtest "<log line>" [--format syslog\|json\|...] [--location L] [--json]` | Run one line through the master's decoders and rules: the decoder, the fields, and the rule that matches (or none). Without a line, the interactive `wazuh-logtest`. |
| `wazuh rules ls [--json]` | Rule files: custom ones, `vexor_tools_rules.xml` and Wazuh's built-in files (read-only), with rule count, ID range and source. |
| `wazuh rules show <name>` | Print a rule file. |
| `wazuh rules put <name> --from <path\|->` | Save a rule file from a path or stdin. Wazuh checks it before it stays; a failed check restores the previous version and exits non-zero. |
| `wazuh rules rm <name>` | Delete a custom rule file. |
| `wazuh rules history <name> [--json]` / `wazuh rules restore <name> <id>` | The last 20 versions of a file / put one back. |
| `wazuh rules templates [--json]` | Templates in `config/detection-templates/rules/`. |
| `wazuh decoders ls \| show \| put \| rm \| history \| restore \| templates` | The same for decoder files; templates from `config/detection-templates/decoders/`. |
| `wazuh lists ls \| show \| put \| rm \| history \| restore` | The same for CDB lists in `config/wazuh_custom/lists/`. |
| `wazuh lists add <name> <key>[:<value>]` / `wazuh lists del <name> <key>` | Add or remove one entry without editing the file. |
| `wazuh integrations ls [--json]` | Integrations in the manager config: hook URL, whether an API key is set (the key is never shown), level, group, rule IDs, format. The n8n block is read-only here. |
| `wazuh integrations add <name> [--hook-url URL] [--api-key K \| --api-key-file F] [--level N] [--group G] [--rule-id IDS] [--format json]` | Add `slack`, `pagerduty`, `virustotal`, `shuffle`, `maltiverse` or `custom-<id>`. Written to the master and every worker, then the managers are recreated. A `custom-<id>` needs its script in `/var/ossec/integrations/` first. `--api-key-file` keeps the key out of the process list. |
| `wazuh integrations edit <name> [same options]` / `wazuh integrations rm <name>` / `wazuh integrations test <name>` | Change or remove one / send a sample alert through it. |
| `wazuh config ls [--json]` | Curated manager settings (alert log level, email, logall, syscheck, localfile, active response, enrollment password) with their scope (`all` or `master`). |
| `wazuh config set <key> <value> [<key> <value> ..]` | Change one or more of them in one go (one check, one restart). List values are comma-separated or a JSON array. |
| `wazuh config custom show` / `wazuh config custom put --from <path\|-> [--scope master\|all]` / `wazuh config custom rm` | The raw XML block between the `vexor:custom` markers. Wazuh checks it first; a block it refuses changes nothing. Vexor's own blocks are never touched. |
| `wazuh detection status --json` | Counts of rules, decoders and lists, the last change and the last error. The Detection page header shows the same. |
| `agents list \| summary \| outdated` | Agents with status, node, version and OS / counts by status / agents older than the manager. |
| `agents enroll-cmd [linux\|rpm\|windows\|macos] [--name N] [--group G]` | Copy-paste install commands, including the enrollment password and non-default ports. |
| `agents remove <id[,id..]>` | Remove agents. |
| `agents password on [pw] \| off \| show` | Require a password for enrollment. |
| `cluster` | Manager cluster nodes and their last sync. |
| `node-type [status]` | Applied layout, the `.env` value, what is shared, any unfinished switch. |
| `node-type single [--dry-run] [--no-backup]` | 1 manager and 1 indexer. Backs up, moves every shard to `wazuh1`, removes the workers (volumes kept). Agents keep their keys and address. |
| `node-type multi [--indexers 1\|3] [--dry-run] [--no-backup]` | Master plus `WORKER_COUNT` workers and 3 indexers. |
| `scale <1-3>` | Number of workers (multi); updates the nginx agent balancer. |
| `indexers status \| 1 \| 3 \| abort \| cleanup` | The indexer-count steps `node-type` uses: shrink or grow without data loss, undo an unfinished shrink, delete the old volumes. |
| `health` | Same as `wazuh status`. |
| `indexer <METHOD> <path> [json]` / `api <METHOD> <path> [json]` | Raw Wazuh indexer or Wazuh API call, e.g. `vexor api GET /agents/summary/status`. |

## ELK

Available when `SOC` is `elk` or `both`.

| Command | Description |
|---|---|
| `soc [status]` / `soc wazuh \| elk \| both` | Which stacks run / switch. Turning ELK on generates its passwords, creates the Logstash writer user and role, applies ILM retention with 0 replicas, and adds the Kibana data views. `elk` stops Wazuh, keeping its data and agent keys. |
| `elk [status]` | Elasticsearch health, Kibana, events in the last hour, the Beats endpoint. |
| `elk indices` | `vexor-*` indices with health, document count and size. |
| `elk search [query] [-n N] [--index P]` | Lucene search, newest first, with a short summary of each hit. Example: `vexor elk search 'alert.signature_id:2100498' --index 'vexor-suricata-*'`. |
| `elk data-views` / `elk retention` | Re-create the Kibana data views / re-apply ILM retention (`RETENTION_DAYS` or `ELK_RETENTION_DAYS`) and the index template. |
| `elk beats-ca` | The CA that Beats senders trust when `LOGSTASH_BEATS_TLS=true`. |
| `elk beats-config` | `filebeat.yml` snippet for machines that ship logs to Logstash (`LOGSTASH_BEATS_PORT`). |
| `elk es <METHOD> <path> [json]` | Raw Elasticsearch API as `elastic`, e.g. `vexor elk es GET /_cat/health?v`. |
| `elk explain` / `elk reset-password` | Shard allocation explanation / a new `elastic` password, stored in `.env`. |
| `elk logs [svc]` | Logs of `elasticsearch` (default), `logstash` or `kibana`. |

## n8n

Needs `N8N=true` for the built-in n8n. `connect` also accepts the full URL of an n8n somewhere else.

| Command | Description |
|---|---|
| `n8n [status]` | Whether n8n runs, the owner account and the number of workflows. Then the forwarding: integration block per manager config, script and `wazuh-integratord` per manager (or the Logstash output with `SOC=elk`), whether the webhook is registered, delivery errors in the last 15 minutes, and the credentials. |
| `n8n enable \| disable` | Start n8n behind nginx on `N8N_PORT` / remove it (the `n8n-data` volume is kept). |
| `n8n connect [path\|url] [--level N] [--groups G]` | Forward alerts of level N or higher (default 7), optionally only those groups. The default path is `vexor-alerts`. A bare path or this host's n8n URL becomes the internal address `http://n8n:5678/webhook/<path>`. With Wazuh, writes a `custom-n8n` integration into the master and every worker config, installs the script into each manager's integrations volume and recreates the managers. With `SOC=elk`, Logstash forwards Suricata alerts and Zeek notices. Generates `N8N_HOOK_TOKEN`, sent as `X-Vexor-Token`. |
| `n8n workflow [import]` | Import and publish **Vexor - SOC alerts**. A webhook feeds a code step that checks the token and normalises the event. A switch then routes it by severity. Optional steps: chat message (`N8N_NOTIFY_URL`), AbuseIPDB score (`N8N_ABUSEIPDB_KEY`), firewall-drop after approval in chat (`N8N_AUTO_BLOCK=approve`). The credentials are created inside n8n. n8n is restarted so the webhook goes live. |
| `n8n workflow file` | Only write the workflow JSON to `config/tools/n8n/` for a manual import. |
| `n8n credentials` | Wazuh API user `vexor-n8n`: readonly plus agent commands, active response and syscheck. Elasticsearch user `vexor_n8n`: read `vexor-*`. Prints how to use both from an HTTP Request node. Re-running it rotates the Wazuh password. |
| `n8n test [--level N] [--srcip IP]` | Posts a fake alert (rule 100000 "Vexor test alert", default level 12, source 192.0.2.10) to the published workflow webhook from inside the n8n container, with `X-Vexor-Token`. Reads the run in n8n for up to 40 s and prints one line per workflow node: ✔ ran, – not reached (with the setting that leaves it out), ✘ error. Reports a missing workflow (404: run `n8n workflow`) and a token mismatch. |
| `n8n disconnect` | Stop forwarding; removes the integration blocks or the Logstash output. |
| `n8n backup [dir]` | Export every workflow and credential. Credentials stay encrypted with `N8N_ENCRYPTION_KEY`. |
| `n8n reset-owner` | Remove the n8n user accounts (workflows are kept); the next visitor creates the owner again. |
| `n8n logs [-f]` | Container logs. |

Each delivered alert is the full Wazuh alert JSON, or the Logstash event for Suricata and Zeek. The integration retries three times and logs failures to the manager's `/var/ossec/logs/integrations.log`. A 404 means the workflow is not published or the path is wrong.

## Suricata

Needs `SURICATA=true`.

| Command | Description |
|---|---|
| `suricata [status]` | State, interface, loaded signatures, `eve.json` size and freshness, alerts in the last 24 hours by severity, the top 5 signatures, and where alerts go (Wazuh, Elasticsearch, n8n). |
| `suricata alerts [-n N] [--since 30m\|1h\|2d]` | Newest alerts: time, severity, protocol, source → destination, signature and sid. |
| `suricata test` | Requests a page whose body matches sid 2100498 (*GPL ATTACK_RESPONSE id check returned root*), then checks each hop: Suricata, the Wazuh alert (rule 100721) and Elasticsearch. |
| `suricata update-rules` | Download ET Open, fix ownership, hot-reload (`USR2`). Also runs daily in maintenance. |
| `suricata enable \| disable \| logs` | Same as `tools enable suricata` …, container logs. |

## Zeek

Needs `ZEEK=true`.

| Command | Description |
|---|---|
| `zeek [status]` | Current logs with size and age, and which ones Wazuh and ELK read (`ZEEK_WAZUH_LOGS`); number and size of the hourly copies. |
| `zeek show <log> [-n N]` | Readable lines of one log; `conn`, `dns`, `http`, `ssl`, `ssh`, `notice` and `weird` have their own format, other logs are shown as compact JSON. |
| `zeek notices [-n N]` | Same as `zeek show notice`. |
| `zeek top [hosts\|ports\|dns]` | Top talkers by bytes, top destination ports, or top DNS names in the current hour. |
| `zeek test` | Requests a test page over plain HTTP and waits for it in `http.log`. |
| `zeek enable \| disable \| logs` | Same as `tools enable zeek` …, container logs. |

## Other tools

| Command | Description |
|---|---|
| `tools [status]` | Every tool: enabled, state, URL or interface. |
| `tools enable \| disable <tool>` | Set the flag in `.env` and apply. Tools: `n8n`, `grafana`, `portainer`, `suricata`, `zeek`. |
| `tools apply` | Start enabled tools and remove disabled ones (volumes kept). Then wire them in: Grafana user and datasource, Suricata rules, sensor sources in Wazuh and Logstash, the n8n integration on new managers, nginx ports. |
| `tools update-rules` | Same as `suricata update-rules`. |

Grafana gets an OpenSearch datasource and a **Wazuh alerts overview** dashboard (login `admin` / `GRAFANA_ADMIN_PASSWORD`). Portainer's admin password is `PORTAINER_ADMIN_PASSWORD`, applied on its first start.

## Console

The web UI (`CONSOLE=true`, `https://PUBLIC_HOST:CONSOLE_PORT`). The README lists its nine pages (Monitor: Overview, Map · Stack: Containers, Stacks, Storage · Access: Proxy, Logins · System: Settings, Terminal); each action is on one page only. Older addresses open the page that took them over, at the matching section: `#health` → Overview, `#ports` and `#reset` → Settings, `#volumes` → Storage, `#activity` → Terminal. While `CONSOLE_PASSWORD` is still the generated one, every API call except sign-in returns 403 `password_change_required` until `POST /api/password` (`current`, `new`, `repeat`, header `X-Vexor-CSRF`) sets one the user chose; the console remembers that in `.state/console-password-set`. `vexor console password --generate` makes the next sign-in ask again.

The slow reads (`json state`, `docker compose ps`, `docker stats` of the project's containers, `disk --json`, `json volumes`, `proxy ls`) are cached: a request gets the last value at once while one background refresh per key runs, and a warmer keeps what a browser reads fresh. A command that changes something makes the next read wait for new data; `?fresh=1` (the Refresh button) does the same. JSON is gzip-compressed for clients that accept it, and the UI files are revalidated with ETag (304 when unchanged).

`GET /api/map` (same sign-in and password rules, cached 2.5 s) returns the Map page's data: the containers of `COMPOSE_PROJECT_NAME` from one `docker inspect` (state, health, restarts, exit code, OOM, image, networks and IPs), rx/tx bytes, packets, errors and drops from `/proc/<pid>/net/dev` with rates against the previous sample (none on the first), listening ports and established connections from `/proc/<pid>/net/tcp`, `tcp6`, `udp` and `udp6` turned into client → server edges, an aggregated `external` entry, and services the layout enables but no container runs (`missing`). Containers on the host network get no counters (they would be the host's). When `/proc` cannot be read, `traffic` and `connections` are null and `limits` says why.

| Command | Description |
|---|---|
| `console [status]` | Whether the `vexor-console` service runs and the console answers. |
| `console url` | The console address. |
| `console enable \| disable` | Set `CONSOLE` and start or stop the service. `start`, `config apply` and `daemon install` keep it in step. |
| `console password [--generate]` | Show the login, or set a new password. |
| `console restart \| logs [N]` | Restart the service / its journal. A restart does not stop a command the console started. |
| `json state \| volumes` | Machine-readable stack state and volume sizes (what the console reads). |

---

## Setup

| Command | Description |
|---|---|
| `install [--fresh] [--force]` | First-time setup, safe to re-run. If it finds an earlier `.env`, certificates, state or volumes, it asks whether to reuse them (default) or start clean; without a terminal it reuses them. `--fresh` starts clean: it deletes the project's containers, volumes and generated files (backups are kept), because the old indexer volumes keep the old password hashes. `--force` installs even when a disk is nearly full. It checks prerequisites and sets `vm.max_map_count`, then creates `.env` and detects `PUBLIC_HOST`. It generates the passwords and the cluster key, removes the OpenSearch demo users, and creates the internal certificates and a local-CA dashboard certificate. Finally it starts the selected stack and waits until it is ready. |
| `info [--show-secrets]` | URLs and logins (Wazuh dashboard, Kibana, tools), agent and API ports, certificate mode. |
| `config show [--show-secrets]` / `get KEY` / `set KEY VALUE` | View or set values; keys with their own command are redirected to it. |
| `plan [KEY=VALUE ..] [--json]` | What an apply would change, without changing anything: settings since the last apply (or the ones given), containers recreated, created and removed (a compose dry-run against temp-rendered files), nginx changes, and the downtime each means. |
| `config edit` / `validate` / `apply` | Edit `.env` with validation and rollback / check it / apply it (renders nginx and the override, pulls missing images with retries, recreates what changed). |

## Run

| Command | Description |
|---|---|
| `start [svc..]` | Start everything `.env` enables (or the given services) and wait until it is ready. |
| `stop [svc..]` | Stop containers. Stopping the whole stack sets the *stopped* marker, so the watchdog leaves it alone. |
| `restart [svc..]` | Restart everything or the given services; managers are recreated. |
| `down` | Remove containers and the network. Volumes are kept. |
| `wait-ready [--timeout S] [--json] [svc..]` | Wait until the services (default: all enabled, 900 s) run, report healthy and answer: indexer, manager cluster and API, dashboard, Elasticsearch, Kibana, Logstash, n8n, Grafana, Portainer. Prints what it waits for, exits 0 when ready and 1 with a list of what is not. `install`, `start`, `restart`, `update` and CI use it; `doctor` uses the same check to say "still starting" instead of failing. |
| `status` | Containers (state, uptime, restarts, OOM), Wazuh clusters and agents, ELK health, n8n forwarding, disk, the last health check, due reminders. |

## What runs

| Command | Description |
|---|---|
| `soc [status] \| wazuh \| elk \| both` | See [ELK](#elk). |
| `node-type …`, `scale`, `indexers …` | See [Wazuh](#wazuh). |
| `tools …` | See [other tools](#other-tools). |

## Troubleshoot

| Command | Description |
|---|---|
| `doctor [--fix]` | About 60 checks across host, configuration, containers, Wazuh, proxy, agent ports, ELK, tools, n8n forwarding and logs. Each problem comes with a hint; `--fix` applies the [known repairs](#what-doctor---fix-repairs). Exit code 1 when a check failed. |
| `logs [svc..] [-f] [-n N] [--since T]` | Container logs. |
| `logs ossec \| api \| cluster \| alerts \| archives \| integrations [node] [-f]` | Wazuh's own log files inside a manager. |
| `logs errors [--since 1h]` / `logs size` | Error lines of every container / disk used by logs. |
| `shell [svc]` / `exec <svc> <cmd..>` | A shell or a command inside a container. |
| `support-bundle` | `support-<stamp>.tar.gz` with doctor, status, logs and configs; secrets masked. |

## Update

| Command | Description |
|---|---|
| `update [check]` | Configured and running Wazuh version against the latest stable 4.x. |
| `update apply [VER\|latest] [--no-backup] [--force]` | Pull first, back up, record a rollback point, switch, restart, verify. |
| `update rollback` / `update images` / `version` | Return to the previous version / re-pull current tags / versions. |

## Certificates

nginx serves one certificate for the Wazuh dashboard, Kibana and every web tool. Modes: `default`, `local` (local CA), `custom`, `letsencrypt`.

| Command | Description |
|---|---|
| `cert status` | Mode, names, issuer, expiry; whether `PUBLIC_HOST` is covered; internal node certificates. |
| `cert create [name\|ip ..]` | Issue from the local CA (kept, so clients trust it once). |
| `cert export-ca [dir]` / `cert serve-ca [port]` | The CA file plus trust steps for Windows, macOS, Linux, Firefox and AD / a temporary download page. |
| `cert import <crt> <key> [chain]` / `cert letsencrypt <domain> [--email E] [--staging] [--dns]` | Your own certificate / a public one. |
| `cert renew [--force]` / `cert use-default` / `cert internal-regen` | Renew under 30 days / built-in certificate / re-issue internal certificates. |

## Proxy routes

Open a Vexor service, or something on this host or your LAN, under its own name: `https://soc.example.com` instead of `https://<ip>:8080`. nginx answers on `ROUTES_HTTPS_PORT` (443) and `ROUTES_HTTP_PORT` (80, redirects to https and serves Let's Encrypt challenges). Both are published on `BIND_IP` only while at least one route exists. Names nginx does not know get no answer.

| Command | Description |
|---|---|
| `proxy ls [--json]` / `proxy show <host>` | Routes with target, TLS mode, certificate expiry and status / one route, its certificate and a DNS check. |
| `proxy add <host> <target> [--tls local\|letsencrypt\|off] [--websocket] [--max-body SIZE]` | Add a route. `<host>` is a domain, subdomain or IPv4 address. `<target>` is a Vexor service and port (`wazuh.dashboard:5601`, `n8n:5678`, `grafana:3000`, `kibana:5601`) or `[http(s)://]IP:PORT`; `127.0.0.1:PORT` means this host (through `host.docker.internal`, so the program must listen on `0.0.0.0` or the Docker bridge). Defaults: `--tls local`, `--max-body 100m`. |
| `proxy edit <host> [--target T] [--tls M] [--websocket\|--no-websocket] [--max-body SIZE]` | Change a route. |
| `proxy rm <host>` | Remove a route and its certificate. |
| `proxy cert <host> [--renew]` | Issue or re-issue the certificate. `maintenance` renews any with less than 30 days left. |
| `proxy cert-file <host> [ca\|cert]` / `proxy cert-file ca` | Path of the route certificate or the local CA (public files only; the console's downloads use it). |
| `proxy apply` | Render, test and reload again, for example after restoring `routes.json`. |

Every change renders `nginx.conf`, tests it with `nginx -t` (inside nginx, or in a one-off nginx container when the ports change), and only then reloads or recreates nginx. If the test fails, `routes.json`, `nginx.conf` and the override go back to what they were and nginx keeps running. The Wazuh dashboard, tool and agent servers are not touched.

**Certificates.** `local` signs a certificate for the host (DNS or IP name) with the same local CA as `vexor cert create`, stored in `config/nginx/routes-certs/<host>.pem` (key `0600`). `letsencrypt` asks Let's Encrypt over HTTP-01: the name must resolve to this server and public port 80 must reach `ROUTES_HTTP_PORT`; until the certificate arrives the route answers 503 on http. `off` serves plain HTTP. Only one IP-address route can use TLS, because clients send no name for an IP address.

**DNS.** Create an A record for each name pointing at this server's address (in your DNS provider, AD, Pi-hole or router), or for a test add `SERVER-IP soc.example.com` to the client's hosts file. Behind NAT, use the public address and forward the two ports. `doctor` warns when a name does not resolve to this machine.

**Trust the local CA** once per device (download it from the console's Proxy page, or `vexor cert export-ca`):

- Windows: double-click the `.crt` → Install → Local Machine → Trusted Root Certification Authorities, or `Import-Certificate -FilePath .\ca.crt -CertStoreLocation Cert:\LocalMachine\Root` in an admin PowerShell.
- macOS: `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt`
- Linux: `sudo cp ca.crt /usr/local/share/ca-certificates/vexor-local-ca.crt && sudo update-ca-certificates`; Firefox: Settings → Privacy & Security → Certificates → Authorities → Import.
- Android: Settings → Security → Encryption & credentials → Install a certificate → CA certificate.
- iPhone / iPad: open the file in Safari → install the profile in Settings, then General → About → Certificate Trust Settings → turn on full trust.
- Company-wide: Group Policy → Public Key Policies → Trusted Root Certification Authorities → Import.

```bash
vexor proxy add soc.example.com wazuh.dashboard:5601
vexor proxy add n8n.example.com n8n:5678 --websocket --tls letsencrypt
vexor proxy add printer.lan http://192.168.1.50:80 --tls off
```

## Security

| Command | Description |
|---|---|
| `passwd admin \| kibanaserver \| api [--generate]` | Change a Wazuh password on the running stack and in `.env`; indexer pushes roll back on failure. |
| `elk reset-password` | New `elastic` password. |
| `n8n credentials` | Least-privilege users for n8n (see [n8n](#n8n)). |
| `agents password on \| off \| show` | Enrollment password. |

Wazuh password policy: 8–64 characters from letters, digits and `. * + ? -`, with an upper-case letter, a lower-case letter, a digit and a symbol. Wazuh API user names are 4–64 characters.

## Logins

| Command | Description |
|---|---|
| `login [service\|container ..] [--json]` | URL, user and password of every login Vexor manages: Wazuh dashboard, indexer and API, the n8n API user, the enrollment password, Kibana and Elasticsearch (and their internal users), Grafana, Portainer, the n8n webhook token, the console. Without arguments: everything that is enabled. Names such as `wazuh.master`, `kibana`, `grafana`, `elk` or `wazuh` select a subset; nginx, Suricata and Zeek have no login. The console's Logins page shows the same, with passwords hidden until revealed. |

## Data

| Command | Description |
|---|---|
| `backup [run] \| list \| register` | Wazuh indexer snapshot, Elasticsearch snapshot (`vexor-*` + Kibana saved objects, when ELK runs), master state, n8n, Grafana and Portainer volumes, configuration; prunes old backups and snapshots. |
| `backup restore-es <es-snap-id> [--indices P] [--rename] [--kibana]` | Restore Elasticsearch indices (and with `--kibana` the saved objects) from an `es-snap-*` snapshot. |
| `backup restore-snapshot <id> [--indices P] [--rename]` / `restore-manager <stamp>` / `restore-config <file>` | Restore indices / agent keys, rules and groups / `.env` and `config/`. |
| `n8n backup [dir]` | Workflows and credentials as JSON. |
| `retention [status\|apply]` | Deletion policies for Wazuh and Elasticsearch data (`RETENTION_DAYS`, 0 = keep forever). `status` shows them and the indices they cover; `apply` sets them. Also runs at start, after install and in maintenance. |
| `prune-logs` | Delete old rotated manager logs. |
| `volumes ls \| orphans \| backup <vol\|all> [--stop] \| restore <vol> <file> \| rm <vol> \| prune [--yes]` | Project volumes. `orphans` lists volumes no service of the current layout uses (old worker or indexer data), with sizes. `prune` deletes them after you type DELETE; volumes still held by a container and the data of switched-off tools are skipped. `vexor plan` mentions them. |
| `disk [--json]` | Size, used, free and percent of every filesystem Docker uses (Docker root, volumes, containerd image store, `BACKUP_DIR`, the checkout) with their roles, plus the size of Vexor's volumes and images. `--json` prints `{"filesystems":[{"mount","size","used","avail","pct","roles":[...]}]}` (bytes). |
| `images prune [--yes]` | Remove old image versions of this stack (same repository, other tag) that no container uses. Offered at the end of `update apply`. |
| `reset [containers\|data\|full\|purge]` | From removing containers up to a full wipe; backups are never deleted. |
| `uninstall [--keep-data] [--images] [--yes]` | Remove Vexor: systemd units, PATH link, the containers, network and volumes of the compose project (and its `-certs` helper), and the generated files in the checkout (`.env`, `.state`, certificates, `backups/` inside the checkout, `reports/`, `tools-data/` and the like). It shows a plan and asks first. Git-tracked files and other projects are never touched. `--keep-data` keeps the volumes and files. `--images` also removes the stack's images unless another container uses them. Running it again prints "already clean". |
| `migrate [--yes]` | Rename the Docker project `wazuh` (installs before 2.0) to `vexor`: copies and verifies every volume, removes the old containers and network, starts the stack. The old volumes are removed only after you confirm. Also removes unused old Shuffle Wazuh app images. |

## Health automation

| Command | Description |
|---|---|
| `autoheal` | What the health timer runs: `doctor --fix`, a re-check, the result in `.state/health.last`; remaining problems produce an AI report and a reminder. |
| `notify [status] \| test \| send <fail\|warn\|ok\|info> <msg>` | Health alerts: to `NOTIFY_URL` (Slack, Teams, Discord, JSON) or, when empty, to the n8n webhook. Sent by the hourly check (`NOTIFY_ON`, repeated every `NOTIFY_REPEAT_HOURS`, then a recovered message) and when the watchdog starts containers. |
| `ai-context [--print]` | One Markdown report covering the architecture and data flow (including n8n forwarding), settings, host, containers, the full doctor output, Wazuh and ELK state, recent errors and the action history. Secrets are masked. |
| `reminders [list] \| done <id>` | Follow-up tasks; shown in `status`, `doctor` and the SSH login summary. |
| `watchdog` / `maintenance` / `motd` | One watchdog pass / daily maintenance / the login summary. |

## Automation

| Command | Description |
|---|---|
| `daemon install` | Sets up: `/usr/local/bin/vexor`, bash completion, `vexor.service` at boot, the `vexor-watchdog` (5 min), `vexor-health` (`HEALTH_INTERVAL`), `vexor-backup` and `vexor-maintenance` timers, and the login summary. |
| `daemon uninstall \| status \| logs [N]` | Remove (the stack keeps running) / timers / journal. |
| `completion [install]` | Bash completion, including every stack subcommand. |

---

## What `doctor --fix` repairs

| Problem | Automatic repair |
|---|---|
| `vm.max_map_count` too low | Set and persist it |
| `.env` readable by others, a duplicate key, an empty value with an inline comment | `chmod 600`, comment out the earlier key, move the comment |
| Demo indexer users log in with public default passwords | Remove them and push `internal_users.yml` |
| A manager runs an older `ossec.conf` than `config/` | Recreate it |
| Wazuh rejects events with *Too many fields for JSON decoder* (Suricata stats records) | Restrict the Suricata source to alert and anomaly records, recreate the master |
| `custom-n8n` script missing or outdated on a manager | Install it and recreate that manager |
| n8n integration block missing from a manager config | Rewrite the blocks, recreate the managers |
| Cluster key differs between manager configs | Sync it, restart the managers |
| nginx out of date (upstreams, redirect, tool or Kibana servers) | Re-render, reload or recreate nginx |
| Stack or service not running, image missing | Pull with retries, `docker compose up -d` |
| Wazuh indices read-only, unassigned shards, retention or snapshot repository missing | Clear the block, retry allocation, create the policy or repository |
| Worker missing, core daemon down, filebeat cannot reach the indexer | Restart that manager |
| Elasticsearch yellow, read-only, ILM or template missing | Replicas 0, clear the block, apply them |
| Logstash writer or `kibana_system` login fails, data views missing | Re-create users and roles, reset the password, add the views |
| A web tool not answering, Grafana user broken, Suricata with 0 signatures | Restart it, re-create the user, load the rules |
| Any disk Docker uses above `DISK_WARN_PCT` | Prune old manager logs and dangling images (`doctor` fails above `DISK_FAIL_PCT`) |

Problems reported with a hint only include:

- a wrong password or an expired custom certificate
- a port used by another program or a missing interface
- too little RAM
- an n8n workflow that is not published
- an integration webhook that keeps failing

---

## Files and state

| Path | Content |
|---|---|
| `.env` | Settings and secrets (`chmod 600`) |
| `docker-compose.override.yml` | Generated: nginx ports, single-indexer URL, sensor mounts, proxy route ports and mounts |
| `config/nginx/routes.json` | Proxy routes (`vexor proxy`); `routes-certs/` holds their certificates, `acme/` the Let's Encrypt challenge files. Saved by `backup` with the rest of `config/` |
| `config/wazuh_custom/` | Detection files you save: `rules/`, `decoders/`, `lists/`. Git-ignored, backed up with `config/`, pushed to the managers on every save and apply. Versions in `.state/detection-history/`. |
| `config/detection-templates/` | Templates for the Detection page and `wazuh rules\|decoders templates` (rules, decoders, a sample list). Tracked in git. |
| `config/tools/` | Generated: `wazuh/custom-n8n.py` and the tool rules, `n8n/vexor-soc-alerts.workflow.json`, Grafana provisioning, the Zeek script, the Portainer password file |
| `config/elk/` | Generated: Logstash settings and pipeline (follows `SOC`, sensors and the n8n link) |
| `tools-data/` | Suricata and Zeek logs |
| `.state/` | `history.log`, `health.last`, `reminders`, applied node type, rollback version |
| `reports/ai-context-*.md` | AI reports (the last 20) |
| `backups/` | Snapshots, configuration, volumes, n8n exports |

---

## Exit codes

`0` means success (for `doctor`: no failed checks; warnings are allowed). `1` means an error, an aborted confirmation, or failed `doctor` checks:

```bash
vexor --no-color doctor > /tmp/doctor.txt || mail -s "Vexor doctor failed" admin@example.com < /tmp/doctor.txt
```

---

## Extending vexor

The script is divided into sections, each starting with a `# ====` header.

- **A doctor check:** add it to `cmd_doctor`, `elk_doctor` or `n8n_doctor` with `d_pass`, `d_warn` or `d_fail "<message>" "<hint>"`. If a safe repair exists, add `d_fix "<what>" && <repair>`.
- **A command:** add `cmd_<name>()`, a line in the `case` of `main`, a line in `cmd_help` and the words in `completion_script`. Call `take_lock` when the command changes anything.
- **A `.env` key:** add it to `ensure_env_defaults` and `.env.example` (never with a comment after an empty value).
- **A tool:** add it to `TOOLS`, a service with its own profile in `ensure_tools_compose`, and its wiring in `tools_prepare` / `tools_post`.

CI runs `bash -n`, ShellCheck, compose validation for every SOC mode and a secret scan on each push. Test anything that changes a cluster on a sandbox copy with its own `COMPOSE_PROJECT_NAME` and ports.
