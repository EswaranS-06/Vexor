# vexor: command reference

`vexor` is a single bash script that manages the whole Vexor stack described in [README.md](README.md). It covers setup, choosing what runs (SOC, node type, tools), certificates, passwords, agents, upgrades, backups, troubleshooting and self-healing.

```
vexor <command> [subcommand] [options]
```

---

## Contents

- [Installation](#installation)
- [Conventions](#conventions)
- [Change management](#change-management)
- Commands: [setup](#setup) · [run](#run) · [what runs](#what-runs-soc-node-type-tools) · [troubleshoot](#troubleshoot) · [update](#update) · [certificates](#certificates) · [security](#security) · [agents](#agents) · [indexer cluster](#indexer-cluster) · [Shuffle SOAR](#shuffle-soar) · [data](#data) · [health automation](#health-automation) · [automation](#automation)
- [What `doctor --fix` repairs](#what-doctor---fix-repairs)
- [Files and state](#files-and-state)
- [Exit codes](#exit-codes)
- [Extending vexor](#extending-vexor)

---

## Installation

The script lives in the repository root, next to `docker-compose.yml` and `.env`:

```bash
sudo ./vexor install          # first time; creates .env from .env.example
sudo ./vexor daemon install   # /usr/local/bin/vexor, completion, boot service, timers, login summary
```

It needs bash 4.4+, Docker Engine with Compose v2, `python3`, `openssl`, `curl`, `ss`, `flock`, and systemd for the daemon.

---

## Conventions

| Topic | Behaviour |
|---|---|
| **Root** | Every command except `help`, `version` and `completion` needs root; a non-root user is re-run through `sudo`. |
| **Global options** | `-y` / `--yes` answers every prompt. `-q` / `--quiet` prints less. `--no-color` gives plain output for scripts and logs. |
| **Service names** | Full names (`wazuh.master`) or aliases: `master`, `worker`, `worker2`, `worker3`, `indexer1`–`indexer3`, `dashboard`, `nginx`, plus the groups `managers` and `indexers`. ELK and tool services use their own names (`kibana`, `grafana` …). |
| **Confirmation** | Risky actions ask `[y/N]`. Destructive ones make you type `DELETE`, `RESTORE` or `REGEN`. `--yes` skips both. |
| **Locking** | Commands that change something take `/run/lock/vexor.lock`. Interactive commands wait up to 3 minutes for a running watchdog or health check; timers skip their run. |
| **Idempotent** | `install`, `start`, `config apply`, `tools apply`, `soc …`, `retention apply` and `daemon install` are safe to repeat. |
| **History** | Every changing command is logged to `.state/history.log`, secrets masked. `ai-context` includes it. |
| **Self-migration** | On every run `vexor` upgrades files written by older versions: new `.env` keys, compose layout, nginx template, old `wazuhctl` names and units. |
| **Settings** | Read from `.env`. A key defined twice resolves to its last definition, the same way Docker Compose does. |

---

## Change management

After editing `.env`: `vexor config validate`, then `vexor config apply`, then `vexor doctor`. Never use `down -v` or `reset` to apply settings, because they delete the data volumes.

| You changed | Apply with | Downtime |
|---|---|---|
| Plain values (ports, heap, log rotation, images) | `vexor config apply` | only the changed containers |
| `SOC` | `vexor soc <wazuh\|elk\|both>` | 1–3 min (ELK first start) |
| `NODE_TYPE` / `WORKER_COUNT` | `vexor node-type …` / `vexor scale …` | about 1–2 min |
| Tool flags | `vexor tools apply` | none for the Wazuh stack |
| Passwords | `vexor passwd …` | dependent containers |
| `WAZUH_VERSION` | `vexor update apply <version>` | a few minutes |
| `PUBLIC_HOST`, certificate names | `vexor cert create` | nginx (seconds) |
| Timer times | `vexor daemon install` | none |
| `config/wazuh_cluster/*.conf` | edit every manager file → `vexor restart managers` | managers are **recreated** |
| `config/nginx/nginx.conf.tpl` | `vexor config apply` | none (reload) |
| `config/wazuh_indexer/*.yml` | `vexor restart indexer1` …, one at a time | per node |

`restart` on a manager recreates the container, because the Wazuh image applies the mounted `ossec.conf` only to a fresh container.

---

## Setup

| Command | Description |
|---|---|
| `install` | First-time setup, safe to re-run. It checks prerequisites, sets `vm.max_map_count`, creates `.env` from `.env.example`, detects `PUBLIC_HOST`, generates passwords and the cluster key, removes the OpenSearch demo users, creates the internal certificates and a local-CA dashboard certificate, then starts the selected stack and waits until it is ready. |
| `info [--show-secrets]` | URLs and logins (Wazuh dashboard, Kibana, tools), agent and API ports, certificate mode, file locations. |
| `config show [--show-secrets]` / `get KEY` / `set KEY VALUE` | View or set values. Keys with their own command (passwords, version, workers, node type) are redirected to it. |
| `config edit` | Open `.env` in `$EDITOR`, validate it with Compose, and offer to restore the previous file if it is invalid. |
| `config validate` / `config apply` | Check `.env` with the compose files / apply it (renders nginx and the override, pulls missing images with retries, recreates only what changed, re-applies retention). |

## Run

| Command | Description |
|---|---|
| `start [svc..]` | Start the stack (or the given services) and wait until it is ready. Clears the *stopped* marker. |
| `stop [svc..]` | Stop containers. Stopping the whole stack sets the *stopped* marker, so the watchdog leaves it alone. |
| `restart [svc..]` | Restart everything or the given services; managers are recreated. |
| `down` | Remove containers and the network. Volumes are kept. |
| `scale <1-3>` | Number of workers in `NODE_TYPE=multi`; updates the nginx agent balancer. |
| `status` | Containers (state, uptime, restarts, OOM), Wazuh clusters and agents, ELK health, disk, the last health check, due reminders. |
| `health` | Detailed Wazuh indexer and manager state. |

## What runs: SOC, node type, tools

| Command | Description |
|---|---|
| `soc [status]` | Which stacks run, the Kibana and Beats endpoints. |
| `soc wazuh \| elk \| both` | Switch. `elk` stops Wazuh, keeping its data and agent keys. `both` copies every Wazuh alert into Elasticsearch (`vexor-wazuh-alerts-*`). Switching to ELK generates its passwords, creates the Logstash writer user and role, applies ILM retention and 0 replicas, and adds the Kibana data views. |
| `elk [status] \| explain \| reset-password` | Elasticsearch health and event counts; shard allocation explanation; reset the `elastic` password and store it in `.env`. |
| `node-type [status]` | Applied layout, the `.env` value, what is shared, any unfinished switch. |
| `node-type single [--dry-run] [--no-backup]` | Move to 1 manager and 1 indexer. Backs up, moves every shard to `wazuh1`, removes the workers (volumes kept). Agents keep their keys and address. |
| `node-type multi [--indexers 1\|3] [--dry-run] [--no-backup]` | Master plus `WORKER_COUNT` workers and 3 indexers. New indexers join the existing cluster and the replica copies are restored. |
| `tools [status]` | Every tool: enabled, state, URL. |
| `tools enable \| disable <tool>` | Set the flag in `.env` and apply. Tools: `n8n`, `grafana`, `portainer`, `suricata`, `zeek`. |
| `tools apply` | Start enabled tools, remove disabled ones (volumes kept), wire them in: Grafana user and datasource, Suricata rules, sensor log sources in Wazuh and Logstash, nginx ports. |
| `tools update-rules` | Download and hot-reload the Suricata rules (also daily during maintenance). |

A re-run of an interrupted `node-type` switch resumes it. Editing `NODE_TYPE` in `.env` and running `start` or `config apply` performs the same switch, after asking.

## Troubleshoot

| Command | Description |
|---|---|
| `doctor [--fix]` | About 60 checks across host, configuration, containers, Wazuh indexer and managers, proxy, agent ports, ELK, tools and logs. Each problem comes with a hint. `--fix` applies the [known repairs](#what-doctor---fix-repairs). Exit code 1 when a check failed. |
| `logs [svc..] [-f] [-n N] [--since T]` | Container logs. |
| `logs ossec \| api \| cluster \| alerts \| archives \| integrations [node] [-f]` | Wazuh's own log files inside a manager. |
| `logs errors [--since 1h]` / `logs size` | Error lines of every container / disk used by logs. |
| `shell [svc]` / `exec <svc> <cmd..>` | A shell or a command inside a container. |
| `indexer <METHOD> <path> [json]` | Raw Wazuh indexer API call, e.g. `vexor indexer GET '/_cat/indices?v'`. |
| `api <METHOD> <path> [json]` | Raw Wazuh API call (token handled), e.g. `vexor api GET /agents/summary/status`. |
| `cluster` | Manager cluster nodes and their last sync. |
| `support-bundle` | `support-<stamp>.tar.gz`: doctor and status output, logs, indexer state, configs; secrets masked. |

## Update

| Command | Description |
|---|---|
| `update [check]` | Configured and running Wazuh version compared with the latest stable 4.x; offers to upgrade. |
| `update apply [VER\|latest] [--no-backup] [--force]` | Pull images first, back up, record a rollback point, switch, restart, verify. Refuses downgrades and 5.x without `--force`. |
| `update rollback` | Back to the version before the last upgrade. |
| `update images` | Re-pull the current tags and nginx; recreate only what changed. |
| `version` | `vexor` and Wazuh versions. |

## Certificates

nginx serves one certificate for the Wazuh dashboard, Kibana and every web tool. Modes: `default` (built-in self-signed), `local` (local CA), `custom`, `letsencrypt`.

| Command | Description |
|---|---|
| `cert status` | Mode, subject, issuer, names, expiry; whether nginx serves it and `PUBLIC_HOST` is covered; internal node certificates. |
| `cert create [name\|ip ..]` | Issue a certificate from the local CA (the CA is kept, so clients trust it once). Without arguments it covers `PUBLIC_HOST`, the host IPs and names, and `CERT_EXTRA_SANS`. |
| `cert export-ca [dir]` / `cert serve-ca [port]` | The CA file plus trust steps (Windows, macOS, Linux, Firefox, AD) / a temporary download page for it. |
| `cert import <crt> <key> [chain]` | Use your own certificate; the certificate and key must match. |
| `cert letsencrypt <domain> [--email E] [--staging] [--dns]` | Public certificate via certbot (HTTP-01 on port 80, or a manual DNS record). |
| `cert renew [--force]` | Renew a local or Let's Encrypt certificate when fewer than 30 days are left. |
| `cert use-default` / `cert internal-regen` | Back to the built-in certificate / re-issue all internal node certificates (type `REGEN`). |

## Security

| Command | Description |
|---|---|
| `passwd admin \| kibanaserver \| api [--generate]` | Change a Wazuh password on the running stack and in `.env`. Indexer users are hashed and pushed with securityadmin, and rolled back if the push fails. |
| `agents password on [pw] \| off \| show` | Require a password for agent enrollment. |

Policy for Wazuh passwords: 8–64 characters from letters, digits and `. * + ? -`, including an upper-case letter, a lower-case letter, a digit and a symbol.

## Agents

| Command | Description |
|---|---|
| `agents list \| summary \| outdated` | Agents with status, node, version and OS / counts by status / agents older than the manager. |
| `agents enroll-cmd [linux\|rpm\|windows\|macos] [--name N] [--group G]` | Copy-paste install commands for this manager, including the enrollment password and non-default ports. |
| `agents remove <id[,id..]>` | Remove agents. |

## Indexer cluster

Usually handled by `node-type`; these are the underlying steps.

| Command | Description |
|---|---|
| `indexers status` | Node count, shards and disk per node, fixed-replica indices, leftover volumes. |
| `indexers 1 \| 3 [--dry-run] [--no-backup]` | Shrink 3 → 1 or grow 1 → 3 without data loss. |
| `indexers abort \| cleanup` | Undo an unfinished shrink / delete the old volumes of indexers 2 and 3 (type `DELETE`). A reminder appears `CLEANUP_REMIND_DAYS` after a shrink. |

## Shuffle SOAR

| Command | Description |
|---|---|
| `shuffle connect <webhook-url> [--level N] [--groups G]` | Forward alerts of level N or higher from **every** manager to a Shuffle webhook. Internal Shuffle hostnames are rewritten to `PUBLIC_HOST`. |
| `shuffle api-user` | Wazuh API user `shuffle` (readonly plus a `soar` role: agent restart/upgrade, active response, syscheck) for Shuffle's Wazuh app; authenticate it with JWT. |
| `shuffle status \| test \| disconnect` | Check, send a test alert, remove. |

## Data

| Command | Description |
|---|---|
| `backup [run] \| list \| register` | Wazuh indexer snapshot, master state, tool volumes, configuration; prunes old backups. |
| `backup restore-snapshot <id> [--indices P] [--rename]` / `restore-manager <stamp>` / `restore-config <file>` | Restore indices / agent keys, rules and groups / `.env` and `config/`. |
| `retention [show\|apply]` | Wazuh index retention (`INDEX_RETENTION_DAYS`). ELK retention is applied by `soc` and `config apply`. |
| `prune-logs` | Delete rotated manager logs older than `MANAGER_LOG_RETENTION_DAYS`. |
| `volumes ls \| backup <vol\|all> [--stop] \| restore <vol> <file> \| rm <vol> \| prune` | Project volumes. |
| `reset [containers\|data\|full\|purge]` | From removing containers up to a full wipe; backups are never deleted. Without a level you get a menu. |

## Health automation

| Command | Description |
|---|---|
| `autoheal` | What the health timer runs: `doctor --fix`, a re-check, the result saved to `.state/health.last`. Problems that remain produce an AI report and a reminder. |
| `ai-context [--print]` | One Markdown report: architecture and data flow, settings, host, containers, the full doctor output, Wazuh and ELK state, recent errors, the action history. Secrets are masked. |
| `reminders [list] \| done <id>` | Follow-up tasks; also shown in `status`, `doctor` and the SSH login summary. |
| `watchdog` / `maintenance` / `motd` | One watchdog pass / daily maintenance (logs, retention, certificates, Suricata rules, sensor log rotation, image cleanup) / the login summary. |

## Automation

| Command | Description |
|---|---|
| `daemon install` | `/usr/local/bin/vexor`, bash completion, `vexor.service` at boot, the `vexor-watchdog` (5 min), `vexor-health` (`HEALTH_INTERVAL`), `vexor-backup` (`BACKUP_TIME`) and `vexor-maintenance` (`MAINT_TIME`) timers, and `/etc/update-motd.d/99-vexor`. Removes the units of the old `wazuhctl` name. |
| `daemon uninstall \| status \| logs [N]` | Remove (the stack keeps running) / timers and next runs / journal of every `vexor*` unit. |
| `completion [install]` | Print or install the bash completion. |

---

## What `doctor --fix` repairs

| Problem | Automatic repair |
|---|---|
| `vm.max_map_count` too low | Set it and persist it in `/etc/sysctl.d/99-wazuh.conf` |
| `.env` readable by others, a duplicate key, or an empty value with an inline comment | `chmod 600`, comment out the earlier key, move the comment onto its own line |
| Demo indexer users log in with their public default passwords | Remove them from `internal_users.yml` and push it |
| A manager runs an older `ossec.conf` than `config/` | Recreate it |
| Cluster key differs between manager configs | Sync it and restart the managers |
| nginx out of date (worker upstreams, http→https redirect, tool or Kibana servers, old direct ports) | Re-render, reload, or recreate nginx |
| Stack or service not running, image missing | Pull with retries, then `docker compose up -d` |
| Wazuh indices read-only, unassigned shards, retention or snapshot repository missing | Clear the block, retry allocation (replicas 0 on one node), create the policy or repository |
| Worker missing from the cluster, core daemon down, filebeat cannot reach the indexer | Restart that manager |
| Wazuh dashboard 502/504 after 5 min | Restart it |
| Elasticsearch yellow, read-only, ILM or template missing | Replicas 0, clear the block, apply them |
| Logstash writer or `kibana_system` login fails, Kibana data views missing | Re-create users and roles, reset the password, add the data views |
| A web tool not answering (after its start-up time), Grafana indexer user broken, Suricata with 0 signatures | Restart it, re-create the user, download and load the rules |
| Docker disk above `DISK_WARN_PCT` | Prune old manager logs and dangling images |

Problems without an automatic repair are reported with a hint, for example: a wrong password, an expired custom certificate, a port used by another program, a missing interface, too little RAM, or a failing integration webhook. Under the health timer they also produce an AI report and a reminder.

---

## Files and state

| Path | Content |
|---|---|
| `.env` | Settings and secrets (`chmod 600`) |
| `docker-compose.override.yml` | Generated: nginx ports for the SOC and tools, the master's single-indexer URL and sensor mounts |
| `config/elk/`, `config/tools/` | Generated: Logstash pipeline, Grafana provisioning, Zeek script, Wazuh tool rules, Portainer password file |
| `tools-data/` | Suricata and Zeek logs |
| `.state/` | `history.log`, `health.last`, `reminders`, applied node type, rollback version, saved configs |
| `reports/ai-context-*.md` | AI reports (the last 20 are kept) |
| `backups/` | `snapshots/` (indexer repository), `config/`, `volumes/`, replaced certificates |

---

## Exit codes

`0` means success (for `doctor`: no failed checks; warnings are allowed). `1` means an error, an aborted confirmation, or failed `doctor` checks. That makes `doctor` usable from monitoring:

```bash
vexor --no-color doctor > /tmp/doctor.txt || mail -s "Vexor doctor failed" admin@example.com < /tmp/doctor.txt
```

---

## Extending vexor

The script is divided into sections, each starting with a `# ====` header.

- **A doctor check:** add it to `cmd_doctor` (or `elk_doctor`) using `d_pass`, `d_warn` or `d_fail "<message>" "<hint>"`. If a safe repair exists, add `d_fix "<what>" && <repair>`; it runs only with `--fix` or from the health timer.
- **A command:** add `cmd_<name>()`, a line in the `case` of `main`, a line in `cmd_help` and the words in `completion_script`. Call `take_lock` when the command changes anything.
- **A `.env` key:** add it to the block in `ensure_env_defaults`, with its comment on the line above (never on an empty value), and to `.env.example`.
- **A tool:** add it to `TOOLS`, a service with its own profile in `ensure_tools_compose`, and its wiring in `tools_prepare` / `tools_post`.

Before deploying, run `bash -n vexor` and `shellcheck -S warning vexor`, and test anything that changes a cluster on a sandbox copy with its own `COMPOSE_PROJECT_NAME` and ports.
