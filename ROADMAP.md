# Vexor V2 roadmap

V1 proved the idea: one host, one CLI, five security tools wired together and kept healthy. V2 removes the limits V1 runs into, without breaking what works.

**Compatibility promise.** Every v1 command keeps its name and behaviour. An existing `.env` is imported by `vexor migrate`, and the stack keeps running during the move.

**Phases.** `alpha` (foundations), `beta` (feature-complete, used on test stacks), `2.0` (stable release), `2.x` (after 2.0).

**Priority.** `must` ships in 2.0, `should` is planned for 2.0, `could` comes when there is time or a contributor.

The landing page renders this file live: <https://eswarans-06.github.io/Vexor/roadmap.html>

---

## Platform

### Stack modules
- **Priority:** must
- **Phase:** alpha
- **Fixes:** one 4,900-line script
- **Why:** Adding a stack means editing compose generation, doctor checks, help, completion and the AI report in separate places of one script.
- **What:** Each stack (Wazuh, ELK, n8n, Suricata, Zeek, and new ones) becomes a module folder with a manifest: compose fragment, `.env` keys, ports, doctor checks with repairs, commands and migrations. The core discovers modules; `vexor module list | enable | disable`.

### Declarative config and `vexor plan`
- **Priority:** must
- **Phase:** alpha
- **Fixes:** surprise restarts
- **Why:** Today a change is applied directly; you learn what was recreated afterwards.
- **What:** A validated `vexor.yaml` (schema-checked, comments allowed anywhere) replaces `.env` as the source of truth. `vexor plan` prints which containers, files and users would change and the expected downtime; `vexor apply` does it. `.env` stays readable for one major version.

### Secrets out of plain text
- **Priority:** must
- **Phase:** beta
- **Fixes:** passwords in .env
- **Why:** Every password and key sits in one `chmod 600` file; a copied backup leaks all of them.
- **What:** Secrets encrypted at rest with age (sops-compatible), decrypted only while rendering. `vexor secrets rotate <name>` rotates one secret everywhere it is used, with rollback.

### A single static binary
- **Priority:** should
- **Phase:** beta
- **Fixes:** one 4,900-line script
- **Why:** Bash limits testing, error handling and parallel work such as health checks across many containers.
- **What:** The core rewritten as one Go binary with the same command names. The bash script stays as a thin shim during the move, so timers and habits keep working.

## Scale and resilience

### Multi-host stacks
- **Priority:** must
- **Phase:** 2.0
- **Fixes:** single host
- **Why:** The clusters protect against a failed container, not a failed host.
- **What:** Place indexers, Elasticsearch, sensors and workers on several hosts through SSH and Docker contexts. Agents still use one address; nginx balances across hosts. `vexor host add | drain | remove` moves data safely, the way `node-type` does today.

### Elasticsearch in backups
- **Priority:** must
- **Phase:** beta
- **Fixes:** no Elasticsearch backup
- **Why:** `vexor backup` covers Wazuh, n8n and the configuration, but not the ELK data.
- **What:** A snapshot repository for Elasticsearch, included in the daily backup with the same retention and `restore-snapshot` flow. Multi-node Elasticsearch follows multi-host.

### Wazuh 5.x
- **Priority:** should
- **Phase:** 2.0
- **Fixes:** Wazuh 4.x only
- **Why:** Wazuh 5 changes the deployment layout, so `vexor update apply` stops at 4.x.
- **What:** A Wazuh 5 module, and a guided `vexor update apply 5.x` that backs up, migrates agents and indices, and can roll back.

### Rolling upgrades
- **Priority:** should
- **Phase:** 2.0
- **Fixes:** upgrade downtime
- **Why:** Upgrades restart whole groups of containers at once.
- **What:** One node at a time with health gates (cluster green, agents reconnected, doctor clean) before moving on; automatic stop and rollback when a gate fails.

## Detection and response

### Workflow library for n8n
- **Priority:** must
- **Phase:** beta
- **Fixes:** one starter workflow
- **Why:** The starter workflow routes by severity but leaves every action to you.
- **What:** Ready workflows: Slack, Teams and email alerts; VirusTotal and AbuseIPDB enrichment; ticket creation; and blocking an IP through active response after a one-click approval. `vexor n8n workflow add <name>`.

### n8n credentials set up for you
- **Priority:** should
- **Phase:** beta
- **Fixes:** manual credential setup
- **Why:** `vexor n8n credentials` prints the users; you still type them into n8n.
- **What:** Vexor creates the Wazuh API and Elasticsearch credentials inside n8n through its API, so imported workflows run without editing.

### Sigma rules
- **Priority:** should
- **Phase:** 2.0
- **Fixes:** vendor-specific rules
- **Why:** Detection logic written once should run in Wazuh and Elasticsearch alike.
- **What:** `vexor rules add <sigma.yml>` converts Sigma rules into Wazuh rules and Elasticsearch detection queries, tests them with sample logs, and reports which ones fired.

### Threat intelligence module
- **Priority:** should
- **Phase:** 2.0
- **Fixes:** no intel feeds
- **Why:** Alerts are richer when known-bad IPs, domains and hashes are flagged as they arrive.
- **What:** Optional MISP or OpenCTI, or plain feed URLs, turned into Wazuh CDB lists, Zeek intel files and Suricata IP reputation; refreshed daily by maintenance.

### Case management module
- **Priority:** could
- **Phase:** 2.x
- **Fixes:** alerts without cases
- **Why:** Analysts need somewhere to group alerts, notes and evidence.
- **What:** DFIR-IRIS (or TheHive) as an optional module; n8n opens cases from high-severity alerts.

### Zeek packages
- **Priority:** could
- **Phase:** 2.x
- **Fixes:** stock Zeek scripts
- **Why:** JA4 fingerprints and the intel framework catch what plain logs miss.
- **What:** Managed Zeek packages (JA4, intel, file extraction) enabled per host.

## Operations and visibility

### Health notifications
- **Priority:** must
- **Phase:** alpha
- **Fixes:** silent failures
- **Why:** When the hourly `doctor --fix` cannot repair something, the result only shows at SSH login and in the AI report.
- **What:** Doctor and autoheal results sent to n8n, Slack or email, with the hint and the AI report attached.

### Stack health metrics
- **Priority:** must
- **Phase:** beta
- **Fixes:** health only in the terminal
- **Why:** Heap, disk, queue and execution trends predict trouble before the doctor sees it.
- **What:** Prometheus exporters for the indexers, Elasticsearch, Logstash, n8n and containers, plus a "Vexor health" Grafana dashboard.

### `vexor console`
- **Priority:** should
- **Phase:** 2.0
- **Fixes:** terminal-only management
- **Why:** Not everyone on a SOC team lives in a shell.
- **What:** A local web console behind nginx with login: the live topology (the landing-page simulator, fed by real `vexor status`), doctor runs, logs and reminders. Read-only by default; actions need an admin role.

## Security

### Encrypted Beats input and safer defaults
- **Priority:** must
- **Phase:** alpha
- **Fixes:** Beats input without TLS
- **Why:** The Logstash Beats port accepts plain TCP, and agent enrollment is open until you set a password.
- **What:** TLS on the Beats input with certificates from the local CA, and an enrollment password generated by `vexor install`.

### Single sign-on for every UI
- **Priority:** should
- **Phase:** 2.0
- **Fixes:** one login per tool
- **Why:** Wazuh, Kibana, Grafana, Portainer and n8n each keep their own users.
- **What:** OIDC (Entra ID, Google, Keycloak) through oauth2-proxy in nginx, with group-to-role mapping where the tool supports it.

## Quality and delivery

### Integration tests in CI
- **Priority:** must
- **Phase:** alpha
- **Fixes:** checks only on a live host
- **Why:** CI checks syntax and the compose model; real behaviour is tested by hand on a server.
- **What:** GitHub Actions brings up a single-node stack, runs `vexor doctor`, `suricata test`, `zeek test` and `n8n test`, and switches SOC modes, on every pull request.

### Packages and arm64
- **Priority:** could
- **Phase:** 2.x
- **Fixes:** git-clone install only
- **Why:** A package manager install is easier to audit and update.
- **What:** `.deb` and `.rpm` packages, a signed release binary, and arm64 support where the upstream images allow it.

### Versioned docs
- **Priority:** could
- **Phase:** 2.x
- **Fixes:** docs for main only
- **Why:** Users on 1.x need docs that match their version.
- **What:** The guide and command reference built per tag, with a version switcher and full-text search.
