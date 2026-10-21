// The Vexor stack model: which containers a .env starts, their host ports, the data flows between them,
// and the recommended RAM. Values follow vexor 1.2 (docker-compose*.yml, .env.example, README).

export const LANES = [
  { id: "outside", label: "outside" },
  { id: "edge", label: "edge · host network" },
  { id: "engine", label: "analysis" },
  { id: "store", label: "storage" },
  { id: "app", label: "UIs + automation" },
];

export const NODES = {
  agents:            { lane: "outside", sub: "endpoints", ext: true },
  traffic:           { lane: "outside", sub: "SNIFF_INTERFACE", ext: true },
  beats:             { lane: "outside", sub: "Filebeat · Agent", ext: true },
  browser:           { lane: "outside", sub: "admins", ext: true },
  nginx:             { lane: "edge", sub: "TLS · balancer" },
  suricata:          { lane: "edge", sub: "IDS · ET Open" },
  zeek:              { lane: "edge", sub: "JSON logs" },
  "wazuh.master":    { lane: "engine", sub: "rules · API" },
  "wazuh.worker":    { lane: "engine", sub: "analysis" },
  "wazuh2.worker":   { lane: "engine", sub: "analysis" },
  "wazuh3.worker":   { lane: "engine", sub: "analysis" },
  logstash:          { lane: "engine", sub: "pipeline" },
  "wazuh1.indexer":  { lane: "store", sub: "wazuh-alerts-*" },
  "wazuh2.indexer":  { lane: "store", sub: "replica" },
  "wazuh3.indexer":  { lane: "store", sub: "replica" },
  elasticsearch:     { lane: "store", sub: "vexor-*" },
  "wazuh.dashboard": { lane: "app", sub: ":8080" },
  kibana:            { lane: "app", sub: ":55601" },
  n8n:               { lane: "app", sub: ":55678 · webhook" },
  grafana:           { lane: "app", sub: ":53000" },
  portainer:         { lane: "app", sub: ":59443" },
};

export const PORTS = {
  nginx: "8080 · 1514 · 1515",
  "wazuh.master": "55000 · 514/udp",
  "wazuh1.indexer": "127.0.0.1:9200",
  elasticsearch: "127.0.0.1:59200",
  logstash: "55044",
  kibana: "55601 (nginx)",
  n8n: "55678 (nginx)",
  grafana: "53000 (nginx)",
  portainer: "59443 (nginx)",
  suricata: "host network",
  zeek: "host network",
};

export const TOOLS = ["n8n", "suricata", "zeek", "grafana", "portainer"];

export const DEFAULT_CONFIG = { soc: "wazuh", node: "single", workers: 1, tools: ["n8n", "suricata"] };

export const hasWazuh = (c) => c.soc !== "elk";
export const hasElk = (c) => c.soc !== "wazuh";
export const isMulti = (c) => hasWazuh(c) && c.node === "multi";
export const toolOn = (c, t) => c.tools.includes(t);

export function managers(c) {
  if (!hasWazuh(c)) return [];
  const m = ["wazuh.master"];
  if (isMulti(c)) ["wazuh.worker", "wazuh2.worker", "wazuh3.worker"].slice(0, c.workers).forEach((w) => m.push(w));
  return m;
}
export function indexers(c) {
  if (!hasWazuh(c)) return [];
  return isMulti(c) ? ["wazuh1.indexer", "wazuh2.indexer", "wazuh3.indexer"] : ["wazuh1.indexer"];
}

// containers in the order `vexor status` lists them
export function services(c) {
  const s = [...managers(c), ...indexers(c)];
  if (hasWazuh(c)) s.push("wazuh.dashboard");
  s.push("nginx");
  if (hasElk(c)) s.push("elasticsearch", "logstash", "kibana");
  ["n8n", "grafana", "portainer", "suricata", "zeek"].forEach((t) => toolOn(c, t) && s.push(t));
  return s;
}

// nodes drawn in the diagram (containers + outside sources)
export function visibleNodes(c) {
  const v = [];
  if (hasWazuh(c)) v.push("agents");
  if (toolOn(c, "suricata") || toolOn(c, "zeek")) v.push("traffic");
  if (hasElk(c)) v.push("beats");
  v.push("browser");
  return v.concat(services(c));
}

// edges: [from, to, kind]  kind: data | ui | act
export function edges(c) {
  const e = [];
  const mg = managers(c);
  const ix = indexers(c);
  const add = (a, b, k = "data") => e.push([a, b, k]);
  if (hasWazuh(c)) {
    add("agents", "nginx");
    mg.forEach((m) => add("nginx", m));
    mg.forEach((m) => add(m, "wazuh1.indexer"));
    ix.slice(1).forEach((i) => add("wazuh1.indexer", i));
    add("wazuh.dashboard", "wazuh1.indexer", "ui");
  }
  add("browser", "nginx", "ui");
  if (hasWazuh(c)) add("nginx", "wazuh.dashboard", "ui");
  if (hasElk(c)) add("nginx", "kibana", "ui");
  ["n8n", "grafana", "portainer"].forEach((t) => toolOn(c, t) && add("nginx", t, "ui"));
  ["suricata", "zeek"].forEach((t) => {
    if (!toolOn(c, t)) return;
    add("traffic", t);
    if (hasWazuh(c)) add(t, "wazuh.master");
    if (hasElk(c)) add(t, "logstash");
  });
  if (hasElk(c)) {
    add("beats", "logstash");
    add("logstash", "elasticsearch");
    add("kibana", "elasticsearch", "ui");
    if (hasWazuh(c)) mg.forEach((m) => add(m, "logstash"));
  }
  if (toolOn(c, "grafana") && hasWazuh(c)) add("grafana", "wazuh1.indexer", "ui");
  if (toolOn(c, "n8n")) {
    if (hasWazuh(c)) {
      mg.forEach((m) => add(m, "n8n"));
      add("n8n", "wazuh.master", "act");
    } else {
      add("logstash", "n8n");
      add("n8n", "elasticsearch", "act");
    }
  }
  return e;
}

// recommended host RAM (README: wazuh single 8 / multi 16, +4 for ELK, ELK alone 6, tools 0.3-1 each)
const TOOL_RAM = { n8n: 0.5, grafana: 0.3, portainer: 0.3, suricata: 1, zeek: 1 };
export function ramGB(c) {
  let r = c.soc === "elk" ? 6 : isMulti(c) ? 16 : 8;
  if (c.soc === "both") r += 4;
  c.tools.forEach((t) => (r += TOOL_RAM[t] || 0));
  return r;
}

export function hostPorts(c) {
  const p = [];
  if (hasWazuh(c)) p.push("8080", "1514", "1515", "514/udp", "55000");
  if (hasElk(c)) p.push("55601", "55044");
  if (toolOn(c, "n8n")) p.push("55678");
  if (toolOn(c, "grafana")) p.push("53000");
  if (toolOn(c, "portainer")) p.push("59443");
  return p;
}

export function envText(c) {
  const on = (t) => (toolOn(c, t) ? "true" : "false");
  const lines = [
    ["#", ".env (the settings that decide what runs)"],
    ["SOC", c.soc],
  ];
  if (hasWazuh(c)) {
    lines.push(["NODE_TYPE", c.node]);
    if (isMulti(c)) lines.push(["WORKER_COUNT", String(c.workers)], ["INDEXER_COUNT", "3"]);
  }
  ["n8n", "suricata", "zeek", "grafana", "portainer"].forEach((t) => lines.push([t.toUpperCase(), on(t)]));
  if (toolOn(c, "n8n")) lines.push(["N8N_ALERT_LEVEL", "7"]);
  const cmds = ["# from a fresh `vexor install`"];
  if (c.soc !== "wazuh") cmds.push(`vexor soc ${c.soc}`);
  if (isMulti(c)) {
    cmds.push("vexor node-type multi");
    if (c.workers > 1) cmds.push(`vexor scale ${c.workers}`);
  }
  if (toolOn(c, "suricata")) cmds.push("vexor suricata enable && vexor suricata test");
  if (toolOn(c, "zeek")) cmds.push("vexor zeek enable && vexor zeek test");
  if (toolOn(c, "n8n")) cmds.push("vexor n8n enable", "vexor n8n connect && vexor n8n workflow", "vexor n8n credentials");
  ["grafana", "portainer"].forEach((t) => toolOn(c, t) && cmds.push(`vexor tools enable ${t}`));
  cmds.push("vexor doctor");
  return { lines, cmds };
}
