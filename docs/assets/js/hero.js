// Hero: replays a real Vexor session once (install → ELK → n8n → Suricata test → doctor).
// Output lines are taken from vexor 1.2 runs on a test host.
const SESSION = [
  { cmd: "sudo ./vexor install", out: [
    "passwords, cluster key and certificates generated",
    "OpenSearch demo users removed",
    "Wazuh dashboard: https://soc.lan:8080",
  ] },
  { cmd: "vexor soc both", out: [
    "Elasticsearch user vexor_logstash (write vexor-* only)",
    "Kibana data views: Wazuh alerts / Suricata / Zeek / Beats",
  ] },
  { cmd: "vexor n8n connect", out: [
    "alerts -> http://n8n:5678/webhook/vexor-alerts  (level >= 7)",
    "wazuh.master: integratord running",
  ] },
  { cmd: "vexor suricata test", out: [
    "Suricata raised the alert (sid 2100498)",
    "Wazuh turned it into an alert (rule 100721, level 7)",
  ] },
  { cmd: "vexor doctor --fix", out: [
    "52 passed, 2 warnings, 0 failed",
  ] },
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const reduced = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;
let token = 0;

function okLine(text) {
  const li = document.createElement("li");
  li.className = "s-ok";
  const b = document.createElement("b");
  b.textContent = "  ✔ ";
  li.append(b, document.createTextNode(text));
  return li;
}

async function run(list, stepEl, bar) {
  const my = ++token;
  list.replaceChildren();
  const total = SESSION.length;
  const instant = reduced();
  for (let i = 0; i < total; i++) {
    if (my !== token) return;
    const s = SESSION[i];
    stepEl.textContent = `${i + 1} / ${total}`;
    bar.style.transform = `scaleX(${(i + 1) / total})`;
    const li = document.createElement("li");
    li.className = "s-cmd";
    list.appendChild(li);
    if (instant) {
      li.textContent = s.cmd;
    } else {
      const caret = document.createElement("span");
      caret.className = "s-caret";
      for (let k = 1; k <= s.cmd.length; k++) {
        if (my !== token) return;
        li.textContent = s.cmd.slice(0, k);
        li.appendChild(caret);
        await sleep(28 + Math.random() * 30);
      }
      await sleep(260);
      caret.remove();
    }
    for (const o of s.out) {
      if (my !== token) return;
      const line = okLine(o);
      if (!instant) line.classList.add("s-line-in");
      list.appendChild(line);
      if (!instant) await sleep(240);
    }
    const gap = document.createElement("li");
    gap.className = "s-gap";
    list.appendChild(gap);
    if (!instant) await sleep(420);
  }
}

export function initHero() {
  const list = document.querySelector("[data-session]");
  if (!list) return;
  const stepEl = document.querySelector("[data-session-step]");
  const bar = document.querySelector("[data-session-progress]");
  const replay = document.querySelector("[data-session-replay]");
  replay.addEventListener("click", () => run(list, stepEl, bar));
  run(list, stepEl, bar);
}
