const $ = (id) => document.getElementById(id);
const el = (tag, text, cls) => { const n = document.createElement(tag); if (text != null) n.textContent = text; if (cls) n.className = cls; return n; };
const DRAFT_LABELS = { cert_in: "CERT-In report", dpdp_board: "DPDP Board intimation", principal_notice: "Notice to affected people" };
let state = null, tab = "cert_in", ticker = null;

function localNow() { const d = new Date(Date.now() - new Date().getTimezoneOffset() * 60000); return d.toISOString().slice(0, 16); }

async function api(path, body) {
  const res = await fetch(path, body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : undefined);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Request failed (" + res.status + ")");
  return data;
}

async function init() {
  $("noticed").value = localNow();
  api("/healthz").then((h) => {
    $("engine").textContent = h.gemini ? "Gemini: " + h.model : "Offline rules engine (no Gemini key set)";
    $("engine").classList.toggle("live", h.gemini);
  }).catch(() => { $("engine").textContent = "engine unknown"; });
  for (const s of await api("/api/samples")) {
    const b = el("button", s.label);
    b.type = "button";
    b.onclick = async () => {
      const full = await api("/api/samples/" + s.id);
      $("logs").value = full.logs;
      $("org-name").value = full.org.name; $("org-sector").value = full.org.sector; $("org-location").value = full.org.location;
    };
    $("samples").append(b);
  }
  // ?sample=patient-portal loads and analyses a sample straight away (for demos).
  const wanted = new URLSearchParams(location.search).get("sample");
  if (wanted) {
    try {
      const full = await api("/api/samples/" + encodeURIComponent(wanted));
      $("logs").value = full.logs;
      $("org-name").value = full.org.name; $("org-sector").value = full.org.sector; $("org-location").value = full.org.location;
      $("go").click();
    } catch (e) { $("error").textContent = e.message; $("error").hidden = false; }
  }
}

$("go").onclick = async () => {
  $("error").hidden = true;
  const logs = $("logs").value.trim();
  if (!logs) { $("error").textContent = "Paste some logs or load a sample first."; $("error").hidden = false; return; }
  $("go").disabled = true; $("go").textContent = "Analysing...";
  try {
    state = await api("/api/analyze", {
      logs,
      noticed_at: $("noticed").value || "",
      org: { name: $("org-name").value, sector: $("org-sector").value, location: $("org-location").value,
             contact_name: $("c-name").value, contact_role: $("c-role").value, contact_phone: $("c-phone").value, contact_email: $("c-email").value },
    });
    render();
  } catch (e) {
    $("error").textContent = e.message; $("error").hidden = false;
  } finally {
    $("go").disabled = false; $("go").textContent = "Start the clock and analyse";
  }
};

function fmtLeft(ms) {
  const late = ms < 0; ms = Math.abs(ms);
  const h = Math.floor(ms / 3600000), m = Math.floor(ms % 3600000 / 60000), s = Math.floor(ms % 60000 / 1000);
  return (late ? "-" : "") + String(h).padStart(2, "0") + ":" + String(m).padStart(2, "0") + ":" + String(s).padStart(2, "0");
}

function renderClocks() {
  const box = $("clocks"); box.replaceChildren();
  for (const d of state.deadlines) {
    const card = el("div", null, "clock" + (d.applies ? "" : " off"));
    card.append(el("div", d.label, "label"));
    const time = el("div", "", "time"); card.append(time);
    const due = new Date(d.due);
    card.append(el("small", d.applies ? "Due " + due.toLocaleString("en-IN", { dateStyle: "medium", timeStyle: "short" }) + " - " + d.law : "Not triggered: no personal data found in these logs"));
    card.dataset.due = d.applies ? due.getTime() : "";
    box.append(card);
  }
  const tick = () => {
    for (const card of box.children) {
      const t = card.querySelector(".time");
      if (!card.dataset.due) { t.textContent = "--:--:--"; continue; }
      const left = Number(card.dataset.due) - Date.now();
      t.textContent = fmtLeft(left);
      card.classList.toggle("late", left < 0);
    }
  };
  clearInterval(ticker); tick(); ticker = setInterval(tick, 1000);
}

function showEvidence(line) {
  const pre = $("evidence"); pre.replaceChildren(); pre.hidden = false;
  const from = Math.max(1, line - 2), to = Math.min(state.lines.length, line + 2);
  for (let n = from; n <= to; n++) {
    const text = String(n).padStart(4, " ") + "  " + state.lines[n - 1] + "\n";
    pre.append(n === line ? el("mark", text) : document.createTextNode(text));
  }
}

function render() {
  const inc = state.incident;
  $("result").hidden = false;
  renderClocks();
  $("title").textContent = inc.title || "Incident";
  $("sev").textContent = inc.severity; $("sev").className = "sev " + inc.severity;
  $("summary").textContent = inc.summary;
  $("note").textContent = state.note; $("note").hidden = !state.note;
  $("engine").textContent = state.engine === "rules" ? "Analysed by: offline rules engine" : "Analysed by: " + state.engine;
  $("engine").classList.toggle("live", state.engine !== "rules");
  $("types").replaceChildren(...inc.incident_types.map((t) => el("span", t)));

  const masked = Object.entries(state.masked).map(([k, v]) => v + " " + k.toLowerCase()).join(", ") || "none found";
  const pd = inc.personal_data;
  const facts = [
    ["Attacker address", inc.attacker_ips.join(", ") || "not established"],
    ["Affected systems", inc.affected_assets.join(", ") || "not established"],
    ["Likely cause", inc.root_cause || "not established"],
    ["Personal data", pd.involved ? pd.categories.join(", ") + (pd.estimated_records ? " (about " + pd.estimated_records.toLocaleString("en-IN") + " records)" : "") : "no evidence in these logs"],
    ["Masked before AI", masked],
  ];
  $("facts").replaceChildren(...facts.flatMap(([k, v]) => [el("dt", k), el("dd", v)]));

  $("evidence").hidden = true;
  $("timeline").replaceChildren(...inc.timeline.map((e) => {
    const li = el("li"); li.append(el("time", e.time || "time unknown"), el("span", e.event));
    if (e.evidence_line) { const b = el("button", "line " + e.evidence_line); b.type = "button"; b.title = "Show the log line"; b.onclick = () => showEvidence(e.evidence_line); li.append(b); }
    else li.append(el("span", ""));
    return li;
  }));
  $("containment").replaceChildren(...inc.containment.map((step) => {
    const li = el("li"), label = el("label"), box = el("input"); box.type = "checkbox";
    label.append(box, el("span", step)); li.append(label); return li;
  }));
  $("unknowns").replaceChildren(...inc.unknowns.map((u) => el("li", u)));

  tab = "cert_in";
  $("tabs").replaceChildren(...Object.keys(state.drafts).map((key) => {
    const b = el("button", DRAFT_LABELS[key]); b.type = "button"; b.setAttribute("role", "tab"); b.dataset.key = key;
    b.onclick = () => { state.drafts[tab] = $("draft").value; tab = key; showDraft(); };
    return b;
  }));
  showDraft();
  $("result").scrollIntoView({ behavior: "smooth", block: "start" });
}

function showDraft() {
  $("draft").value = state.drafts[tab];
  for (const b of $("tabs").children) b.setAttribute("aria-selected", b.dataset.key === tab);
  $("translate-box").hidden = tab !== "principal_notice";
  $("status").textContent = "";
}

$("copy").onclick = async () => {
  try { await navigator.clipboard.writeText($("draft").value); $("status").textContent = "Copied."; }
  catch { $("draft").select(); $("status").textContent = "Press Ctrl+C to copy."; }
};
$("download").onclick = () => {
  const a = el("a"); a.href = URL.createObjectURL(new Blob([$("draft").value], { type: "text/plain" }));
  a.download = "sixhour-" + tab.replace("_", "-") + ".txt"; a.click(); URL.revokeObjectURL(a.href);
};
$("translate").onclick = async () => {
  $("translate").disabled = true; $("status").textContent = "Translating...";
  try {
    const out = await api("/api/translate", { text: $("draft").value, language: $("lang").value });
    $("draft").value = out.text; $("status").textContent = "Translated. Have a native speaker check it before sending.";
  } catch (e) { $("status").textContent = e.message; }
  finally { $("translate").disabled = false; }
};

init();
