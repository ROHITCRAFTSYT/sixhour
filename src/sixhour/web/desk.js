// The desk. No dependencies; everything rendered with textContent (no HTML from the server or the logs).
const $ = (id) => document.getElementById(id);
const el = (tag, text, cls) => { const n = document.createElement(tag); if (text != null) n.textContent = text; if (cls) n.className = cls; return n; };

const DRAFT_LABELS = { cert_in: "CERT-In report", dpdp_board: "DPDP Board intimation", principal_notice: "Notice to affected people" };
const FORM_FIELDS = ["org-name", "org-sector", "org-location", "noticed", "c-name", "c-role", "c-phone", "c-email"];
const STORE_KEY = "sixhour.incident.v2";
const MAX_CHARS = 600000;
const TODO = "[TO CONFIRM]";
const GO_LABEL = "Start the clock";

let state = null, tab = "cert_in", ticker = null;

function localNow() { const d = new Date(Date.now() - new Date().getTimezoneOffset() * 60000); return d.toISOString().slice(0, 16); }

async function api(path, body) {
  let res;
  try {
    res = await fetch(path, body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : undefined);
  } catch {
    throw new Error("Could not reach SixHour. Check your connection and try again.");
  }
  const data = await res.json().catch(() => ({}));
  if (res.ok) return data;
  if (res.status === 429) throw new Error("Too many requests from this network. Wait a minute and try again.");
  if (res.status === 413) throw new Error("That log is too large. Send the part around the incident (up to about 600,000 characters).");
  throw new Error(typeof data.detail === "string" ? data.detail : "Request failed (" + res.status + ").");
}

function fail(message) { $("error").textContent = message; $("error").hidden = !message; }

// The open incident is kept in this browser only, so the clocks survive a reload.
function save() {
  try {
    if (!state) return localStorage.removeItem(STORE_KEY);
    const form = Object.fromEntries(FORM_FIELDS.map((id) => [id, $(id).value]));
    localStorage.setItem(STORE_KEY, JSON.stringify({ state, tab, form }));
  } catch { /* private window or full storage: the desk still works, it just will not survive a reload */ }
}
function restore() {
  try {
    const saved = JSON.parse(localStorage.getItem(STORE_KEY) || "null");
    if (!saved || !saved.state || !Array.isArray(saved.state.deadlines)) return false;
    state = saved.state; tab = saved.tab in state.drafts ? saved.tab : "cert_in";
    for (const id of FORM_FIELDS) if (saved.form && saved.form[id] != null) $(id).value = saved.form[id];
    return true;
  } catch { return false; }
}

function countLines() {
  const text = $("logs").value;
  const n = text ? text.split("\n").filter((l) => l.trim()).length : 0;
  $("linecount").textContent = n ? n.toLocaleString("en-IN") + " lines" + (n > 4000 ? " (first 4,000 are analysed)" : "") : "";
}

function fillSample(full) {
  $("logs").value = full.logs;
  $("org-name").value = full.org.name; $("org-sector").value = full.org.sector; $("org-location").value = full.org.location;
  countLines();
}

async function readFile(file) {
  fail("");
  if (!file) return;
  if (file.size > MAX_CHARS * 4) return fail("That file is too large. Send the part around the incident (up to about 600,000 characters).");
  const text = await file.text();
  if (text.includes("\u0000")) return fail("That does not look like a text log file.");
  $("logs").value = text.slice(0, MAX_CHARS);
  countLines();
}

async function init() {
  $("noticed").value = localNow();
  api("/healthz").then((h) => {
    if (state) return;
    $("engine").textContent = h.gemini ? "Gemini ready" : "Rules engine only";
    $("engine").classList.toggle("live", h.gemini);
    if (!h.gemini) { $("use-model").checked = false; $("use-model").disabled = true; }
  }).catch(() => { $("engine").textContent = "engine unknown"; });

  const wanted = new URLSearchParams(location.search).get("sample");
  if (!wanted && restore()) render(false);

  try {
    for (const s of await api("/api/samples")) {
      const b = el("button", s.label, "sample type");
      b.type = "button";
      b.onclick = async () => { fail(""); try { fillSample(await api("/api/samples/" + s.id)); } catch (e) { fail(e.message); } };
      $("samples").append(b);
    }
    // ?sample=patient-portal opens and analyses a sample straight away.
    if (wanted) { fillSample(await api("/api/samples/" + encodeURIComponent(wanted))); $("go").click(); }
  } catch (e) { fail(e.message); }
}

$("logs").addEventListener("input", countLines);
$("file").addEventListener("change", (e) => readFile(e.target.files[0]));
const zone = $("dropzone");
for (const type of ["dragenter", "dragover"]) zone.addEventListener(type, (e) => { e.preventDefault(); zone.classList.add("over"); });
for (const type of ["dragleave", "drop"]) zone.addEventListener(type, (e) => { e.preventDefault(); zone.classList.remove("over"); });
zone.addEventListener("drop", (e) => readFile(e.dataTransfer.files[0]));

$("go").onclick = async () => {
  fail("");
  const logs = $("logs").value.trim();
  if (!logs) return fail("Paste some logs, drop a file, or open a sample case first.");
  if (logs.length > MAX_CHARS) return fail("That log is too large. Send the part around the incident (up to about 600,000 characters).");
  const started = Date.now();
  $("go").disabled = true;
  const waiting = setInterval(() => { $("go").textContent = "Reading the logs " + Math.round((Date.now() - started) / 1000) + "s"; }, 500);
  $("go").textContent = "Reading the logs";
  try {
    state = await api("/api/analyze", {
      logs,
      noticed_at: $("noticed").value || "",
      use_model: $("use-model").checked,
      org: { name: $("org-name").value, sector: $("org-sector").value, location: $("org-location").value,
             contact_name: $("c-name").value, contact_role: $("c-role").value, contact_phone: $("c-phone").value, contact_email: $("c-email").value },
    });
    tab = "cert_in";
    render(true);
    save();
  } catch (e) {
    fail(e.message);
  } finally {
    clearInterval(waiting);
    $("go").disabled = false; $("go").textContent = GO_LABEL;
  }
};

$("clear").onclick = () => {
  if (!confirm("Close this incident? The clocks, record and drafts are removed from this browser.")) return;
  state = null; clearInterval(ticker); save();
  $("result").hidden = true; $("idle").hidden = false; $("clear").hidden = true;
  $("logs").value = ""; countLines();
  $("engine").textContent = "desk clear"; $("engine").classList.remove("live");
  window.scrollTo({ top: 0 });
};

function fmtLeft(ms) {
  const late = ms < 0; ms = Math.abs(ms);
  const h = Math.floor(ms / 3600000), m = Math.floor(ms % 3600000 / 60000), s = Math.floor(ms % 60000 / 1000);
  return (late ? "+" : "") + String(h).padStart(2, "0") + ":" + String(m).padStart(2, "0") + ":" + String(s).padStart(2, "0");
}

function renderClocks() {
  const box = $("clocks"); box.replaceChildren();
  for (const d of state.deadlines) {
    const card = el("div", null, "clock sheet " + (d.id === "cert_in" ? "pink" : "green") + (d.applies ? "" : " off"));
    card.append(el("div", d.label, "label"));
    card.append(el("div", "", "time"));
    const due = new Date(d.due);
    card.append(el("p", d.applies
      ? "Due " + due.toLocaleString("en-IN", { dateStyle: "medium", timeStyle: "short" })
      : "Not triggered: no personal data found in these logs", "due"));
    card.append(el("p", d.law, "law type"));
    const fuse = el("div", null, "fuse"); fuse.append(el("i")); card.append(fuse);
    card.append(el("span", "Overdue", "stamp late-stamp"));
    card.dataset.due = d.applies ? due.getTime() : "";
    card.dataset.total = d.hours * 3600000;
    box.append(card);
  }
  const tick = () => {
    for (const card of box.children) {
      const t = card.querySelector(".time");
      if (!card.dataset.due) { t.textContent = "--:--:--"; continue; }
      const left = Number(card.dataset.due) - Date.now(), total = Number(card.dataset.total);
      t.textContent = fmtLeft(left);
      card.classList.toggle("late", left < 0);
      card.classList.toggle("urgent", left >= 0 && left < 3600000);
      card.querySelector(".fuse i").style.width = Math.min(100, Math.max(0, (1 - left / total) * 100)) + "%";
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

function render(scroll) {
  const inc = state.incident;
  $("result").hidden = false; $("idle").hidden = true; $("clear").hidden = false;
  renderClocks();
  $("title").textContent = inc.title || "Incident";
  $("sev").textContent = inc.severity; $("sev").className = "stamp sev " + inc.severity;
  $("summary").textContent = inc.summary;
  $("note").textContent = state.note; $("note").hidden = !state.note;
  $("engine").textContent = state.engine === "rules" ? "Analysed by rules engine" : "Analysed by " + state.engine;
  $("engine").classList.toggle("live", state.engine !== "rules");
  $("types").replaceChildren(...inc.incident_types.map((t) => el("span", t)));

  const masked = Object.entries(state.masked).map(([k, v]) => v + " " + k.toLowerCase()).join(", ") || "none found";
  const pd = inc.personal_data;
  const facts = [
    ["Attacker address", inc.attacker_ips.join(", ") || "not established"],
    ["Affected systems", inc.affected_assets.join(", ") || "not established"],
    ["Likely cause", inc.root_cause || "not established"],
    ["Personal data", pd.involved ? pd.categories.join(", ") + (pd.estimated_records ? " (about " + pd.estimated_records.toLocaleString("en-IN") + " records)" : "") : "no evidence in these logs"],
    ["Masked before analysis", masked],
  ];
  $("facts").replaceChildren(...facts.flatMap(([k, v]) => [el("dt", k), el("dd", v)]));

  $("evidence").hidden = true;
  $("timeline").replaceChildren(...inc.timeline.map((e) => {
    const li = el("li"); li.append(el("time", e.time || "time unknown"), el("span", e.event));
    if (e.evidence_line) {
      const b = el("button", "line " + e.evidence_line, "type"); b.type = "button"; b.title = "Show the log line that proves this";
      b.onclick = () => { showEvidence(e.evidence_line); for (const row of $("timeline").children) row.classList.toggle("cited", row === li); };
      li.append(b);
    } else li.append(el("span", ""));
    return li;
  }));
  $("containment").replaceChildren(...inc.containment.map((step, i) => {
    const li = el("li"), label = el("label"), box = el("input"); box.type = "checkbox";
    box.checked = Boolean(state.done && state.done[i]);
    box.onchange = () => { state.done = state.done || {}; state.done[i] = box.checked; save(); };
    label.append(box, el("span", step)); li.append(label); return li;
  }));
  $("unknowns").replaceChildren(...(inc.unknowns.length ? inc.unknowns : ["Nothing flagged."]).map((u) => el("li", u)));

  $("tabs").replaceChildren(...Object.keys(state.drafts).map((key) => {
    const b = el("button", DRAFT_LABELS[key]); b.type = "button"; b.setAttribute("role", "tab"); b.dataset.key = key;
    b.onclick = () => { tab = key; showDraft(); save(); };
    return b;
  }));
  showDraft();
  if (scroll) $("result").scrollIntoView({ behavior: "smooth", block: "start" });
}

function blanks(text) { return text.split(TODO).length - 1; }

function showConfirm() {
  const n = blanks($("draft").value), box = $("confirm");
  box.replaceChildren();
  box.classList.toggle("clear", n === 0);
  if (!n) { box.textContent = "Every field in this draft is filled. Read it once more before you file."; return; }
  box.append(el("span", n + (n === 1 ? " field" : " fields") + " still marked " + TODO));
  const next = el("button", "Go to next", "type"); next.type = "button";
  next.onclick = () => {
    const area = $("draft"), from = area.selectionEnd || 0;
    let at = area.value.indexOf(TODO, from);
    if (at < 0) at = area.value.indexOf(TODO);
    if (at < 0) return;
    area.focus(); area.setSelectionRange(at, at + TODO.length);
    const lineHeight = parseFloat(getComputedStyle(area).lineHeight) || 24;
    area.scrollTop = Math.max(0, area.value.slice(0, at).split("\n").length * lineHeight - area.clientHeight / 2);
  };
  box.append(next);
}

function showDraft() {
  $("draft").value = state.drafts[tab];
  for (const b of $("tabs").children) b.setAttribute("aria-selected", b.dataset.key === tab);
  $("translate-box").hidden = tab !== "principal_notice";
  $("status").textContent = "";
  showConfirm();
}

$("draft").addEventListener("input", () => { if (!state) return; state.drafts[tab] = $("draft").value; showConfirm(); save(); });

$("copy").onclick = async () => {
  try { await navigator.clipboard.writeText($("draft").value); $("status").textContent = "Copied."; }
  catch { $("draft").select(); $("status").textContent = "Press Ctrl+C to copy."; }
};
$("download").onclick = () => {
  const a = el("a"); a.href = URL.createObjectURL(new Blob([$("draft").value], { type: "text/plain;charset=utf-8" }));
  a.download = "sixhour-" + tab.replace(/_/g, "-") + ".txt"; a.click(); URL.revokeObjectURL(a.href);
};
$("translate").onclick = async () => {
  $("translate").disabled = true; $("status").textContent = "Translating";
  try {
    // Names stay in English letters so a reader can match them to the company and the people.
    const keep = ["org-name", "c-name", "c-email", "c-phone"].map((id) => $(id).value.trim()).filter(Boolean);
    const out = await api("/api/translate", { text: $("draft").value, language: $("lang").value, keep });
    $("draft").value = out.text; state.drafts[tab] = out.text; showConfirm(); save();
    $("status").textContent = out.not_kept && out.not_kept.length
      ? "Translated, but check these names, which may have been changed: " + out.not_kept.join(", ") + "."
      : "Translated. Have a native speaker check it before sending.";
  } catch (e) { $("status").textContent = e.message; }
  finally { $("translate").disabled = false; }
};

// The printed dossier carries every draft, not only the open tab.
function fillPrint() {
  const box = $("print-drafts"); box.replaceChildren();
  if (!state) return;
  for (const [key, text] of Object.entries(state.drafts)) { box.append(el("h2", DRAFT_LABELS[key]), el("pre", text)); }
}
window.addEventListener("beforeprint", fillPrint);
$("print").onclick = () => { fillPrint(); window.print(); };

init();
