// TPH Net Check front end. Plain JavaScript, no build step.

const T = window.__TAURI__;
const invoke = T ? T.core.invoke : async () => { throw new Error("Not running inside the app"); };
const listen = T ? T.event.listen : async () => {};

const STEPS = [
  ["link", "Your connection"],
  ["neptune", "Neptune's current load"],
  ["path", "Ping and latency"],
  ["switches", "UniFi switches"],
  ["jumbo", "Jumbo frames"],
  ["speed", "Network speed test"],
  ["files", "File transfer test"],
];

const $ = (s) => document.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

let settingsView = null;

// ---------- Navigation ----------
function show(view) {
  document.querySelectorAll(".nav").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${view}`));
  if (view === "history") loadHistory();
  if (view === "settings") loadSettings();
}
document.querySelectorAll(".nav").forEach((b) => b.addEventListener("click", () => show(b.dataset.view)));

function toast(msg, isErr) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (isErr ? " err" : "");
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.hidden = true), isErr ? 7000 : 3500);
}

// ---------- Formatting ----------
const gb = (mbps) => (mbps == null ? "n/a" : mbps >= 1000 ? `${(mbps / 1000).toFixed(2)} Gb/s` : `${Math.round(mbps)} Mb/s`);
const linkLabel = (mbps) => (mbps == null ? "unknown" : mbps >= 1000 ? `${+(mbps / 1000).toFixed(1)} Gb/s` : `${mbps} Mb/s`);
const mbs = (v) => (v == null ? "n/a" : `${Math.round(v)} MB/s`);
const pct = (v) => (v == null ? "n/a" : `${Math.round(v)}%`);
const when = (ms) => new Date(ms).toLocaleString("en-GB", { weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });

function avg(samples, key) {
  if (!samples || !samples.length) return null;
  return samples.reduce((a, s) => a + s[key], 0) / samples.length;
}
function peak(samples, key) {
  if (!samples || !samples.length) return null;
  return Math.max(...samples.map((s) => s[key]));
}

// ---------- Diagnose ----------
function renderSteps(states = {}) {
  $("#steps").innerHTML = STEPS.map(([id, label]) => {
    const st = states[id] || { state: "pending", note: "" };
    return `<li class="${esc(st.state)}"><span class="dot"></span><div><div class="step-label">${esc(label)}</div>${st.note ? `<div class="step-note">${esc(st.note)}</div>` : ""}</div></li>`;
  }).join("");
}

let stepStates = {};
listen("step", (e) => {
  const p = e.payload;
  stepStates[p.id] = { state: p.state, note: p.note };
  renderSteps(stepStates);
});

function tile(k, v, s, cls) {
  return `<div class="tile ${cls || ""}"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div>${s ? `<div class="s">${esc(s)}</div>` : ""}</div>`;
}

function renderReport(r) {
  // Verdict
  const h = r.headline;
  const v = $("#verdict");
  v.className = `verdict sev-${h.severity}`;
  $("#verdict-area").textContent = h.area;
  $("#verdict-title").textContent = h.title;
  $("#verdict-detail").textContent = h.detail;
  $("#verdict-meta").textContent = `${r.machine} · ${when(r.started_at_ms)} · took ${Math.round(r.duration_s)} s`;
  v.hidden = false;

  // Steps from the report
  stepStates = {};
  for (const s of r.steps) stepStates[s.id] = { state: s.state, note: s.note };
  renderSteps(stepStates);

  // Tiles
  const exp = settingsView?.settings?.expected_link_mbps || 10000;
  const t = [];
  const l = r.link;
  if (l) {
    const slow = l.kind === "wifi" || (l.speed_mbps != null && l.speed_mbps < exp);
    t.push(tile("Your link", l.kind === "wifi" ? "Wi-Fi" : linkLabel(l.speed_mbps), `${l.iface}, MTU ${l.mtu ?? "?"}`, slow ? "bad" : l.speed_mbps == null ? "" : "good"));
  }
  const info = r.server_before?.info;
  const nif = info?.interfaces?.find((i) => i.ipv4.includes(r.neptune_ip));
  if (nif) t.push(tile("Neptune link", linkLabel(nif.speed_mbps), `${nif.name}, MTU ${nif.mtu ?? "?"}`, nif.speed_mbps && nif.speed_mbps < exp ? "bad" : "good"));
  const np = r.pings.find((p) => p.label === "Neptune");
  if (np) t.push(tile("Neptune ping", np.avg_ms != null ? `${np.avg_ms.toFixed(2)} ms` : "no reply", `${np.loss_pct.toFixed(0)}% loss`, np.loss_pct > 0 ? "warn" : ""));
  if (r.throughput) {
    t.push(tile("Network from Neptune", gb(r.throughput.download_mbps), r.throughput.server?.download ? `Neptune CPU peak core ${pct(r.throughput.server.download.busiest_core_peak_pct)}` : ""));
    t.push(tile("Network to Neptune", gb(r.throughput.upload_mbps), r.throughput.server?.upload ? `Neptune CPU peak core ${pct(r.throughput.server.upload.busiest_core_peak_pct)}` : ""));
  }
  if (r.smb) {
    const sw = r.smb.server_during_write.samples, sr = r.smb.server_during_read.samples;
    t.push(tile("File write", mbs(r.smb.write_mb_s), sw.length ? `Neptune disks ${pct(peak(sw, "disk_util_avg_pct"))}` : `${r.smb.write_mb} MB`));
    t.push(tile("File read", mbs(r.smb.read_mb_s), sr.length ? `Neptune disks ${pct(peak(sr, "disk_util_avg_pct"))}` : r.smb.read_maybe_cached ? "may be cached" : ""));
  }
  if (r.server_before?.samples?.length) {
    const s = r.server_before.samples;
    t.push(tile("Neptune CPU at rest", pct(avg(s, "cpu_pct")), `busiest core ${pct(peak(s, "busiest_core_pct"))}`, avg(s, "cpu_pct") > 75 ? "warn" : ""));
    t.push(tile("Neptune disks at rest", pct(avg(s, "disk_util_max_pct")), info ? `${info.mem_available_mb} MB RAM free` : "", avg(s, "disk_util_max_pct") > 70 ? "warn" : ""));
  }
  $("#tiles").innerHTML = t.length ? t.join("") : `<p class="muted">No measurements were possible. Check Settings.</p>`;

  // Findings
  $("#findings").innerHTML = r.findings
    .map((f) => `<li class="sev-${esc(f.severity)}"><span class="badge">${esc(sevWord(f.severity))}</span><div><div class="f-area">${esc(f.area)}</div><div class="f-title">${esc(f.title)}</div><div class="f-detail">${esc(f.detail)}</div></div></li>`)
    .join("");
  $("#findings-panel").hidden = !r.findings.length;

  $("#raw").textContent = JSON.stringify(r, null, 2);
  $("#raw-panel").hidden = false;
}

function sevWord(s) {
  return { good: "OK", info: "Note", warn: "Check", bad: "Fault" }[s] || s;
}

$("#run").addEventListener("click", async () => {
  const btn = $("#run");
  btn.disabled = true;
  btn.textContent = "Checking…";
  stepStates = {};
  renderSteps();
  $("#verdict").hidden = true;
  $("#findings-panel").hidden = true;
  $("#raw-panel").hidden = true;
  $("#tiles").innerHTML = `<p class="muted">Measuring…</p>`;
  try {
    const r = await invoke("run_diagnosis");
    renderReport(r);
  } catch (e) {
    toast(String(e), true);
    $("#tiles").innerHTML = `<p class="muted">The check did not complete.</p>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Run check";
  }
});

// ---------- History ----------
async function loadHistory() {
  const body = $("#history tbody");
  try {
    const rows = await invoke("list_history");
    if (!rows.length) {
      body.innerHTML = `<tr><td colspan="5" class="muted">No checks yet.</td></tr>`;
      return;
    }
    body.innerHTML = rows
      .map((r) => `<tr data-id="${esc(r.id)}" class="sev-${esc(r.severity)}">
        <td>${esc(when(r.started_at_ms))}</td>
        <td><span class="badge">${esc(sevWord(r.severity))}</span> ${esc(r.headline)}</td>
        <td>${esc(linkLabel(r.link_mbps))}</td>
        <td>${esc(gb(r.download_mbps))} / ${esc(gb(r.upload_mbps))}</td>
        <td>${esc(mbs(r.write_mb_s))} / ${esc(mbs(r.read_mb_s))}</td></tr>`)
      .join("");
    body.querySelectorAll("tr[data-id]").forEach((tr) =>
      tr.addEventListener("click", async () => {
        try {
          renderReport(await invoke("load_history", { id: tr.dataset.id }));
          show("diagnose");
        } catch (e) {
          toast(String(e), true);
        }
      })
    );
  } catch (e) {
    body.innerHTML = `<tr><td colspan="5">${esc(e)}</td></tr>`;
  }
}

// ---------- Isolation ----------
$("#scan").addEventListener("click", async () => {
  const btn = $("#scan");
  btn.disabled = true;
  btn.textContent = "Scanning…";
  try {
    const r = await invoke("run_scan");
    const f = r.findings[0];
    const v = $("#scan-verdict");
    v.className = `verdict sev-${f.severity}`;
    $("#scan-title").textContent = f.title;
    $("#scan-detail").textContent = f.detail;
    v.hidden = false;
    $("#scan-head").textContent = `${r.devices.length} device(s) on ${r.subnet}`;
    $("#scan-table tbody").innerHTML = r.devices
      .map((d) => `<tr class="${d.label ? "" : "unknown"}"><td>${esc(d.ip)}</td><td>${esc(d.mac)}</td><td>${esc(d.label || "Not recognised")}</td></tr>`)
      .join("");
    $("#scan-panel").hidden = false;
  } catch (e) {
    toast(String(e), true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Scan network";
  }
});

// ---------- Settings ----------
const form = $("#settings-form");

async function loadSettings() {
  try {
    settingsView = await invoke("get_settings");
  } catch (e) {
    toast(String(e), true);
    return;
  }
  const s = settingsView.settings;
  for (const el of form.elements) {
    if (!el.name || !(el.name in s)) continue;
    if (el.type === "checkbox") el.checked = !!s[el.name];
    else el.value = s[el.name];
  }
  $("#known").value = (s.known_devices || []).map((d) => [d.name, d.mac || d.ip].join(", ")).join("\n");
  $("#key-status").textContent = settingsView.has_key ? "Imported" : "Not set";
  $("#key-status").className = "pill" + (settingsView.has_key ? " on" : "");
  $("#pw-status").textContent = settingsView.has_unifi_password ? "Stored in the keychain. Leave blank to keep it." : "Not stored yet.";
  const mac = settingsView.os.startsWith("macos");
  $("#smb-hint").textContent = mac
    ? "With the share mounted in Finder, for example /Volumes/Projects/_netcheck"
    : "For example Z:\\_netcheck or \\\\192.168.x.x\\Projects\\_netcheck";
  $("#machine").textContent = settingsView.machine;
  updateNotice();
}

function updateNotice() {
  const s = settingsView?.settings;
  if (!s) return;
  const missing = [];
  if (!s.neptune_host) missing.push("Neptune's address");
  if (!settingsView.has_key) missing.push("the SSH key");
  if (!s.smb_test_dir) missing.push("the test folder");
  const n = $("#setup-notice");
  if (missing.length) {
    n.innerHTML = `Not set up yet: ${esc(missing.join(", "))}. The check will skip what it cannot reach. <a id="go-settings">Open Settings</a>`;
    n.hidden = false;
    $("#go-settings").onclick = () => show("settings");
  } else n.hidden = true;
}

function readForm() {
  const s = { ...(settingsView?.settings || {}) };
  for (const el of form.elements) {
    if (!el.name) continue;
    if (el.type === "checkbox") s[el.name] = el.checked;
    else if (el.type === "number" || el.tagName === "SELECT") s[el.name] = Number(el.value);
    else s[el.name] = el.value.trim();
  }
  s.known_devices = $("#known").value
    .split("\n")
    .map((line) => line.split(",").map((x) => x.trim()))
    .filter((p) => p[0] && p[1])
    .map(([name, addr]) => (/^\d+\.\d+\.\d+\.\d+$/.test(addr) ? { name, ip: addr, mac: "" } : { name, mac: addr.toLowerCase().replace(/-/g, ":"), ip: "" }));
  return s;
}

async function save(quiet) {
  const pw = $("#unifi-password").value;
  try {
    await invoke("save_settings", { settings: readForm(), unifiPassword: pw || null });
    $("#unifi-password").value = "";
    await loadSettings();
    if (!quiet) toast("Saved");
    return true;
  } catch (e) {
    toast(String(e), true);
    return false;
  }
}
$("#save").addEventListener("click", () => save(false));

$("#key-import").addEventListener("click", async () => {
  try {
    await invoke("import_key", { privateKey: $("#key-text").value });
    $("#key-text").value = "";
    toast("Key imported and locked to your user account");
    loadSettings();
  } catch (e) {
    toast(String(e), true);
  }
});
$("#key-remove").addEventListener("click", async () => {
  await invoke("remove_key").catch((e) => toast(String(e), true));
  loadSettings();
});

async function runTest(btn, out, cmd, fmt) {
  if (!(await save(true))) return;
  btn.disabled = true;
  out.hidden = false;
  out.textContent = "Testing…";
  try {
    out.textContent = fmt(await invoke(cmd));
  } catch (e) {
    out.textContent = String(e);
  } finally {
    btn.disabled = false;
  }
}
$("#test-neptune").addEventListener("click", (e) =>
  runTest(e.target, $("#neptune-result"), "test_neptune", (r) => `Connected to ${r.hostname}: ${r.cores} cores, ${r.mem_total_mb} MB RAM\n${r.interfaces.join("\n")}`)
);
$("#test-unifi").addEventListener("click", (e) => runTest(e.target, $("#unifi-result"), "test_unifi", (r) => r));

// ---------- Start ----------
renderSteps();
loadSettings();
