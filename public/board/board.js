"use strict";
// Ironwatch security operations desk.
// Hash-routed single page. Polls /board/api/state and redraws only what changed.
// All server data is inserted with textContent, never as HTML.

(() => {
  const POLL_MS = 3000;
  const TARGET_MIN = { P1: 15, P2: 60, P3: 240, P4: 480 }; // first-response targets
  const SEV = ["P1", "P2", "P3", "P4"];
  const SEV_ORDER = { P1: 0, P2: 1, P3: 2, P4: 3 };
  const OPEN = ["new", "triaged", "in_progress", "escalated"];
  const CATEGORY = {
    ransomware: "Ransomware", phishing: "Phishing", account_compromise: "Account compromise", malware: "Malware",
    data_breach: "Data breach", ddos: "DDoS attack", lost_device: "Lost or stolen device", other: "Other incident",
  };
  const STATUS = { new: "New", triaged: "Triaged", in_progress: "In progress", escalated: "Escalated", resolved: "Resolved", closed: "Closed" };
  const REASON = { new_incident: "New incident", existing_ticket: "Ticket follow-up", failed_verification: "Failed verification", other: "General enquiry" };
  const MI_STEPS = [["investigating", "Investigating"], ["identified", "Identified"], ["monitoring", "Monitoring"], ["resolved", "Resolved"]];
  const PLAYBOOK_PREFIX = "Playbook step completed: ";
  const ACK_TEXT = "Acknowledged. Taking ownership of this ticket.";

  const PLAYBOOK = {
    ransomware: ["Isolate the affected device from the network", "Confirm backups are intact and offline", "Preserve evidence: do not power off or wipe", "Identify the variant from the ransom note", "Notify the client's IT lead and DPO", "Assess whether ICO notification is required (72 hours)"],
    phishing: ["Confirm whether credentials or payment details were entered", "Reset the password and revoke active sessions", "Block the sender and purge the email from all mailboxes", "Check mailbox rules and forwarding for tampering", "Advise the client on follow-up awareness"],
    account_compromise: ["Disable the account or force a password reset", "Revoke all sessions and refresh MFA methods", "Review sign-in logs for unusual locations", "Check mailbox rules, forwarding and OAuth grants", "Confirm with the user which activity was theirs"],
    malware: ["Isolate the device and quarantine the file", "Run a full EDR scan and collect the alert", "Check for lateral movement from the device", "Re-image the device if persistence is found"],
    data_breach: ["Establish what data is involved and how many people", "Contain the exposure: revoke links or access", "Preserve logs and evidence", "Brief the DPO on the ICO 72-hour clock", "Decide whether affected individuals must be told"],
    ddos: ["Confirm the affected service and traffic pattern", "Engage the upstream provider or DDoS protection", "Apply rate limiting or geo-blocking", "Agree client comms and status updates"],
    lost_device: ["Confirm when and where the device was lost", "Remote lock the device and trigger a wipe", "Revoke tokens and reset the user's password", "Check whether the device was encrypted", "Advise on a police report if stolen"],
    other: ["Gather full details from the client", "Assess impact and confirm the priority", "Assign to the right specialist team"],
  };
  const MACROS = [
    ["Called back", "Called the client back and confirmed the details above."],
    ["Reset and revoke", "Reset the user's password and revoked all active sessions."],
    ["Isolated device", "Isolated the affected device from the network."],
    ["Sent to IR lead", "Escalated to the incident response lead for review."],
    ["Awaiting client", "Waiting for the client to confirm before going further."],
  ];
  const VIEWS = [
    ["open", "All open", (t) => isOpen(t)],
    ["unack", "Unacknowledged", (t) => isWaiting(t)],
    ["breach", "Breaching target", (t) => sla(t).state === "breach"],
    ["high", "P1 and P2", (t) => isOpen(t) && (t.severity === "P1" || t.severity === "P2")],
    ["escalated", "Escalated", (t) => t.status === "escalated"],
    ["mi", "Major incident linked", (t) => isOpen(t) && !!t.linked_incident_ref],
    ["done", "Resolved and closed", (t) => !isOpen(t)],
    ["all", "Everything", () => true],
  ];
  const NEXT = {
    new: [["in_progress", "Start work", "primary", "i-play"], ["escalated", "Escalate", "danger", "i-flag"], ["resolved", "Resolve", "", "i-check"]],
    triaged: [["in_progress", "Start work", "primary", "i-play"], ["escalated", "Escalate", "danger", "i-flag"], ["resolved", "Resolve", "", "i-check"]],
    escalated: [["in_progress", "Start work", "primary", "i-play"], ["resolved", "Resolve", "", "i-check"]],
    in_progress: [["resolved", "Resolve", "ok", "i-check"], ["escalated", "Escalate", "danger", "i-flag"]],
    resolved: [["closed", "Close ticket", "primary", "i-check"], ["in_progress", "Reopen", "", "i-play"]],
    closed: [["in_progress", "Reopen", "primary", "i-play"]],
  };

  // ---------- state ----------
  let state = null;
  let offset = 0; // server clock minus browser clock
  let lastOk = 0;
  let known = null;
  let knownIncidents = null;
  let mounted = null; // key of the view currently in the DOM
  let fresh = new Set();
  const q = { view: "open", text: "", sev: new Set(), cat: "", status: "", team: "", sort: "sla", dir: 1, sel: new Set(), cursor: null };
  const calls = { ver: "all", open: new Set() };
  let drawnTicket = null; // { ref, sig } for the ticket page

  // ---------- small helpers ----------
  const $ = (id) => document.getElementById(id);
  const now = () => Date.now() + offset;
  function el(tag, attrs, kids) {
    const n = document.createElement(tag);
    if (attrs) for (const k of Object.keys(attrs)) {
      const v = attrs[k];
      if (v === null || v === undefined || v === false) continue;
      if (k === "text") n.textContent = v;
      else if (k === "class") n.className = v;
      else if (k === "dataset") Object.assign(n.dataset, v);
      else if (k === "style") n.setAttribute("style", v);
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? "" : v);
    }
    for (const c of kids || []) if (c !== null && c !== undefined && c !== false) n.append(c);
    return n;
  }
  function svgEl(tag, attrs, kids) {
    const n = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const k of Object.keys(attrs || {})) n.setAttribute(k, attrs[k]);
    for (const c of kids || []) if (c) n.append(c);
    return n;
  }
  function icon(name, cls) {
    const use = svgEl("use", { href: "#" + name });
    return svgEl("svg", { class: "ico" + (cls ? " " + cls : ""), "aria-hidden": "true" }, [use]);
  }
  const TZ = "Europe/London";
  const fTime = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", timeZone: TZ });
  const fDay = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", timeZone: TZ });
  const fDayKey = new Intl.DateTimeFormat("en-GB", { year: "numeric", month: "2-digit", day: "2-digit", timeZone: TZ });
  const fHour = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", hour12: false, timeZone: TZ });
  function valid(iso) { const d = new Date(iso); return isNaN(d) ? null : d; }
  function when(iso) {
    if (!iso) return "Unknown";
    const d = valid(iso);
    if (!d) return String(iso);
    return fDayKey.format(d) === fDayKey.format(new Date(now())) ? fTime.format(d) : fDay.format(d) + ", " + fTime.format(d);
  }
  function dur(ms) {
    const m = Math.max(0, Math.round(ms / 60000));
    if (m < 60) return m + "m";
    const h = Math.floor(m / 60);
    if (h < 48) return m % 60 ? h + "h " + (m % 60) + "m" : h + "h";
    return Math.floor(h / 24) + "d " + (h % 24) + "h";
  }
  function ago(iso) {
    const d = valid(iso);
    if (!d) return "";
    const ms = now() - d.getTime();
    if (ms < 45000) return "just now";
    return dur(ms) + " ago";
  }
  function clockText(ms) { // mm:ss under an hour, otherwise h m
    const s = Math.max(0, Math.round(ms / 1000));
    if (s < 3600) return String(Math.floor(s / 60)).padStart(2, "0") + ":" + String(s % 60).padStart(2, "0");
    return dur(ms);
  }
  const plural = (n, one, many) => n + " " + (n === 1 ? one : many || one + "s");
  const initials = (name) => (name || "?").split(/\s+/).filter(Boolean).slice(0, 2).map((p) => p[0].toUpperCase()).join("") || "?";
  const isOpen = (t) => OPEN.includes(t.status);
  const isWaiting = (t) => isOpen(t) && !t.first_response_at;
  const catName = (c) => CATEGORY[c] || c;
  const titleOf = (t) => catName(t.category) + " on " + t.affected_system;
  const typing = (e) => { const n = e.target; return n && (n.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(n.tagName)); };
  function pref(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) { /* storage blocked */ }
    return null;
  }
  const myName = () => pref("iw_name") || "";

  function sla(t) {
    const target = (TARGET_MIN[t.severity] || 480) * 60000;
    const start = new Date(t.created_at).getTime();
    const end = t.first_response_at ? new Date(t.first_response_at).getTime() : now();
    const elapsed = Math.max(0, end - start);
    const ratio = elapsed / target;
    if (t.first_response_at) return { state: ratio > 1 ? "late" : "met", elapsed, target, ratio: Math.min(ratio, 1), left: 0 };
    if (!isOpen(t)) return { state: "closed", elapsed, target, ratio: 1, left: 0 };
    return { state: ratio >= 1 ? "breach" : ratio >= 0.75 ? "warn" : "ok", elapsed, target, ratio: Math.min(ratio, 1), left: target - elapsed };
  }
  function slaMeter(t) {
    const s = sla(t);
    let label, value;
    if (s.state === "met") { label = "Responded"; value = dur(s.elapsed); }
    else if (s.state === "late") { label = "Responded late"; value = dur(s.elapsed); }
    else if (s.state === "closed") { label = "Closed"; value = "No response"; }
    else if (s.state === "breach") { label = "Overdue"; value = "+" + dur(s.elapsed - s.target); }
    else { label = "Respond in"; value = clockText(s.left); }
    return el("div", { class: "sla " + s.state, title: "First response target for " + t.severity + ": " + dur(s.target) }, [
      el("div", { class: "sla-top" }, [el("span", { text: label }), el("b", { text: value })]),
      el("div", { class: "sla-bar" }, [el("i", { style: "width:" + Math.round(s.ratio * 100) + "%" })]),
    ]);
  }
  const pri = (sev) => el("span", { class: "pri", dataset: { sev }, text: sev, title: "Priority " + sev.slice(1) });
  const pill = (s, label) => el("span", { class: "state", dataset: { status: s }, text: label || STATUS[s] || s });
  function verif(v) {
    if (!v) return el("span", { class: "verif", text: "No call log" });
    const ico = v === "Verified" ? "i-shield-ok" : v === "Failed" ? "i-shield-x" : "i-shield-q";
    return el("span", { class: "verif", dataset: { v } }, [icon(ico), v]);
  }
  function copyBtn(text, label) {
    const b = el("button", { class: "copy", type: "button", title: "Copy " + label, "aria-label": "Copy " + label, onclick: (e) => {
      e.stopPropagation();
      const done = () => { b.replaceChildren(icon("i-check")); setTimeout(() => b.replaceChildren(icon("i-copy")), 1200); };
      if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, () => {}); else done();
    } }, [icon("i-copy")]);
    return b;
  }

  // ---------- network ----------
  function api(path, opts) {
    opts = Object.assign({ credentials: "same-origin", cache: "no-store" }, opts || {});
    const name = myName();
    if (name) opts.headers = Object.assign({}, opts.headers || {}, { "X-Board-Name": name });
    return fetch(path, opts).then((r) => {
      if (r.status === 401) { location.href = "/board"; throw new Error("Signed out"); }
      return r.json().catch(() => ({})).then((d) => { if (!r.ok) throw new Error(d.message || "Something went wrong."); return d; });
    });
  }
  function post(path, body) {
    return api(path, { method: "POST", headers: { "Content-Type": "application/json", "X-Board-Request": "1" }, body: JSON.stringify(body) });
  }
  const updateTicket = (ref, body) => post("/board/api/tickets/" + encodeURIComponent(ref), body);

  let pollTimer = null, inFlight = false, again = false;
  function poll() {
    if (inFlight) { again = true; return; }
    inFlight = true;
    clearTimeout(pollTimer);
    api("/board/api/state").then((data) => {
      lastOk = Date.now();
      const st = valid(data.server_time);
      if (st) offset = st.getTime() - Date.now();
      const changed = !state || data.version !== state.version;
      const arrivedTickets = known ? data.tickets.filter((t) => !known.has(t.ticket_ref)) : [];
      known = new Set(data.tickets.map((t) => t.ticket_ref));
      const arrivedIncidents = knownIncidents ? data.incidents.filter((i) => !knownIncidents.has(i.incident_ref)) : [];
      knownIncidents = new Set(data.incidents.map((i) => i.incident_ref));
      state = data;
      for (const t of arrivedTickets) fresh.add(t.ticket_ref);
      chrome();
      if (changed) route(false);
      arrivedTickets.forEach(ticketToast);
      arrivedIncidents.forEach(incidentToast);
      if (arrivedTickets.length || arrivedIncidents.length) { chime(arrivedIncidents.length || arrivedTickets.some((t) => t.severity === "P1")); flash(); }
      if (arrivedTickets.length) setTimeout(() => { arrivedTickets.forEach((t) => fresh.delete(t.ticket_ref)); }, 2600);
    }).catch(() => {}).finally(() => {
      inFlight = false;
      setLive();
      if (again) { again = false; poll(); } else pollTimer = setTimeout(poll, POLL_MS);
    });
  }
  function setLive() {
    const offline = !lastOk || Date.now() - lastOk > POLL_MS * 3;
    document.querySelector(".app").classList.toggle("offline", offline);
    $("live-text").textContent = !lastOk ? "Connecting" : offline ? "Reconnecting" : "Live";
    $("live").title = lastOk ? "Last synced " + fTime.format(new Date(lastOk)) : "";
  }

  // ---------- chrome: sidebar, top bar, banner ----------
  function chrome() {
    const open = state.tickets.filter(isOpen);
    const waiting = open.filter(isWaiting);
    const setCount = (id, n, hot) => { const c = $(id); c.textContent = n ? String(n) : ""; c.classList.toggle("hot", !!hot); };
    setCount("n-waiting", waiting.length, waiting.length > 0);
    setCount("n-open", open.length);
    setCount("n-calls", state.calls.length);
    setCount("n-incidents", state.incidents.filter((i) => i.status !== "resolved").length);

    $("side-views").replaceChildren(...VIEWS.slice(1, 6).map(([key, label, fn]) => {
      const n = state.tickets.filter(fn).length;
      return el("a", { href: "#/queue/" + key, dataset: { nav: "view-" + key } }, [
        el("i", { class: "dot", style: "background:" + (key === "breach" || key === "escalated" ? "var(--p1)" : key === "unack" ? "var(--warn)" : key === "high" ? "var(--p2)" : "var(--info)") }),
        el("span", { text: label }), el("b", { class: "count" + (key === "breach" && n ? " hot" : ""), text: n ? String(n) : "" }),
      ]);
    }));

    const name = state.password_required ? state.signed_in_as : myName() || "Incident handler";
    $("who").textContent = name;
    $("avatar").textContent = initials(name);
    $("session").textContent = state.password_required
      ? (state.session_expires ? "Session until " + fTime.format(new Date(state.session_expires)) : "Signed in")
      : "Open demo desk";
    $("signout").hidden = !state.password_required;
    $("who-btn").disabled = !!state.password_required;

    const activeAuto = state.incidents.filter((i) => i.auto_detected && i.status !== "resolved");
    const p1Waiting = waiting.some((t) => t.severity === "P1");
    const breaches = open.filter((t) => sla(t).state === "breach").length;
    const level = activeAuto.length || p1Waiting ? "critical" : open.some((t) => t.severity === "P1") || breaches ? "elevated" : "normal";
    $("posture").dataset.level = level;
    $("posture-text").textContent = level === "critical" ? "Critical" : level === "elevated" ? "Elevated" : "Normal";
    $("posture").title = level === "critical" ? (activeAuto.length ? "Outbreak detected" : "P1 waiting for a handler") : level === "elevated" ? "P1 open or response target missed" : "No P1s or breaches";

    $("banner").replaceChildren(...activeAuto.slice(0, 2).map((i) => el("div", { class: "banner", role: "alert" }, [
      icon("i-alert", "ico-lg"),
      el("div", null, [
        el("span", { class: "mono", text: "OUTBREAK  " + i.incident_ref }),
        el("div", null, [el("b", { text: i.title }), el("span", { class: "muted", text: "  " + plural(i.linked_tickets.length, "linked report") + ". Aggie is telling new callers this is already known." })]),
      ]),
      el("a", { class: "btn btn-sm btn-danger", href: "#/incidents", text: "Open incident" }),
    ])));

    document.title = (waiting.length ? "(" + waiting.length + ") " : "") + ($("page-title").textContent || "Desk") + " · Ironwatch";
  }

  // ---------- alerts ----------
  function toastBox(box, ms) {
    const shelf = $("toasts");
    shelf.append(box);
    while (shelf.children.length > 4) shelf.firstElementChild.remove();
    setTimeout(() => box.remove(), ms);
  }
  function ticketToast(t) {
    const box = el("div", { class: "toast", dataset: { sev: t.severity, ref: t.ticket_ref }, role: "status" }, [
      pri(t.severity),
      el("p", null, [el("b", { text: "New ticket from Aggie" }), t.ticket_ref + " · " + titleOf(t) + " · " + t.caller_name]),
      el("a", { class: "btn btn-sm", href: "#/tickets/" + encodeURIComponent(t.ticket_ref), text: "Open", onclick: () => box.remove() }),
    ]);
    toastBox(box, 15000);
  }
  function incidentToast(i) {
    for (const r of i.linked_tickets || []) { const old = document.querySelector('.toast[data-ref="' + CSS.escape(r) + '"]'); if (old) old.remove(); }
    const box = el("div", { class: "toast toast-outbreak", role: "status" }, [
      el("span", { class: "badge-x" }, [icon("i-alert")]),
      el("p", null, [el("b", { text: i.auto_detected ? "Outbreak detected" : "New major incident" }), i.title]),
      el("a", { class: "btn btn-sm", href: "#/incidents", text: "View", onclick: () => box.remove() }),
    ]);
    toastBox(box, 20000);
  }
  function flash() {
    const app = document.querySelector(".app");
    app.classList.remove("alert"); void app.offsetWidth; app.classList.add("alert");
    setTimeout(() => app.classList.remove("alert"), 2500);
  }
  let audio = null;
  function soundOn() { return pref("iw_sound") === "1"; }
  function chime(urgent) {
    if (!soundOn()) return;
    try {
      audio = audio || new (window.AudioContext || window.webkitAudioContext)();
      const notes = urgent ? [880, 660, 880] : [660, 880];
      notes.forEach((f, n) => {
        const o = audio.createOscillator(), g = audio.createGain(), t0 = audio.currentTime + n * 0.16;
        o.type = "sine"; o.frequency.value = f;
        g.gain.setValueAtTime(0.0001, t0); g.gain.exponentialRampToValueAtTime(0.12, t0 + 0.02); g.gain.exponentialRampToValueAtTime(0.0001, t0 + 0.14);
        o.connect(g).connect(audio.destination); o.start(t0); o.stop(t0 + 0.15);
      });
    } catch (e) { /* no audio */ }
  }

  // ---------- routing ----------
  function parse() {
    const parts = location.hash.replace(/^#\/?/, "").split("/");
    let view = parts[0] || "overview";
    let arg = parts[1] ? decodeURIComponent(parts[1]) : null;
    if (view === "queue") { if (arg && VIEWS.some((v) => v[0] === arg)) q.view = arg; view = "tickets"; arg = null; }
    return { view, arg };
  }
  function route(navigated) {
    if (!state) return;
    const r = parse();
    const navKey = r.view === "tickets" && !r.arg && location.hash.startsWith("#/queue/") ? "view-" + q.view : r.view;
    document.querySelectorAll("[data-nav]").forEach((a) => {
      const on = a.dataset.nav === navKey || (navKey.startsWith("view-") && a.dataset.nav === "tickets");
      if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
    });
    const titles = { overview: "Overview", tickets: r.arg || "Ticket queue", calls: "Call log", incidents: "Major incidents" };
    const title = titles[r.view] || "Overview";
    $("page-title").textContent = title;
    $("page-title").classList.toggle("mono", r.view === "tickets" && !!r.arg);

    if (r.view === "tickets" && r.arg) renderTicket(r.arg, navigated);
    else if (r.view === "tickets") renderQueue();
    else if (r.view === "calls") renderCalls();
    else if (r.view === "incidents") renderIncidents();
    else renderOverview();
    chrome();
    if (navigated) { $("view").focus({ preventScroll: true }); window.scrollTo(0, 0); }
  }
  window.addEventListener("hashchange", () => route(true));
  function mount(key, nodes) { mounted = key; $("view").replaceChildren(...nodes); }

  // ---------- overview ----------
  function kpi(label, value, foot, tone, href, unit) {
    const kids = [el("span", { class: "eyebrow", text: label }), el("span", { class: "kpi-val" }, [value, unit ? el("small", { text: unit }) : null]), el("span", { class: "kpi-foot", text: foot })];
    return href ? el("a", { class: "card kpi", href, dataset: { tone: tone || "" } }, kids) : el("div", { class: "card kpi", dataset: { tone: tone || "" } }, kids);
  }
  function median(xs) { if (!xs.length) return null; const s = xs.slice().sort((a, b) => a - b); const m = Math.floor(s.length / 2); return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; }

  function intakeChart() {
    const W = 720, H = 168, padL = 26, padB = 22, padT = 8;
    const hourMs = 3600000;
    const end = Math.ceil(now() / hourMs) * hourMs;
    const buckets = Array.from({ length: 24 }, (_, i) => ({ start: end - (24 - i) * hourMs, P1: 0, P2: 0, P3: 0, P4: 0 }));
    for (const t of state.tickets) {
      const d = valid(t.created_at); if (!d) continue;
      const i = Math.floor((d.getTime() - (end - 24 * hourMs)) / hourMs);
      if (i >= 0 && i < 24) buckets[i][t.severity] += 1;
    }
    const totals = buckets.map((b) => b.P1 + b.P2 + b.P3 + b.P4);
    const maxV = Math.max(4, ...totals);
    const step = maxV <= 4 ? 1 : maxV <= 10 ? 2 : Math.ceil(maxV / 5);
    const top = Math.ceil(maxV / step) * step;
    const plotW = W - padL, plotH = H - padB - padT, bw = plotW / 24;
    const y = (v) => padT + plotH - (v / top) * plotH;
    const kids = [];
    for (let v = 0; v <= top; v += step) {
      kids.push(svgEl("line", { class: "gridline", x1: padL, x2: W, y1: y(v), y2: y(v) }));
      const tx = svgEl("text", { x: padL - 6, y: y(v) + 3.5, "text-anchor": "end" }); tx.textContent = String(v); kids.push(tx);
    }
    buckets.forEach((b, i) => {
      let acc = 0;
      const x = padL + i * bw + 3;
      const g = svgEl("g", {});
      const tt = svgEl("title", {});
      tt.textContent = fHour.format(new Date(b.start)) + ":00  " + plural(totals[i], "ticket") + (totals[i] ? " (" + SEV.filter((s) => b[s]).map((s) => s + " " + b[s]).join(", ") + ")" : "");
      g.append(tt, svgEl("rect", { x, y: padT, width: bw - 6, height: plotH, fill: "transparent" }));
      for (const s of SEV) {
        if (!b[s]) continue;
        const h = (b[s] / top) * plotH;
        g.append(svgEl("rect", { class: "bar-" + s, x, y: y(acc) - h, width: bw - 6, height: Math.max(h - 1, 1), rx: 1.5 }));
        acc += b[s];
      }
      kids.push(g);
      if (i % 3 === 0) { const tx = svgEl("text", { x: x + (bw - 6) / 2, y: H - 6, "text-anchor": "middle" }); tx.textContent = fHour.format(new Date(b.start)) + ":00"; kids.push(tx); }
    });
    const total = totals.reduce((a, b) => a + b, 0);
    return { svg: svgEl("svg", { class: "chart", viewBox: "0 0 " + W + " " + H, preserveAspectRatio: "none", role: "img", "aria-label": plural(total, "ticket") + " raised in the last 24 hours" }, kids), total };
  }

  function matrix(open) {
    const cols = ["new", "triaged", "in_progress", "escalated"];
    const max = Math.max(1, ...SEV.flatMap((s) => cols.map((c) => open.filter((t) => t.severity === s && t.status === c).length)));
    const go = (s, c) => () => { q.sev = new Set([s]); q.status = c || ""; q.view = "open"; };
    return el("table", { class: "matrix" }, [
      el("thead", null, [el("tr", null, [el("th", { text: "" }), ...cols.map((c) => el("th", { scope: "col", text: STATUS[c] })), el("th", { scope: "col", text: "Total" })])]),
      el("tbody", null, SEV.map((s) => el("tr", { dataset: { sev: s } }, [
        el("th", { scope: "row" }, [pri(s)]),
        ...cols.map((c) => {
          const n = open.filter((t) => t.severity === s && t.status === c).length;
          return el("td", { class: n ? "has" : "", style: n ? "--heat:" + Math.round(18 + (n / max) * 52) : null },
            [n ? el("a", { href: "#/queue/open", onclick: go(s, c), "aria-label": n + " " + s + " " + STATUS[c], text: String(n) }) : "·"]);
        }),
        (() => { const n = open.filter((t) => t.severity === s).length; return el("td", { class: n ? "has" : "", style: n ? "--heat:10" : null }, [n ? el("a", { href: "#/queue/open", onclick: go(s, ""), text: String(n) }) : "0"]); })(),
      ]))),
    ]);
  }

  function feedIcon(kind) { return { raised: "i-bot", status: "i-flow", note: "i-note", call: "i-phone", outbreak: "i-alert" }[kind] || "i-note"; }

  function renderOverview() {
    const T = state.tickets;
    const open = T.filter(isOpen);
    const waiting = open.filter(isWaiting);
    const breaches = open.filter((t) => sla(t).state === "breach");
    const responses = T.filter((t) => t.first_response_at).map((t) => new Date(t.first_response_at) - new Date(t.created_at)).filter((x) => x >= 0);
    const med = median(responses);
    const dayAgo = now() - 86400000;
    const calls24 = state.calls.filter((c) => new Date(c.logged_at).getTime() >= dayAgo);
    const ver = state.calls.filter((c) => c.verification_status);
    const passed = ver.filter((c) => c.verification_status === "Verified").length;
    const failed = ver.filter((c) => c.verification_status === "Failed").length;
    const oldestWait = waiting.length ? Math.max(...waiting.map((t) => now() - new Date(t.created_at).getTime())) : 0;

    let headline, sub;
    if (breaches.length) { headline = plural(breaches.length, "ticket has", "tickets have") + " missed the response target"; sub = "Work the overdue tickets first, highest priority at the top."; }
    else if (waiting.length) { headline = plural(waiting.length, "ticket is", "tickets are") + " waiting for a handler"; sub = "Oldest has waited " + dur(oldestWait) + ". Acknowledge to stop the response clock."; }
    else if (open.length) { headline = "Every open ticket has a handler"; sub = plural(open.length, "open ticket") + " in progress. New reports from Aggie appear here instantly."; }
    else { headline = "All quiet on the desk"; sub = "No open tickets. New reports from Aggie appear here instantly."; }

    const chart = intakeChart();
    const attention = open.slice().sort((a, b) => {
      const sa = sla(a), sb = sla(b);
      const wa = isWaiting(a) ? 0 : 1, wb = isWaiting(b) ? 0 : 1;
      return wa - wb || SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || (sa.left - sb.left) || a.created_at.localeCompare(b.created_at);
    }).slice(0, 8);

    const byCat = {};
    for (const t of open) byCat[t.category] = (byCat[t.category] || 0) + 1;
    const cats = Object.entries(byCat).sort((a, b) => b[1] - a[1]);
    const catMax = Math.max(1, ...cats.map((c) => c[1]));
    const activeMI = state.incidents.filter((i) => i.status !== "resolved").sort((a, b) => b.started_at.localeCompare(a.started_at));

    mount("overview", [
      el("div", { class: "ov-head" }, [
        el("div", null, [el("h2", { text: headline }), el("p", { text: sub })]),
        el("div", { class: "end" }, [
          el("a", { class: "btn", href: "#/calls" }, [icon("i-phone"), "Call log"]),
          el("a", { class: "btn btn-primary", href: "#/queue/" + (waiting.length ? "unack" : "open") }, [icon("i-ticket"), waiting.length ? "Work the queue" : "Open queue"]),
        ]),
      ]),
      el("div", { class: "kpis" }, [
        kpi("Open tickets", String(open.length), SEV.map((s) => s + " " + open.filter((t) => t.severity === s).length).join(" · "), "", "#/queue/open"),
        kpi("Unacknowledged", String(waiting.length), waiting.length ? "Oldest " + dur(oldestWait) : "Nothing waiting", waiting.some((t) => t.severity === "P1") ? "bad" : waiting.length ? "warn" : "ok", "#/queue/unack"),
        kpi("Target breaches", String(breaches.length), breaches.length ? "First response overdue" : "All within target", breaches.length ? "bad" : "ok", "#/queue/breach"),
        kpi("Median response", med === null ? "–" : dur(med), responses.length ? "Across " + plural(responses.length, "ticket") : "No responses yet", ""),
        kpi("Calls, 24h", String(calls24.length), plural(calls24.filter((c) => c.transfer_priority === "Urgent").length, "urgent transfer"), "", "#/calls"),
        kpi("ID checks passed", ver.length ? String(Math.round((passed / ver.length) * 100)) : "–", ver.length ? plural(failed, "failed check") : "No calls yet", failed ? "warn" : "", "#/calls", ver.length ? "%" : ""),
      ]),
      el("div", { class: "grid-ov" }, [
        el("div", { class: "stack" }, [
          el("section", { class: "card" }, [
            el("div", { class: "card-head" }, [el("h2", { text: "Ticket intake" }), el("span", { class: "hint", text: "Last 24 hours, " + plural(chart.total, "ticket") }),
              el("div", { class: "end legend" }, SEV.map((s) => el("span", { dataset: { sev: s } }, [el("i"), s])))]),
            el("div", { class: "card-body" }, [chart.svg]),
          ]),
          el("section", { class: "card" }, [
            el("div", { class: "card-head" }, [el("h2", { text: "Needs attention" }), el("span", { class: "hint", text: "Unacknowledged first, then by priority and time left" }), el("div", { class: "end" }, [el("a", { class: "link", href: "#/queue/open", text: "Full queue" })])]),
            attention.length
              ? el("ul", { class: "plain attn" }, attention.map((t) => el("li", null, [el("a", { href: "#/tickets/" + encodeURIComponent(t.ticket_ref), class: fresh.has(t.ticket_ref) ? "arrived" : null }, [
                  pri(t.severity),
                  el("span", { style: "min-width:0" }, [el("span", { class: "t", text: titleOf(t) }), el("span", { class: "s" }, [el("span", { class: "ref", text: t.ticket_ref }), "  ·  " + t.caller_name + (t.organisation ? ", " + t.organisation : "") + "  ·  " + STATUS[t.status]])]),
                  slaMeter(t),
                ])])))
              : el("div", { class: "empty" }, [icon("i-shield-ok"), el("b", { text: "Nothing needs attention" }), "No open tickets right now."]),
          ]),
          el("section", { class: "card" }, [
            el("div", { class: "card-head" }, [el("h2", { text: "Open by category" })]),
            el("div", { class: "card-body" }, [cats.length
              ? el("ul", { class: "plain bars" }, cats.map(([c, n]) => el("li", null, [el("span", { text: catName(c) }), el("b", { text: String(n) }), el("span", { class: "track" }, [el("i", { style: "width:" + Math.round((n / catMax) * 100) + "%" })])])))
              : el("p", { class: "muted", text: "No open tickets." })]),
          ]),
        ]),
        el("div", { class: "stack" }, [
          el("section", { class: "card" }, [
            el("div", { class: "card-head" }, [el("h2", { text: "Priority and status" }), el("span", { class: "hint", text: "Open tickets" })]),
            el("div", { class: "card-body" }, [matrix(open)]),
          ]),
          el("section", { class: "card" }, [
            el("div", { class: "card-head" }, [el("h2", { text: "Major incidents" }), el("div", { class: "end" }, [el("a", { class: "link", href: "#/incidents", text: "All" })])]),
            activeMI.length
              ? el("div", null, activeMI.slice(0, 4).map((i) => el("a", { class: "mi-mini", href: "#/incidents" }, [
                  el("span", { class: "t", text: i.title }), pill(i.status, MI_STEPS.find((s) => s[0] === i.status)?.[1]),
                  el("span", { class: "s" }, [el("span", { class: "ref", text: i.incident_ref }), "  ·  " + (i.auto_detected ? "Auto-detected " : "Opened ") + ago(i.started_at) + "  ·  " + plural(i.linked_tickets.length, "linked ticket")]),
                ])))
              : el("div", { class: "empty" }, [el("b", { text: "No active major incidents" })]),
          ]),
          el("section", { class: "card" }, [
            el("div", { class: "card-head" }, [el("h2", { text: "Live activity" }), el("span", { class: "hint", text: "Aggie, handlers and detection" })]),
            state.activity.length
              ? el("ol", { class: "plain feed" }, state.activity.map((e) => el("li", { class: "k-" + e.kind }, [
                  el("span", { class: "fi" }, [icon(feedIcon(e.kind))]),
                  el("div", { style: "min-width:0" }, [
                    el("div", { class: "ft" }, [e.ticket_ref ? el("a", { class: "ref", href: "#/tickets/" + encodeURIComponent(e.ticket_ref), text: e.ticket_ref }) : null, e.ticket_ref ? "  " : "", e.kind === "outbreak" ? el("b", { text: e.text }) : e.text.startsWith(PLAYBOOK_PREFIX) ? "Playbook: " + e.text.slice(PLAYBOOK_PREFIX.length) : e.text]),
                    el("div", { class: "fm" }, [el("time", { datetime: e.at, text: when(e.at) }), el("span", { text: e.by })]),
                  ]),
                ])))
              : el("div", { class: "empty" }, [el("b", { text: "No activity yet" })]),
          ]),
        ]),
      ]),
    ]);
  }

  // ---------- queue ----------
  function queueRows() {
    const v = VIEWS.find((x) => x[0] === q.view) || VIEWS[0];
    const text = q.text.trim().toLowerCase();
    const rows = state.tickets.filter((t) => {
      if (!v[2](t)) return false;
      if (q.sev.size && !q.sev.has(t.severity)) return false;
      if (q.cat && t.category !== q.cat) return false;
      if (q.status && t.status !== q.status) return false;
      if (q.team && t.assigned_team !== q.team) return false;
      if (text && [t.ticket_ref, t.caller_name, t.organisation, t.affected_system, catName(t.category), t.linked_incident_ref, t.description, t.caller_phone].join(" ").toLowerCase().indexOf(text) === -1) return false;
      return true;
    });
    const key = {
      pri: (t) => SEV_ORDER[t.severity] * 1e13 + new Date(t.created_at).getTime(),
      ref: (t) => t.ticket_ref,
      caller: (t) => (t.caller_name || "").toLowerCase(),
      status: (t) => OPEN.concat(["resolved", "closed"]).indexOf(t.status),
      age: (t) => -new Date(t.created_at).getTime(),
      sla: (t) => { const s = sla(t); return (isOpen(t) ? 0 : 1e15) + (s.state === "met" || s.state === "late" ? 1e14 : 0) + SEV_ORDER[t.severity] * 1e12 + s.left; },
    }[q.sort] || ((t) => t.ticket_ref);
    return rows.sort((a, b) => { const ka = key(a), kb = key(b); return (ka < kb ? -1 : ka > kb ? 1 : 0) * q.dir; });
  }

  function renderQueue() {
    if (mounted !== "queue") {
      const search = el("input", { class: "input", type: "search", placeholder: "Filter by ref, caller, organisation, system", "aria-label": "Filter tickets", value: q.text, id: "q-text",
        oninput: () => { q.text = search.value; drawQueue(); } });
      const chips = el("div", { class: "chips", role: "group", "aria-label": "Priority" }, SEV.map((s) => {
        const b = el("button", { class: "chip", type: "button", dataset: { sev: s }, "aria-pressed": String(q.sev.has(s)), text: s,
          onclick: () => { if (q.sev.has(s)) q.sev.delete(s); else q.sev.add(s); b.setAttribute("aria-pressed", String(q.sev.has(s))); drawQueue(); } });
        return b;
      }));
      const mkSelect = (id, label, opts, val, set) => {
        const s = el("select", { class: "input", id, "aria-label": label, onchange: () => { set(s.value); drawQueue(); } }, opts.map(([v, l]) => el("option", { value: v, text: l })));
        s.value = val; return s;
      };
      const cat = mkSelect("q-cat", "Category", [["", "Any category"], ...Object.keys(CATEGORY).map((k) => [k, CATEGORY[k]])], q.cat, (v) => { q.cat = v; });
      const st = mkSelect("q-status", "Status", [["", "Any status"], ...Object.keys(STATUS).map((k) => [k, STATUS[k]])], q.status, (v) => { q.status = v; });
      const team = mkSelect("q-team", "Team", [["", "Any team"]], q.team, (v) => { q.team = v; });
      const density = el("button", { class: "btn btn-ghost btn-sm", type: "button", id: "density", title: "Row density", onclick: () => {
        const c = pref("iw_density") === "compact" ? "comfortable" : "compact"; pref("iw_density", c); applyDensity();
      } }, [icon("i-sliders"), el("span", { id: "density-label" })]);
      mount("queue", [
        el("div", { class: "views", role: "tablist", id: "q-views", "aria-label": "Saved views" }),
        el("div", { class: "toolbar" }, [
          el("label", { class: "searchbox" }, [icon("i-search"), search]), chips, st, cat, team,
          el("span", { class: "spacer" }), el("span", { class: "result-count", id: "q-count", "aria-live": "polite" }), density,
        ]),
        el("div", { id: "q-bulk" }),
        el("div", { class: "card", id: "q-wrap" }, [el("table", { class: "qtable", id: "q-table" }, [el("colgroup", { id: "q-cols" }), el("thead", { id: "q-head" }), el("tbody", { id: "q-body" })])]),
      ]);
      applyDensity();
    }
    drawQueue();
  }
  function applyDensity() {
    const c = pref("iw_density") === "compact";
    const wrap = $("q-wrap"); if (wrap) wrap.classList.toggle("density-compact", c);
    const l = $("density-label"); if (l) l.textContent = c ? "Compact" : "Comfortable";
  }

  function drawQueue() {
    const body = $("q-body"); if (!body) return;
    // Saved views with live counts
    $("q-views").replaceChildren(...VIEWS.map(([key, label, fn]) => {
      const n = state.tickets.filter(fn).length;
      return el("button", { type: "button", role: "tab", "aria-selected": String(q.view === key), onclick: () => { q.view = key; q.sel.clear(); history.replaceState(null, "", "#/queue/" + key); route(false); } },
        [label, el("b", { class: "count" + (key === "breach" && n ? " hot" : ""), text: String(n) })]);
    }));
    // Team options come from the data
    const teamSel = $("q-team");
    const teams = [...new Set(state.tickets.map((t) => t.assigned_team).filter(Boolean))].sort();
    if (teamSel.options.length !== teams.length + 1) {
      teamSel.replaceChildren(el("option", { value: "", text: "Any team" }), ...teams.map((t) => el("option", { value: t, text: t })));
      teamSel.value = q.team;
    }
    $("q-status").value = q.status;
    $("q-cat").value = q.cat;
    document.querySelectorAll("#q-views ~ .toolbar .chip").forEach((b) => b.setAttribute("aria-pressed", String(q.sev.has(b.dataset.sev))));

    const rows = queueRows();
    const refs = new Set(rows.map((t) => t.ticket_ref));
    for (const r of [...q.sel]) if (!refs.has(r)) q.sel.delete(r);
    if (q.cursor && !refs.has(q.cursor)) q.cursor = null;
    $("q-count").textContent = rows.length + " of " + state.tickets.length;

    const cols = [["sel", ""], ["pri", "Pri"], ["ref", "Ticket"], ["what", "Incident"], ["caller", "Caller"], ["state", "Status"], ["sla", "Response"], ["team", "Team"], ["age", "Raised"]];
    const sortable = { pri: "pri", ref: "ref", caller: "caller", state: "status", sla: "sla", age: "age" };
    $("q-cols").replaceChildren(...cols.map(([k]) => el("col", { class: "c-" + k })));
    const allSel = rows.length && rows.every((t) => q.sel.has(t.ticket_ref));
    $("q-head").replaceChildren(el("tr", null, cols.map(([k, label]) => {
      if (k === "sel") return el("th", { class: "c-sel", scope: "col" }, [el("input", { type: "checkbox", "aria-label": "Select all", checked: allSel ? true : null, onchange: (e) => { rows.forEach((t) => e.target.checked ? q.sel.add(t.ticket_ref) : q.sel.delete(t.ticket_ref)); drawQueue(); } })]);
      const s = sortable[k];
      if (!s) return el("th", { class: "c-" + k, scope: "col", text: label });
      const active = q.sort === s;
      return el("th", { class: "c-" + k, scope: "col", "aria-sort": active ? (q.dir === 1 ? "ascending" : "descending") : null }, [el("button", { type: "button", onclick: () => { if (q.sort === s) q.dir = -q.dir; else { q.sort = s; q.dir = 1; } drawQueue(); } },
        [label, active ? icon(q.dir === 1 ? "i-up" : "i-down") : null])]);
    })));

    if (!rows.length) {
      body.replaceChildren(el("tr", null, [el("td", { colspan: "9", style: "height:auto;cursor:default" }, [el("div", { class: "empty" }, [icon("i-search"), el("b", { text: "No tickets match" }), "Try another view, or clear the filters."])])]));
    } else {
      body.replaceChildren(...rows.map((t) => {
        const open = (e) => { if (e.target.closest("input, a, button")) return; location.hash = "#/tickets/" + encodeURIComponent(t.ticket_ref); };
        return el("tr", { dataset: { ref: t.ticket_ref, sev: t.severity }, class: [isOpen(t) ? "" : "done", q.sel.has(t.ticket_ref) ? "sel" : "", q.cursor === t.ticket_ref ? "cur" : "", fresh.has(t.ticket_ref) ? "arrived" : ""].join(" ").trim() || null, onclick: open }, [
          el("td", { class: "c-sel" }, [el("input", { type: "checkbox", "aria-label": "Select " + t.ticket_ref, checked: q.sel.has(t.ticket_ref) ? true : null, onchange: (e) => { if (e.target.checked) q.sel.add(t.ticket_ref); else q.sel.delete(t.ticket_ref); drawQueue(); } })]),
          el("td", { class: "c-pri" }, [pri(t.severity)]),
          el("td", { class: "c-ref" }, [el("a", { class: "ref", href: "#/tickets/" + encodeURIComponent(t.ticket_ref), text: t.ticket_ref })]),
          el("td", { class: "c-what" }, [
            el("span", { class: "t" }, [catName(t.category), t.linked_incident_ref ? el("span", { class: "mi-link", title: "Linked to " + t.linked_incident_ref }, [icon("i-link"), t.linked_incident_ref]) : null]),
            el("span", { class: "s", text: t.affected_system + (isWaiting(t) ? "  ·  Not acknowledged" : t.note_count ? "  ·  " + plural(t.note_count, "update") : "") }),
          ]),
          el("td", { class: "c-caller" }, [el("span", { class: "t", text: t.caller_name }), el("span", { class: "s" }, [verif(t.verification_status), t.organisation ? "  ·  " + t.organisation : ""])]),
          el("td", { class: "c-state" }, [pill(t.status)]),
          el("td", { class: "c-sla" }, [slaMeter(t)]),
          el("td", { class: "c-team" }, [el("span", { class: "t dim", style: "font-weight:400", text: t.assigned_team })]),
          el("td", { class: "c-age", title: when(t.created_at) }, [ago(t.created_at).replace(" ago", "")]),
        ]);
      }));
    }
    drawBulk();
  }

  function drawBulk() {
    const box = $("q-bulk"); if (!box) return;
    if (!q.sel.size) { box.replaceChildren(); return; }
    const msg = el("span", { class: "msg", role: "status" });
    const run = (label, pick, body) => el("button", { class: "btn btn-sm", type: "button", text: label, onclick: async (e) => {
      const targets = [...q.sel].map((r) => state.tickets.find((t) => t.ticket_ref === r)).filter(Boolean).filter(pick);
      if (!targets.length) { msg.className = "msg err"; msg.textContent = "Nothing selected needs that."; return; }
      box.querySelectorAll("button").forEach((b) => { b.disabled = true; });
      let ok = 0;
      for (const t of targets) {
        msg.className = "msg"; msg.textContent = "Updating " + t.ticket_ref;
        try { await updateTicket(t.ticket_ref, body(t)); ok += 1; } catch (err) { msg.className = "msg err"; msg.textContent = t.ticket_ref + ": " + err.message; }
      }
      if (ok === targets.length) q.sel.clear();
      msg.textContent = "Updated " + plural(ok, "ticket");
      poll();
    } });
    box.replaceChildren(el("div", { class: "bulkbar" }, [
      el("b", { text: q.sel.size + " selected" }),
      run("Acknowledge", isWaiting, () => ({ note: ACK_TEXT })),
      run("Start work", (t) => isOpen(t) && t.status !== "in_progress", () => ({ status: "in_progress" })),
      run("Resolve", isOpen, () => ({ status: "resolved" })),
      el("button", { class: "btn btn-sm btn-ghost", type: "button", text: "Clear", onclick: () => { q.sel.clear(); drawQueue(); } }),
      msg,
    ]));
  }

  // ---------- ticket ----------
  function ticketSig(ref) {
    const t = state.tickets.find((x) => x.ticket_ref === ref);
    const callSig = state.calls.filter((c) => c.ticket_ref === ref).map((c) => c.call_id + c.logged_at).join();
    const inc = t && t.linked_incident_ref ? state.incidents.find((i) => i.incident_ref === t.linked_incident_ref) : null;
    return t ? [t.updated_at, t.note_count, t.status, callSig, inc ? inc.status : ""].join("|") : "missing";
  }
  function renderTicket(ref, navigated) {
    const sig = ticketSig(ref);
    if (mounted === "ticket:" + ref && !navigated) {
      // Same ticket: refresh the clock every tick; only refetch if something changed on the server.
      if (drawnTicket && drawnTicket.sig === sig) { refreshTicketClock(); return; }
    }
    if (mounted !== "ticket:" + ref || navigated) mount("ticket:" + ref, [el("p", { class: "muted", text: "Loading " + ref })]);
    api("/board/api/tickets/" + encodeURIComponent(ref))
      .then((d) => { if (parse().arg === ref) { drawTicket(d, sig); } })
      .catch((e) => {
        drawnTicket = null;
        mount("ticket:" + ref, [
          el("a", { class: "btn btn-sm btn-ghost", href: "#/tickets" }, [icon("i-left"), "Back to queue"]),
          el("div", { class: "card", style: "margin-top:14px" }, [el("div", { class: "empty" }, [icon("i-alert"), el("b", { text: "Couldn't open " + ref }), e.message])]),
        ]);
      });
  }
  function neighbours(ref) {
    let list = queueRows().map((t) => t.ticket_ref);
    if (!list.includes(ref)) list = state.tickets.slice().sort((a, b) => b.created_at.localeCompare(a.created_at)).map((t) => t.ticket_ref);
    const i = list.indexOf(ref);
    return { prev: i > 0 ? list[i - 1] : null, next: i >= 0 && i < list.length - 1 ? list[i + 1] : null, pos: i + 1, total: list.length };
  }
  function refreshTicketClock() {
    const box = $("tk-sla"); const r = parse();
    const t = state.tickets.find((x) => x.ticket_ref === r.arg);
    if (box && t) box.replaceChildren(...slaBlock(t));
  }
  function slaBlock(t) {
    const s = sla(t);
    let big, cls, label;
    if (s.state === "breach") { big = "+" + clockText(s.elapsed - s.target); cls = "breach"; label = "Response target missed"; }
    else if (s.state === "warn" || s.state === "ok") { big = clockText(s.left); cls = s.state; label = "Time left to respond"; }
    else if (s.state === "met" || s.state === "late") { big = dur(s.elapsed); cls = "met"; label = s.state === "late" ? "First response, over target" : "First response, within target"; }
    else { big = "–"; cls = "met"; label = "Closed without a response"; }
    const bar = el("div", { class: "sla " + s.state }, [el("div", { class: "sla-bar", title: "Target " + dur(s.target) + " for " + t.severity }, [el("i", { style: "width:" + Math.round(s.ratio * 100) + "%" })])]);
    return [el("span", { class: "eyebrow", text: label }), el("span", { class: "big " + cls, text: big }), bar, el("span", { class: "muted", style: "font-size:12px", text: t.severity + " target " + dur(s.target) })];
  }

  function drawTicket(d, sig) {
    const t = d.ticket, tCalls = d.calls || [], inc = d.incident, cust = d.customer || null;
    const summary = state.tickets.find((x) => x.ticket_ref === t.ticket_ref) || t;
    const notes = t.notes || [];
    const first = (t.caller_name || "").split(" ")[0] || "the caller";
    const same = drawnTicket && drawnTicket.ref === t.ticket_ref && mounted === "ticket:" + t.ticket_ref && $("tk-body");
    drawnTicket = { ref: t.ticket_ref, sig };

    // Header
    const msg = el("span", { class: "msg", role: "status", id: "tk-msg" });
    const act = (body, btn) => {
      btn.disabled = true; msg.className = "msg"; msg.textContent = "Saving";
      return updateTicket(t.ticket_ref, body).then(() => { msg.className = "msg ok"; msg.textContent = "Saved"; poll(); })
        .catch((e) => { msg.className = "msg err"; msg.textContent = e.message; btn.disabled = false; });
    };
    const buttons = [];
    if (isWaiting(summary)) {
      const b = el("button", { class: "btn btn-primary", type: "button", id: "act-ack", onclick: () => act({ note: ACK_TEXT }, b) }, [icon("i-check"), "Acknowledge", el("kbd", { text: "A" })]);
      buttons.push(b);
    }
    for (const [status, label, tone, ico] of NEXT[t.status] || []) {
      const primary = tone === "primary" && !isWaiting(summary);
      const b = el("button", { class: "btn" + (primary ? " btn-primary" : tone === "danger" ? " btn-danger" : tone === "ok" ? " btn-ok" : ""), type: "button", dataset: { status }, onclick: () => act({ status }, b) },
        [icon(ico), label, status === "in_progress" ? el("kbd", { text: "S" }) : status === "escalated" ? el("kbd", { text: "E" }) : status === "resolved" ? el("kbd", { text: "R" }) : null]);
      buttons.push(b);
    }
    const nb = neighbours(t.ticket_ref);
    const head = [
      el("div", { class: "tk-nav" }, [
        el("a", { class: "btn btn-sm btn-ghost", href: "#/queue/" + q.view }, [icon("i-left"), "Queue"]),
        el("span", { class: "pos", text: nb.pos ? nb.pos + " of " + nb.total : "" }),
        el("a", { class: "btn btn-sm", href: nb.prev ? "#/tickets/" + encodeURIComponent(nb.prev) : null, "aria-disabled": nb.prev ? null : "true", title: "Previous (K)", style: nb.prev ? null : "opacity:.4;pointer-events:none" }, [icon("i-up"), el("kbd", { text: "K" })]),
        el("a", { class: "btn btn-sm", href: nb.next ? "#/tickets/" + encodeURIComponent(nb.next) : null, "aria-disabled": nb.next ? null : "true", title: "Next (J)", style: nb.next ? null : "opacity:.4;pointer-events:none" }, [icon("i-down"), el("kbd", { text: "J" })]),
      ]),
      el("section", { class: "card tk-head", dataset: { sev: t.severity } }, [
        el("div", null, [
          el("div", { class: "tk-id" }, [pri(t.severity), el("span", { class: "ref", text: t.ticket_ref }), copyBtn(t.ticket_ref, "ticket reference"), pill(t.status), cust ? el("span", { class: "tier", dataset: { tier: cust.tier }, text: cust.tier + " client" }) : null]),
          el("h2", { text: titleOf(t) }),
          el("div", { class: "tk-meta" }, [
            el("span", null, [icon("i-bot"), "Raised by Aggie " + ago(t.created_at)]),
            el("span", null, [icon("i-building"), t.organisation || "Unknown organisation"]),
            el("span", null, [icon("i-user"), t.assigned_team]),
            inc ? el("a", { class: "mi-link", href: "#/incidents", style: "margin:0;font-size:12px" }, [icon("i-link"), inc.incident_ref]) : null,
          ]),
        ]),
        el("div", { class: "tk-sla", id: "tk-sla" }, slaBlock(summary)),
        el("div", { class: "actionbar" }, [...buttons, msg]),
      ]),
    ];

    // Main column
    const facts = el("dl", { class: "kv" }, [
      ["Category", catName(t.category)], ["Affected system", t.affected_system], ["Discovered", t.time_detected ? when(t.time_detected) : "Not given"],
      ["Raised", when(t.created_at)], ["Last update", when(t.updated_at)], ["Call ID", t.call_id || "None"],
    ].flatMap(([k, v]) => [el("dt", { text: k }), el("dd", { class: k === "Call ID" ? "mono" : null, text: v })]));
    const summaryCard = el("section", { class: "card" }, [
      el("div", { class: "card-head" }, [el("h3", { text: "Incident summary" })]),
      el("div", { class: "card-body" }, [
        el("p", { class: "desc", text: t.description }),
        el("div", { class: "eyebrow sub-h", text: "Already done by the caller" }),
        t.containment_actions_taken && t.containment_actions_taken.length
          ? el("div", { class: "tags" }, t.containment_actions_taken.map((a) => el("span", { class: "tag" }, [icon("i-check", "ico-sm"), " " + a])))
          : el("p", { class: "muted", text: "Nothing reported." }),
        el("div", { class: "eyebrow sub-h", text: "Details" }),
        facts,
        inc ? el("div", { class: "callout mi" }, [el("span", { class: "eyebrow", text: "Part of major incident " + inc.incident_ref }), el("b", { text: inc.title }), el("div", { class: "muted", text: "Status: " + (MI_STEPS.find((s) => s[0] === inc.status)?.[1] || inc.status) })]) : null,
      ]),
    ]);

    // Playbook: completed steps are notes on the timeline, so progress is shared and survives reloads.
    const steps = PLAYBOOK[t.category] || PLAYBOOK.other;
    const doneBy = {};
    for (const n of notes) if (n.kind === "note" && n.text.startsWith(PLAYBOOK_PREFIX)) doneBy[n.text.slice(PLAYBOOK_PREFIX.length)] = n;
    const doneCount = steps.filter((s) => doneBy[s]).length;
    const playbook = el("section", { class: "card" }, [
      el("div", { class: "card-head" }, [el("h3", { text: "Response playbook" }), el("span", { class: "hint", text: catName(t.category) }),
        el("div", { class: "end progress" }, [el("span", { text: doneCount + "/" + steps.length }), el("span", { class: "sla-bar" }, [el("i", { style: "width:" + Math.round((doneCount / steps.length) * 100) + "%" })])])]),
      el("ol", { class: "plain playbook" }, steps.map((s) => {
        const n = doneBy[s];
        const box = el("button", { class: "pb-box", type: "button", "aria-label": n ? "Done: " + s : "Mark done: " + s, disabled: n ? true : null, onclick: () => {
          box.disabled = true;
          updateTicket(t.ticket_ref, { note: PLAYBOOK_PREFIX + s }).then(() => poll()).catch((e) => { box.disabled = false; const m = $("tk-msg"); if (m) { m.className = "msg err"; m.textContent = e.message; } });
        } }, [icon("i-check")]);
        return el("li", { class: n ? "done" : "" }, [box, el("span", { class: "pb-t", text: s }), el("span", { class: "pb-m", text: n ? n.author + ", " + when(n.at) : "" })]);
      })),
    ]);

    // Timeline
    const events = [{ at: t.created_at, cls: "tl-raised", ico: "i-bot", who: "Aggie", what: "raised the ticket", body: "Assigned to " + t.assigned_team + " at " + t.severity + "." }];
    for (const c of tCalls) events.push({ at: c.logged_at, cls: "tl-call", ico: "i-phone", who: "Aggie", what: "logged a call (" + (REASON[c.call_reason] || c.call_reason).toLowerCase() + ")", body: c.summary });
    for (const n of notes) {
      if (n.kind === "status") events.push({ at: n.at, cls: "tl-status", ico: "i-flow", who: n.author, what: n.text.charAt(0).toLowerCase() + n.text.slice(1), body: "" });
      else if (n.text.startsWith(PLAYBOOK_PREFIX)) events.push({ at: n.at, cls: "tl-play", ico: "i-check", who: n.author, what: "completed a playbook step", body: n.text.slice(PLAYBOOK_PREFIX.length) });
      else events.push({ at: n.at, cls: "tl-note", ico: "i-note", who: n.author, what: "added a note", body: n.text });
    }
    events.sort((a, b) => a.at.localeCompare(b.at));
    const timeline = el("ol", { class: "plain timeline", id: "tk-timeline" }, events.map((e) => el("li", { class: e.cls }, [
      el("span", { class: "tl-ico" }, [icon(e.ico)]),
      el("div", { style: "min-width:0" }, [
        el("div", { class: "tl-who" }, [el("b", { text: e.who }), el("span", { text: e.what }), el("time", { datetime: e.at, title: e.at, text: when(e.at) })]),
        e.body ? el("div", { class: "tl-body", text: e.body }) : null,
      ]),
    ])));

    // Caller and Aggie side cards
    const related = state.tickets.filter((x) => x.ticket_ref !== t.ticket_ref && ((t.caller_phone && x.caller_phone === t.caller_phone) || (x.caller_name === t.caller_name && x.organisation === t.organisation)));
    const lastCall = tCalls[tCalls.length - 1] || null;
    const side = el("div", { class: "stack", id: "tk-side" }, [
      el("section", { class: "card side-card" }, [
        el("div", { class: "card-head" }, [el("h3", { text: "Caller" }), el("div", { class: "end" }, [verif(lastCall && lastCall.verification_status)])]),
        el("div", { class: "card-body" }, [
          el("div", { class: "person" }, [el("span", { class: "avatar", text: initials(t.caller_name) }), el("div", null, [el("b", { text: t.caller_name }), el("span", { text: (cust && cust.role ? cust.role + ", " : "") + (t.organisation || "Unknown organisation") })])]),
          el("dl", { class: "kv" }, [
            el("dt", { text: "Phone" }), el("dd", null, [el("span", { class: "mono", text: t.caller_phone || "Withheld" }), t.caller_phone ? copyBtn(t.caller_phone, "phone number") : null]),
            el("dt", { text: "Customer ID" }), el("dd", { class: t.customer_id ? "mono" : null, text: t.customer_id || "Not on file" }),
            el("dt", { text: "Service tier" }), el("dd", null, [cust ? el("span", { class: "tier", dataset: { tier: cust.tier }, text: cust.tier }) : "Unknown"]),
          ]),
          related.length ? el("div", null, [
            el("div", { class: "eyebrow", style: "margin:6px 0 2px", text: "Other tickets from this caller" }),
            el("ul", { class: "plain related" }, related.slice(0, 5).map((x) => el("li", null, [el("a", { href: "#/tickets/" + encodeURIComponent(x.ticket_ref) }, [pri(x.severity), el("span", { class: "ref", text: x.ticket_ref }), el("span", { class: "t muted", text: catName(x.category) }), pill(x.status)])]))),
          ]) : null,
        ]),
      ]),
      el("section", { class: "card side-card" }, [
        el("div", { class: "card-head" }, [el("h3", { text: "Aggie's handover" }), lastCall ? el("div", { class: "end" }, [el("span", { class: lastCall.transfer_priority === "Urgent" ? "prio-urgent" : "prio-std", text: lastCall.transfer_priority.toUpperCase() })]) : null]),
        el("div", { class: "card-body" }, lastCall ? [
          el("p", { style: "font-size:13px;line-height:1.55", text: lastCall.summary }),
          lastCall.advice_given ? el("div", { class: "callout" }, [el("span", { class: "eyebrow", text: "Advice given on the call" }), lastCall.advice_given]) : null,
          lastCall.notes ? el("div", { class: "callout flag" }, [el("span", { class: "eyebrow", text: "Flag for the handler" }), lastCall.notes]) : null,
          el("p", { class: "muted", style: "font-size:12px" }, ["Logged " + when(lastCall.logged_at) + " · ", el("span", { class: "mono", text: lastCall.call_id })]),
        ] : [el("p", { class: "muted", text: "No call log for this ticket yet. Aggie logs the call when she hands over." })]),
      ]),
    ]);

    if (same) {
      // Keep the note composer (and anything typed in it) in place; swap everything else.
      $("tk-headwrap").replaceChildren(...head);
      $("tk-summary").replaceChildren(summaryCard, playbook);
      $("tk-timeline").replaceWith(timeline);
      $("tk-side").replaceWith(side);
      const ta = $("note-text"); if (ta) ta.placeholder = "Update the timeline. What you did, found or told " + first + ".";
      return;
    }

    const ta = el("textarea", { class: "input", id: "note-text", placeholder: "Update the timeline. What you did, found or told " + first + ".", "aria-label": "Note",
      onkeydown: (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); form.requestSubmit(); } } });
    const nmsg = el("span", { class: "msg", role: "status" });
    const nbtn = el("button", { class: "btn btn-primary", type: "submit" }, ["Add note", el("kbd", { text: "Ctrl ↵" })]);
    const insert = (text) => {
      const s = ta.selectionStart ?? ta.value.length, e = ta.selectionEnd ?? ta.value.length;
      const pre = ta.value.slice(0, s), add = (pre && !/\s$/.test(pre) ? " " : "") + text;
      ta.value = pre + add + ta.value.slice(e); ta.focus(); ta.selectionStart = ta.selectionEnd = (pre + add).length;
    };
    const form = el("form", { class: "composer", id: "note-form", onsubmit: (e) => {
      e.preventDefault();
      const text = ta.value.trim();
      if (!text) { nmsg.className = "msg err"; nmsg.textContent = "Write a note first."; ta.focus(); return; }
      nbtn.disabled = true; nmsg.className = "msg"; nmsg.textContent = "Saving";
      updateTicket(drawnTicket.ref, { note: text }).then(() => { ta.value = ""; nmsg.className = "msg ok"; nmsg.textContent = "Added to the timeline"; poll(); })
        .catch((err) => { nmsg.className = "msg err"; nmsg.textContent = err.message; }).finally(() => { nbtn.disabled = false; });
    } }, [
      el("div", { class: "macros" }, MACROS.map(([label, text]) => el("button", { class: "btn btn-sm", type: "button", text: "+ " + label, onclick: () => insert(text) }))),
      ta,
      el("div", { class: "composer-foot" }, [nmsg, el("span", { class: "muted", style: "font-size:12px", text: "Notes are visible to every handler" }), nbtn]),
    ]);

    mount("ticket:" + t.ticket_ref, [
      el("div", { id: "tk-headwrap" }, head),
      el("div", { class: "tk-grid", id: "tk-body" }, [
        el("div", { class: "stack" }, [
          el("div", { class: "stack", id: "tk-summary" }, [summaryCard, playbook]),
          el("section", { class: "card" }, [el("div", { class: "card-head" }, [el("h3", { text: "Activity" }), el("span", { class: "hint", text: "Oldest first" })]), timeline, form]),
        ]),
        side,
      ]),
    ]);
  }

  // ---------- calls ----------
  function renderCalls() {
    const all = state.calls;
    const n = (v) => all.filter((c) => c.verification_status === v).length;
    if (mounted !== "calls") {
      mount("calls", [
        el("div", { class: "stats", id: "c-stats" }),
        el("div", { class: "views", role: "tablist", id: "c-views", "aria-label": "Identity check" }),
        el("div", { class: "card" }, [el("table", { class: "qtable calls-t" }, [
          el("colgroup", null, ["time", "who", "ver", "why", "tk", "sum", "pr"].map((k) => el("col", { class: "c-" + k }))),
          el("thead", null, [el("tr", null, [["time", "Time"], ["who", "Caller"], ["ver", "ID check"], ["why", "Reason"], ["tk", "Ticket"], ["sum", "Aggie's summary"], ["pr", "Transfer"]].map(([k, h]) => el("th", { class: "c-" + k, scope: "col", text: h })))]),
          el("tbody", { id: "c-body" }),
        ])]),
      ]);
    }
    const urgent = all.filter((c) => c.transfer_priority === "Urgent").length;
    $("c-stats").replaceChildren(
      kpi("Calls logged", String(all.length), all.length ? "Latest " + ago(all[0].logged_at) : "None yet"),
      kpi("Verified", String(n("Verified")), all.length ? Math.round((n("Verified") / all.length) * 100) + "% of calls" : "–", "ok"),
      kpi("Unverified or failed", String(n("Unverified") + n("Failed")), plural(n("Failed"), "failed check"), n("Failed") ? "warn" : ""),
      kpi("Urgent transfers", String(urgent), "Passed straight to a handler", urgent ? "bad" : ""),
    );
    $("c-views").replaceChildren(...[["all", "All calls", all.length], ["Verified", "Verified", n("Verified")], ["Unverified", "Unverified", n("Unverified")], ["Failed", "Failed", n("Failed")]].map(([k, label, c]) =>
      el("button", { type: "button", role: "tab", "aria-selected": String(calls.ver === k), onclick: () => { calls.ver = k; renderCalls(); } }, [label, el("b", { class: "count" + (k === "Failed" && c ? " hot" : ""), text: String(c) })])));
    const rows = all.filter((c) => calls.ver === "all" || c.verification_status === calls.ver);
    $("c-body").replaceChildren(...(rows.length ? rows.map((c) => {
      const tr = el("tr", { class: calls.open.has(c.call_id) ? "open" : null, onclick: (e) => {
        if (e.target.closest("a")) return;
        if (calls.open.has(c.call_id)) calls.open.delete(c.call_id); else calls.open.add(c.call_id);
        tr.classList.toggle("open");
      } }, [
        el("td", { class: "c-time" }, [el("span", { class: "t mono", style: "font-weight:500", text: valid(c.logged_at) ? fTime.format(new Date(c.logged_at)) : "--:--" }), el("span", { class: "s", text: (valid(c.logged_at) ? fDay.format(new Date(c.logged_at)) + " · " : "") + ago(c.logged_at) })]),
        el("td", { class: "c-who" }, [el("span", { class: "t", text: c.caller_name || "Unknown caller" }), el("span", { class: "s", text: c.organisation || "" })]),
        el("td", { class: "c-ver" }, [verif(c.verification_status)]),
        el("td", { class: "c-why" }, [el("span", { class: "t", style: "font-weight:400", text: REASON[c.call_reason] || c.call_reason })]),
        el("td", { class: "c-tk" }, [c.ticket_ref ? el("a", { class: "ref", href: "#/tickets/" + encodeURIComponent(c.ticket_ref), text: c.ticket_ref }) : el("span", { class: "muted", text: "None" })]),
        el("td", { class: "c-sum" }, [
          el("span", { class: "sum", text: c.summary }),
          el("div", { class: "more" }, [
            c.advice_given ? el("div", { class: "callout", style: "margin:0" }, [el("span", { class: "eyebrow", text: "Advice given" }), c.advice_given]) : null,
            c.notes ? el("div", { class: "callout flag", style: "margin:0" }, [el("span", { class: "eyebrow", text: "Flag" }), c.notes]) : null,
            el("span", { class: "muted mono", style: "font-size:11.5px", text: "Call ID " + c.call_id }),
          ]),
        ]),
        el("td", { class: "c-pr" }, [el("span", { class: c.transfer_priority === "Urgent" ? "prio-urgent" : "prio-std", text: (c.transfer_priority || "Standard").toUpperCase() })]),
      ]);
      return tr;
    }) : [el("tr", null, [el("td", { colspan: "7", style: "cursor:default" }, [el("div", { class: "empty" }, [icon("i-phone"), el("b", { text: "No calls to show" }), calls.ver === "all" ? "Each call Aggie handles is logged here when she hands over." : "No calls with that result."])])])]));
  }

  // ---------- major incidents ----------
  function renderIncidents() {
    const list = state.incidents.slice().sort((a, b) => {
      const ar = a.status === "resolved", br = b.status === "resolved";
      if (ar !== br) return ar ? 1 : -1;
      return b.started_at.localeCompare(a.started_at);
    });
    const byRef = new Map(state.tickets.map((t) => [t.ticket_ref, t]));
    const activeN = list.filter((i) => i.status !== "resolved").length;
    mount("incidents", [
      el("div", { class: "ov-head" }, [el("div", null, [
        el("h2", { text: activeN ? plural(activeN, "major incident") + " in progress" : "No major incidents in progress" }),
        el("p", { text: "When a caller's problem matches one of these, Aggie tells them it's known and links their ticket. Three similar reports within an hour open one automatically." }),
      ])]),
      list.length ? el("div", { class: "mi-list" }, list.map((i) => {
        const msg = el("span", { class: "msg", role: "status" });
        const idx = MI_STEPS.findIndex((s) => s[0] === i.status);
        const resolved = i.status === "resolved";
        const stepper = el("div", { class: "stepper", dataset: { status: i.status } }, MI_STEPS.map(([key, label], n) => {
          const b = el("button", { class: "step" + (n < idx ? " past" : n === idx ? " cur" : ""), type: "button", "aria-current": n === idx ? "step" : null, title: n === idx ? "Current status" : "Set status to " + label, onclick: () => {
            if (n === idx) return;
            stepper.querySelectorAll("button").forEach((x) => { x.disabled = true; });
            msg.className = "msg"; msg.textContent = "Saving";
            post("/board/api/incidents/" + encodeURIComponent(i.incident_ref), { status: key }).then(() => { msg.className = "msg ok"; msg.textContent = "Saved"; poll(); })
              .catch((e) => { msg.className = "msg err"; msg.textContent = e.message; stepper.querySelectorAll("button").forEach((x) => { x.disabled = false; }); });
          } }, [el("i"), label]);
          return b;
        }));
        const end = resolved && i.resolved_at ? new Date(i.resolved_at).getTime() : now();
        const linked = (i.linked_tickets || []).map((r) => byRef.get(r)).filter(Boolean);
        return el("section", { class: "card mi" + (i.auto_detected ? " auto" : "") + (resolved ? " is-resolved" : "") }, [
          el("div", { class: "mi-head" }, [
            el("div", null, [
              el("div", { class: "mi-id" }, [el("span", { class: "ref", text: i.incident_ref }), pill(i.status, MI_STEPS[idx] ? MI_STEPS[idx][1] : i.status), i.auto_detected ? el("span", { class: "auto-flag" }, [icon("i-radar"), "Auto-detected"]) : null, el("span", { class: "tag", text: catName(i.category) })]),
              el("h3", { text: i.title }),
            ]),
            el("div", { class: "mi-dur" }, [el("span", { class: "eyebrow", text: resolved ? "Lasted" : "Running for" }), el("b", { text: dur(end - new Date(i.started_at).getTime()) }), el("span", { class: "muted", style: "font-size:12px", text: "Since " + when(i.started_at) })]),
          ]),
          stepper,
          el("div", { class: "mi-body" }, [
            el("div", null, [
              el("div", { class: "eyebrow", text: "What Aggie tells callers" }),
              el("div", { class: "callout", style: "margin-top:8px" }, [i.caller_guidance]),
              el("div", { class: "eyebrow sub-h", text: "Affected systems" }),
              el("div", { class: "tags" }, i.affected_systems.map((x) => el("span", { class: "tag mono", text: x }))),
              el("div", { style: "margin-top:12px" }, [msg]),
            ]),
            el("div", null, [
              el("div", { class: "eyebrow", text: plural(linked.length, "linked ticket") }),
              linked.length
                ? el("ul", { class: "plain linked", style: "margin-top:6px" }, linked.map((t) => el("li", null, [pri(t.severity), el("a", { class: "ref", href: "#/tickets/" + encodeURIComponent(t.ticket_ref), text: t.ticket_ref }), el("span", { class: "t", text: t.caller_name + (t.organisation ? ", " + t.organisation : "") }), pill(t.status)])))
                : el("p", { class: "muted", style: "margin-top:8px", text: "No tickets linked yet." }),
            ]),
          ]),
        ]);
      })) : el("div", { class: "card" }, [el("div", { class: "empty" }, [icon("i-radar"), el("b", { text: "No major incidents" })])]),
    ]);
  }

  // ---------- overlays: palette, shortcuts, name ----------
  function closeOverlay() { $("overlay").replaceChildren(); }
  function overlay(dialog, onClose) {
    const scrim = el("div", { class: "scrim", onclick: (e) => { if (e.target === scrim) { closeOverlay(); if (onClose) onClose(); } } }, [dialog]);
    $("overlay").replaceChildren(scrim);
  }
  const overlayOpen = () => $("overlay").children.length > 0;

  function openPalette() {
    if (!state) return;
    const input = el("input", { type: "text", placeholder: "Search tickets by ref, caller or system, or type a command", "aria-label": "Search", autocomplete: "off", spellcheck: "false" });
    const list = el("div", { class: "palette-list", role: "listbox", id: "pal-list" });
    let items = [], idx = 0;
    const commands = [
      ["Go to overview", "G O", () => { location.hash = "#/overview"; }, "i-grid"],
      ["Go to ticket queue", "G T", () => { location.hash = "#/queue/open"; }, "i-ticket"],
      ["Go to call log", "G C", () => { location.hash = "#/calls"; }, "i-phone"],
      ["Go to major incidents", "G I", () => { location.hash = "#/incidents"; }, "i-radar"],
      ...VIEWS.slice(1).map(([k, label]) => ["View: " + label, "", () => { q.view = k; location.hash = "#/queue/" + k; route(false); }, "i-sliders"]),
      ["Switch light or dark theme", "", toggleTheme, "i-contrast"],
      [soundOn() ? "Turn the new-ticket chime off" : "Turn the new-ticket chime on", "", toggleSound, soundOn() ? "i-bell-off" : "i-bell"],
      ["Change my name on notes", "", askName, "i-user"],
      ["Keyboard shortcuts", "?", showKeys, "i-keyboard"],
    ];
    const draw = () => {
      const s = input.value.trim().toLowerCase();
      const tickets = state.tickets.filter((t) => !s || [t.ticket_ref, t.caller_name, t.organisation, t.affected_system, catName(t.category), t.caller_phone].join(" ").toLowerCase().includes(s))
        .sort((a, b) => (isOpen(a) === isOpen(b) ? 0 : isOpen(a) ? -1 : 1) || SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || b.created_at.localeCompare(a.created_at)).slice(0, s ? 8 : 5);
      const cmds = commands.filter((c) => !s || c[0].toLowerCase().includes(s));
      items = [];
      const nodes = [];
      if (tickets.length) {
        nodes.push(el("div", { class: "palette-group eyebrow", text: "Tickets" }));
        for (const t of tickets) {
          const i = items.length;
          items.push(() => { location.hash = "#/tickets/" + encodeURIComponent(t.ticket_ref); });
          nodes.push(el("div", { class: "palette-item", role: "option", dataset: { i: String(i) }, onclick: () => { closeOverlay(); items[i](); } }, [pri(t.severity), el("span", { class: "ref", text: t.ticket_ref }), el("span", { class: "t", text: titleOf(t) + " · " + t.caller_name }), pill(t.status)]));
        }
      }
      if (cmds.length) {
        nodes.push(el("div", { class: "palette-group eyebrow", text: "Commands" }));
        for (const c of cmds) {
          const i = items.length;
          items.push(c[2]);
          nodes.push(el("div", { class: "palette-item", role: "option", dataset: { i: String(i) }, onclick: () => { closeOverlay(); items[i](); } }, [icon(c[3]), el("span", { class: "t", text: c[0] }), c[1] ? el("kbd", { text: c[1] }) : null]));
        }
      }
      if (!items.length) nodes.push(el("div", { class: "empty", text: "Nothing matches." }));
      list.replaceChildren(...nodes);
      idx = Math.min(idx, Math.max(0, items.length - 1));
      mark();
    };
    const mark = () => list.querySelectorAll(".palette-item").forEach((n) => {
      const on = Number(n.dataset.i) === idx;
      n.setAttribute("aria-selected", String(on));
      if (on) n.scrollIntoView({ block: "nearest" });
    });
    input.addEventListener("input", () => { idx = 0; draw(); });
    input.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown") { e.preventDefault(); idx = Math.min(items.length - 1, idx + 1); mark(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); idx = Math.max(0, idx - 1); mark(); }
      else if (e.key === "Enter") { e.preventDefault(); const f = items[idx]; closeOverlay(); if (f) f(); }
      else if (e.key === "Escape") { e.preventDefault(); closeOverlay(); }
    });
    overlay(el("div", { class: "dialog", role: "dialog", "aria-modal": "true", "aria-label": "Search and commands" }, [
      el("div", { class: "palette-input" }, [icon("i-search"), input, el("kbd", { text: "Esc" })]),
      list,
      el("div", { class: "palette-foot" }, [el("span", { text: "↑ ↓ to move" }), el("span", { text: "↵ to open" }), el("span", { text: "Esc to close" })]),
    ]));
    draw();
    input.focus();
  }

  function showKeys() {
    const rows = [["Search and commands", "Ctrl K"], ["Search (alternative)", "/"], ["Overview", "G then O"], ["Ticket queue", "G then T"], ["Call log", "G then C"], ["Major incidents", "G then I"],
      ["Queue: move down / up", "J / K"], ["Queue: open ticket", "Enter"], ["Queue: select ticket", "X"], ["Ticket: next / previous", "J / K"],
      ["Ticket: acknowledge", "A"], ["Ticket: start work", "S"], ["Ticket: escalate", "E"], ["Ticket: resolve", "R"], ["Ticket: write a note", "N"], ["Ticket: save note", "Ctrl Enter"],
      ["Back to queue", "U"], ["This help", "?"]];
    overlay(el("div", { class: "dialog", role: "dialog", "aria-modal": "true", "aria-label": "Keyboard shortcuts" }, [
      el("div", { class: "dialog-head" }, [el("h2", { text: "Keyboard shortcuts" })]),
      el("div", { class: "dialog-body" }, [el("div", { class: "keys" }, rows.map(([a, k]) => el("div", null, [el("span", { text: a }), el("kbd", { text: k })])))]),
      el("div", { class: "dialog-foot" }, [el("button", { class: "btn", type: "button", text: "Close", onclick: closeOverlay })]),
    ]));
    $("overlay").querySelector(".btn").focus();
  }

  function askName() {
    if (state && state.password_required) return;
    const input = el("input", { class: "input", id: "name-in", type: "text", maxlength: "40", value: myName(), autocomplete: "name", placeholder: "For example, Sam Patel" });
    const save = (e) => { if (e) e.preventDefault(); pref("iw_name", input.value.trim().slice(0, 40)); closeOverlay(); if (state) chrome(); };
    overlay(el("form", { class: "dialog dialog-sm", role: "dialog", "aria-modal": "true", "aria-label": "Your name", onsubmit: save }, [
      el("div", { class: "dialog-head" }, [el("h2", { text: "Your name on the desk" })]),
      el("div", { class: "dialog-body" }, [el("div", { class: "field" }, [el("label", { for: "name-in", text: "Shown on notes and status changes you make" }), input])]),
      el("div", { class: "dialog-foot" }, [el("button", { class: "btn btn-ghost", type: "button", text: "Cancel", onclick: closeOverlay }), el("button", { class: "btn btn-primary", type: "submit", text: "Save" })]),
    ]));
    input.focus(); input.select();
  }

  function toggleTheme() {
    const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    pref("iw_theme", next);
  }
  function toggleSound() {
    const on = !soundOn();
    pref("iw_sound", on ? "1" : "0");
    paintSound();
    if (on) chime(false);
  }
  function paintSound() {
    const b = $("sound-btn"), on = soundOn();
    b.setAttribute("aria-pressed", String(on));
    b.title = on ? "New-ticket chime is on" : "New-ticket chime is off";
    b.replaceChildren(icon(on ? "i-bell" : "i-bell-off"));
  }

  // ---------- keyboard ----------
  let gPending = 0;
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "K")) { e.preventDefault(); if (overlayOpen()) closeOverlay(); else openPalette(); return; }
    if (e.key === "Escape" && overlayOpen()) { closeOverlay(); return; }
    if (overlayOpen() || typing(e) || e.ctrlKey || e.metaKey || e.altKey) return;
    const k = e.key;
    if (Date.now() - gPending < 1200) {
      gPending = 0;
      const dest = { o: "#/overview", t: "#/queue/open", c: "#/calls", i: "#/incidents" }[k.toLowerCase()];
      if (dest) { e.preventDefault(); location.hash = dest; }
      return;
    }
    if (k === "g" || k === "G") { gPending = Date.now(); return; }
    if (k === "/") { e.preventDefault(); openPalette(); return; }
    if (k === "?") { e.preventDefault(); showKeys(); return; }
    if (!state) return;
    const r = parse();
    if (r.view === "tickets" && !r.arg) {
      const rows = queueRows().map((t) => t.ticket_ref);
      if (!rows.length) return;
      let i = rows.indexOf(q.cursor);
      if (k === "j" || k === "ArrowDown") { e.preventDefault(); q.cursor = rows[Math.min(rows.length - 1, i + 1)]; markCursor(); }
      else if (k === "k" || k === "ArrowUp") { e.preventDefault(); q.cursor = rows[Math.max(0, i === -1 ? 0 : i - 1)]; markCursor(); }
      else if ((k === "Enter" || k === "o") && q.cursor) { e.preventDefault(); location.hash = "#/tickets/" + encodeURIComponent(q.cursor); }
      else if (k === "x" && q.cursor) { e.preventDefault(); if (q.sel.has(q.cursor)) q.sel.delete(q.cursor); else q.sel.add(q.cursor); drawQueue(); }
      else if (k === "Escape" && q.sel.size) { q.sel.clear(); drawQueue(); }
    } else if (r.view === "tickets" && r.arg) {
      const nb = neighbours(r.arg);
      const click = (sel) => { const b = document.querySelector(sel); if (b && !b.disabled) { e.preventDefault(); b.click(); } };
      if (k === "j" && nb.next) { e.preventDefault(); q.cursor = nb.next; location.hash = "#/tickets/" + encodeURIComponent(nb.next); }
      else if (k === "k" && nb.prev) { e.preventDefault(); q.cursor = nb.prev; location.hash = "#/tickets/" + encodeURIComponent(nb.prev); }
      else if (k === "u" || k === "Escape") { e.preventDefault(); q.cursor = r.arg; location.hash = "#/queue/" + q.view; }
      else if (k === "a") click("#act-ack");
      else if (k === "s") click('.actionbar [data-status="in_progress"]');
      else if (k === "e") click('.actionbar [data-status="escalated"]');
      else if (k === "r") click('.actionbar [data-status="resolved"]');
      else if (k === "n") { const ta = $("note-text"); if (ta) { e.preventDefault(); ta.focus(); ta.scrollIntoView({ block: "center" }); } }
    }
  });
  function markCursor() {
    document.querySelectorAll("#q-body tr").forEach((tr) => {
      const on = tr.dataset.ref === q.cursor;
      tr.classList.toggle("cur", on);
      if (on) tr.scrollIntoView({ block: "nearest" });
    });
  }

  // ---------- start ----------
  $("search-btn").addEventListener("click", openPalette);
  $("keys-btn").addEventListener("click", showKeys);
  $("theme-btn").addEventListener("click", toggleTheme);
  $("sound-btn").addEventListener("click", toggleSound);
  $("who-btn").addEventListener("click", askName);
  paintSound();

  const tickClock = () => { $("clock-uk").textContent = fTime.format(new Date(now())); };
  tickClock();
  setInterval(tickClock, 10000);
  // Response clocks count down on their own: refresh the ticket header every second and lists every 15.
  setInterval(() => { if (state && parse().view === "tickets" && parse().arg) refreshTicketClock(); }, 1000);
  setInterval(() => {
    setLive();
    if (!state) return;
    const r = parse();
    if (r.view === "overview") renderOverview();
    else if (r.view === "tickets" && !r.arg) drawQueue();
    else if (r.view === "incidents") renderIncidents();
    chrome();
  }, 15000);
  if (!location.hash) history.replaceState(null, "", "#/overview");
  poll();
})();
