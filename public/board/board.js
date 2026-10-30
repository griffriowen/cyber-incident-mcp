"use strict";
// Ironwatch incident board. Polls /board/api/state and redraws when anything changes.
// All data is inserted with textContent, never as HTML.

(function () {
  var POLL_MS = 3000;
  var SEV_ORDER = { P1: 0, P2: 1, P3: 2, P4: 3 };
  var OPEN = ["new", "triaged", "in_progress", "escalated"];
  var CATEGORY = {
    ransomware: "Ransomware", phishing: "Phishing", account_compromise: "Account compromise",
    malware: "Malware", data_breach: "Data breach", ddos: "DDoS attack", lost_device: "Lost device", other: "Other",
  };
  var STATUS = {
    new: "New", triaged: "Triaged", in_progress: "In progress", escalated: "Escalated", resolved: "Resolved", closed: "Closed",
  };
  var REASON = {
    new_incident: "New incident", existing_ticket: "Existing ticket", failed_verification: "Failed verification", other: "Other",
  };

  var state = { version: -1, tickets: [], calls: [] };
  var known = null; // ticket refs already seen; null until the first load so nothing "arrives" on page open
  var openRef = null;
  var lastOk = 0;

  var $ = function (id) { return document.getElementById(id); };
  function el(tag, attrs, children) {
    var n = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      if (k === "text") n.textContent = attrs[k];
      else if (k === "dataset") Object.assign(n.dataset, attrs[k]);
      else n.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) { if (c) n.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return n;
  }
  var fmtTime = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", timeZone: "Europe/London" });
  var fmtDate = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", timeZone: "Europe/London" });
  function when(iso) {
    if (!iso) return "Unknown";
    var d = new Date(iso);
    if (isNaN(d)) return iso; // e.g. "29/10/2026 11:15" as typed by the caller
    var today = new Date().toDateString() === d.toDateString();
    return today ? fmtTime.format(d) : fmtDate.format(d);
  }
  function signedOut() { location.href = "/board"; }

  // ---------- data ----------
  function poll() {
    fetch("/board/api/state", { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { if (r.status === 401) { signedOut(); throw new Error("signed out"); } return r.json(); })
      .then(function (data) {
        lastOk = Date.now();
        if (data.version !== state.version) {
          var fresh = [];
          if (known) data.tickets.forEach(function (t) { if (!known.has(t.ticket_ref)) fresh.push(t.ticket_ref); });
          known = new Set(data.tickets.map(function (t) { return t.ticket_ref; }));
          state = data;
          render(fresh);
          if (openRef) loadDetail(openRef, true);
        }
        setLive();
      })
      .catch(function () { setLive(); })
      .finally(function () { setTimeout(poll, POLL_MS); });
  }

  function setLive() {
    var live = $("live");
    var stale = Date.now() - lastOk > POLL_MS * 3;
    live.classList.toggle("stale", stale);
    live.textContent = lastOk ? (stale ? "Reconnecting" : "Live, checked " + fmtTime.format(new Date(lastOk))) : "Connecting";
  }

  // ---------- render ----------
  function render(fresh) {
    renderRail();
    renderStrips(fresh || []);
    renderCalls();
  }

  function renderRail() {
    var rail = $("rail");
    rail.replaceChildren();
    ["P1", "P2", "P3", "P4"].forEach(function (s) {
      var n = state.tickets.filter(function (t) { return t.severity === s && OPEN.indexOf(t.status) !== -1; }).length;
      rail.appendChild(el("div", { class: "rail-cell" + (n ? "" : " zero"), dataset: { sev: s } }, [
        el("b", { text: String(n) }),
        el("span", { text: "open at priority " + s.slice(1) }),
      ]));
    });
  }

  function renderStrips(fresh) {
    var list = $("strips");
    var showAll = $("filter").value === "all";
    var rows = state.tickets
      .filter(function (t) { return showAll || OPEN.indexOf(t.status) !== -1; })
      .sort(function (a, b) {
        var aOpen = OPEN.indexOf(a.status) !== -1, bOpen = OPEN.indexOf(b.status) !== -1;
        if (aOpen !== bOpen) return aOpen ? -1 : 1;
        if (SEV_ORDER[a.severity] !== SEV_ORDER[b.severity]) return SEV_ORDER[a.severity] - SEV_ORDER[b.severity];
        return b.created_at.localeCompare(a.created_at);
      });
    list.replaceChildren();
    if (!rows.length) {
      list.appendChild(el("li", { class: "empty", text: showAll
        ? "No tickets yet. When Aggie raises one during a call, it appears here within a few seconds."
        : "No open tickets. Choose All tickets to see resolved ones." }));
      return;
    }
    rows.forEach(function (t) {
      var closed = OPEN.indexOf(t.status) === -1;
      var btn = el("button", {
        class: "strip" + (closed ? " closed" : "") + (fresh.indexOf(t.ticket_ref) !== -1 ? " arrived" : ""),
        type: "button",
        dataset: { sev: t.severity, ref: t.ticket_ref },
        "aria-label": "Open " + t.ticket_ref + ", priority " + t.severity.slice(1) + ", " + (CATEGORY[t.category] || t.category),
      }, [
        el("span", { class: "sev", text: t.severity }),
        el("span", { class: "ref", text: t.ticket_ref }),
        el("span", { class: "what" }, [
          el("b", { text: CATEGORY[t.category] || t.category }),
          el("small", { text: t.affected_system + (t.linked_incident_ref ? ", linked to " + t.linked_incident_ref : "") }),
        ]),
        el("span", { class: "who" }, [
          el("b", { text: t.caller_name }),
          el("small", { text: t.organisation || "Organisation unknown" }),
        ]),
        el("span", { class: "status", dataset: { status: t.status }, text: STATUS[t.status] || t.status }),
        el("span", { class: "time", text: when(t.created_at) }),
      ]);
      btn.addEventListener("click", function () { openDrawer(t.ticket_ref, t.severity); });
      list.appendChild(el("li", null, [btn]));
    });
  }

  function renderCalls() {
    var box = $("calls");
    box.replaceChildren();
    if (!state.calls.length) {
      box.appendChild(el("p", { class: "empty", text: "No calls logged yet. Each call Aggie handles appears here when she hands over." }));
      return;
    }
    var tbody = el("tbody");
    state.calls.forEach(function (c) {
      var refCell = el("td");
      if (c.ticket_ref) {
        var b = el("button", { class: "linkish", type: "button", text: c.ticket_ref });
        b.addEventListener("click", function () { openDrawer(c.ticket_ref); });
        refCell.appendChild(b);
      } else refCell.textContent = "None";
      tbody.appendChild(el("tr", null, [
        el("td", { text: when(c.logged_at) }),
        el("td", null, [el("b", { text: c.caller_name || "Unknown caller" }), el("br"), el("span", { text: c.organisation || "" })]),
        el("td", null, [el("span", { class: "verif", dataset: { v: c.verification_status }, text: c.verification_status })]),
        el("td", { text: REASON[c.call_reason] || c.call_reason }),
        refCell,
        el("td", { class: "sum", text: c.summary + (c.notes ? " Note: " + c.notes : "") }),
      ]));
    });
    box.appendChild(el("table", { class: "calls" }, [
      el("thead", null, [el("tr", null, ["Time", "Caller", "Verification", "Reason", "Ticket", "Summary"].map(function (h) { return el("th", { scope: "col", text: h }); }))]),
      tbody,
    ]));
  }

  // ---------- detail drawer ----------
  var lastFocus = null;
  function openDrawer(ref, sev) {
    openRef = ref;
    lastFocus = document.activeElement;
    var root = $("drawer-root");
    root.replaceChildren();
    var scrim = el("div", { class: "scrim" });
    scrim.addEventListener("click", closeDrawer);
    var drawer = el("aside", { class: "drawer", role: "dialog", "aria-modal": "true", "aria-labelledby": "d-title", dataset: { sev: sev || "P4" } }, [
      el("div", { class: "drawer-head" }, [
        el("div", null, [el("h2", { id: "d-title", text: ref }), el("p", { class: "sub", id: "d-sub", text: "Loading" })]),
        el("button", { class: "close", type: "button", id: "d-close", text: "Close" }),
      ]),
      el("div", { id: "d-body" }),
      buildUpdateForm(ref),
    ]);
    root.append(scrim, drawer);
    $("d-close").addEventListener("click", closeDrawer);
    $("d-close").focus();
    loadDetail(ref, false);
  }

  function closeDrawer() {
    openRef = null;
    $("drawer-root").replaceChildren();
    if (lastFocus) lastFocus.focus();
  }
  document.addEventListener("keydown", function (e) { if (e.key === "Escape" && openRef) closeDrawer(); });

  function loadDetail(ref, quiet) {
    fetch("/board/api/tickets/" + encodeURIComponent(ref), { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { if (r.status === 401) { signedOut(); throw new Error("signed out"); } return r.json(); })
      .then(function (d) { if (openRef === ref && d.ticket) renderDetail(d.ticket, d.calls || []); })
      .catch(function () { if (!quiet && $("d-sub")) $("d-sub").textContent = "Couldn't load this ticket. Close it and try again."; });
  }

  function renderDetail(t, calls) {
    var drawer = document.querySelector(".drawer");
    if (!drawer) return;
    drawer.dataset.sev = t.severity;
    $("d-sub").textContent = "Priority " + t.severity.slice(1) + ", " + (CATEGORY[t.category] || t.category) + ", " + (STATUS[t.status] || t.status);
    var sel = $("u-status");
    if (sel && !sel.dataset.touched) sel.value = t.status;

    var facts = [
      ["Caller", t.caller_name],
      ["Organisation", t.organisation || "Unknown"],
      ["Phone", t.caller_phone || "Unknown"],
      ["Affected system", t.affected_system],
      ["Discovered", t.time_detected ? when(t.time_detected) : "Unknown"],
      ["Assigned to", t.assigned_team],
      ["Known incident", t.linked_incident_ref || "None"],
      ["Raised", when(t.created_at)],
    ];
    var dl = el("dl", { class: "facts" });
    facts.forEach(function (f) { dl.append(el("dt", { text: f[0] }), el("dd", { text: f[1] })); });

    var body = $("d-body");
    body.replaceChildren(
      dl,
      el("h3", { text: "What happened" }),
      el("p", { text: t.description }),
      el("h3", { text: "Caller's actions so far" }),
      el("p", { text: t.containment_actions_taken && t.containment_actions_taken.length ? t.containment_actions_taken.join("; ") : "None reported" })
    );

    if (calls.length) {
      body.append(el("h3", { text: "Calls about this ticket" }));
      calls.forEach(function (c) {
        body.append(el("p", null, [
          el("b", { text: when(c.logged_at) + ", " + (c.verification_status || "") + ". " }),
          c.summary + (c.advice_given ? " Advice given: " + c.advice_given + "." : "") + (c.notes ? " Note: " + c.notes : ""),
        ]));
      });
    }

    body.append(el("h3", { text: "Timeline" }));
    var tl = el("ol", { class: "timeline" });
    tl.append(el("li", { class: "tl-status" }, [el("time", { text: when(t.created_at) }), "Ticket raised"]));
    (t.notes || []).forEach(function (n) {
      tl.append(el("li", { class: n.kind === "status" ? "tl-status" : "" }, [el("time", { text: when(n.at) + ", " + n.author }), n.text]));
    });
    body.append(tl);
  }

  function buildUpdateForm(ref) {
    var sel = el("select", { id: "u-status" }, Object.keys(STATUS).map(function (k) { return el("option", { value: k, text: STATUS[k] }); }));
    sel.addEventListener("change", function () { sel.dataset.touched = "1"; });
    var note = el("textarea", { id: "u-note", placeholder: "What you've done or found out" });
    var msg = el("p", { class: "msg", id: "u-msg", role: "status" });
    var save = el("button", { class: "save", type: "submit", text: "Save update" });
    var form = el("form", { class: "update" }, [
      el("h3", { text: "Update this ticket" }),
      el("label", { for: "u-status", text: "Status" }), sel,
      el("label", { for: "u-note", text: "Note (optional)" }), note,
      save, msg,
    ]);
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var payload = {};
      if (sel.dataset.touched) payload.status = sel.value;
      if (note.value.trim()) payload.note = note.value.trim();
      if (!payload.status && !payload.note) { msg.className = "msg err"; msg.textContent = "Choose a new status or write a note first."; return; }
      save.disabled = true; msg.className = "msg"; msg.textContent = "Saving";
      fetch("/board/api/tickets/" + encodeURIComponent(ref), {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-Board-Request": "1" },
        body: JSON.stringify(payload),
      })
        .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
        .then(function (res) {
          if (!res.ok) throw new Error(res.d.message || "Couldn't save the update.");
          note.value = ""; delete sel.dataset.touched;
          msg.textContent = "Update saved";
          loadDetail(ref, true);
        })
        .catch(function (err) { msg.className = "msg err"; msg.textContent = err.message + " Try again."; })
        .finally(function () { save.disabled = false; });
    });
    return form;
  }

  // ---------- tabs and filter ----------
  function showTab(which) {
    ["tickets", "calls"].forEach(function (k) {
      $("tab-" + k).setAttribute("aria-selected", String(k === which));
      $("view-" + k).hidden = k !== which;
    });
  }
  $("tab-tickets").addEventListener("click", function () { showTab("tickets"); });
  $("tab-calls").addEventListener("click", function () { showTab("calls"); });
  $("filter").addEventListener("change", function () { renderStrips([]); });

  setInterval(setLive, 1000);
  poll();
})();
