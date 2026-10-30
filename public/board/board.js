"use strict";
// Ironwatch incident desk. Hash-routed single page; polls /board/api/state every
// few seconds and redraws the current view when anything changes.
// All server data is inserted with textContent, never as HTML.

(function () {
  var POLL_MS = 3000;
  var TARGET_MIN = { P1: 15, P2: 60, P3: 240, P4: 480 }; // response targets by priority
  var SEV_ORDER = { P1: 0, P2: 1, P3: 2, P4: 3 };
  var OPEN = ["new", "triaged", "in_progress", "escalated"];
  var CATEGORY = {
    ransomware: "Ransomware", phishing: "Phishing", account_compromise: "Account compromise",
    malware: "Malware", data_breach: "Data breach", ddos: "DDoS attack", lost_device: "Lost device", other: "Other incident",
  };
  var STATUS = { new: "New", triaged: "Triaged", in_progress: "In progress", escalated: "Escalated", resolved: "Resolved", closed: "Closed" };
  var REASON = { new_incident: "Reported a new incident", existing_ticket: "Asked about a ticket", failed_verification: "Failed verification", other: "General enquiry" };
  var INCIDENT_STATUS = { investigating: "Investigating", identified: "Identified", monitoring: "Monitoring", resolved: "Resolved" };

  var state = null;
  var known = null; // ticket refs already seen, so only genuinely new ones raise an alert
  var lastOk = 0;
  var filters = { q: "", sev: { P1: false, P2: false, P3: false, P4: false }, status: "open" };
  var callFilter = "all";
  var mountedView = null;

  // ---------- helpers ----------
  var $ = function (id) { return document.getElementById(id); };
  function el(tag, attrs, children) {
    var n = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (k === "text") n.textContent = v;
      else if (k === "dataset") Object.assign(n.dataset, v);
      else if (k.slice(0, 2) === "on") n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? "" : v);
    });
    (children || []).forEach(function (c) { if (c !== null && c !== undefined && c !== false) n.append(c); });
    return n;
  }
  function icon(name, cls) {
    var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "ico" + (cls ? " " + cls : ""));
    svg.setAttribute("aria-hidden", "true");
    var use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", "#" + name);
    svg.appendChild(use);
    return svg;
  }
  var tz = "Europe/London";
  var fmtTime = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", timeZone: tz });
  var fmtDay = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", timeZone: tz });
  function when(iso) {
    if (!iso) return "Unknown";
    var d = new Date(iso);
    if (isNaN(d)) return iso; // free text such as "29/10/2026 11:15"
    return new Date().toDateString() === d.toDateString() ? fmtTime.format(d) : fmtDay.format(d) + ", " + fmtTime.format(d);
  }
  function dur(ms) {
    var m = Math.max(0, Math.round(ms / 60000));
    if (m < 60) return m + " min";
    var h = Math.floor(m / 60);
    if (h < 48) return m % 60 ? h + "h " + (m % 60) + "m" : h + "h";
    return Math.floor(h / 24) + " days";
  }
  function isOpen(t) { return OPEN.indexOf(t.status) !== -1; }
  function isWaiting(t) { return isOpen(t) && !t.first_response_at; }
  function title(t) { return (CATEGORY[t.category] || t.category) + " on " + t.affected_system; }
  function sevBadge(sev) { return el("span", { class: "pri", dataset: { sev: sev }, text: sev, "aria-label": "Priority " + sev.slice(1) }); }
  function stateBadge(s) { return el("span", { class: "state", dataset: { status: s }, text: STATUS[s] || s }); }
  function verifBadge(v) {
    if (!v) return el("span", { class: "verif muted", text: "No call log" });
    var ico = v === "Verified" ? "i-shield-ok" : v === "Failed" ? "i-shield-x" : "i-shield-q";
    return el("span", { class: "verif", dataset: { v: v } }, [icon(ico), v]);
  }
  function clock(t) {
    var target = (TARGET_MIN[t.severity] || 480) * 60000;
    var start = new Date(t.created_at).getTime();
    var end = t.first_response_at ? new Date(t.first_response_at).getTime() : Date.now();
    var elapsed = end - start, ratio = elapsed / target;
    var cls = "clock", text;
    if (t.first_response_at && ratio > 1) { cls += " done late"; text = "Responded in " + dur(elapsed) + ", " + dur(elapsed - target) + " over target"; ratio = 1; }
    else if (t.first_response_at) { cls += " done"; text = "Responded in " + dur(elapsed); }
    else if (!isOpen(t)) { cls += " done"; text = "Closed without a note"; ratio = 1; }
    else if (ratio >= 1) { cls += " breach"; text = "Over target by " + dur(elapsed - target); }
    else if (elapsed < 60000) { text = "Just raised, target " + dur(target); }
    else { if (ratio >= 0.75) cls += " warn"; text = "Waiting " + dur(elapsed) + " of " + dur(target); }
    return el("div", { class: cls, title: "Response target for " + t.severity + ": " + dur(target) }, [
      el("span", { class: "clock-text" }, [icon("i-clock"), text]),
      el("span", { class: "clock-bar" }, [el("i", { style: "width:" + Math.min(100, Math.round(ratio * 100)) + "%" })]),
    ]);
  }
  function signedOut() { location.href = "/board"; }
  function myName() { try { return localStorage.getItem("iw_name") || ""; } catch (e) { return ""; } }
  function api(path, opts) {
    opts = Object.assign({ credentials: "same-origin", cache: "no-store" }, opts || {});
    var name = myName();
    if (name) opts.headers = Object.assign({}, opts.headers || {}, { "X-Board-Name": name });
    return fetch(path, opts).then(function (r) {
      if (r.status === 401) { signedOut(); throw new Error("Signed out"); }
      return r.json().then(function (d) { if (!r.ok) throw new Error(d.message || "Something went wrong."); return d; });
    });
  }

  // ---------- polling ----------
  var pollTimer = null, inFlight = false, again = false;
  function poll() {
    if (inFlight) { again = true; return; }
    inFlight = true;
    clearTimeout(pollTimer);
    api("/board/api/state")
      .then(function (data) {
        lastOk = Date.now();
        var changed = !state || data.version !== state.version;
        var fresh = [];
        if (known) data.tickets.forEach(function (t) { if (!known.has(t.ticket_ref)) fresh.push(t); });
        known = new Set(data.tickets.map(function (t) { return t.ticket_ref; }));
        state = data;
        renderChrome();
        if (changed) route(false, fresh.map(function (t) { return t.ticket_ref; }));
        fresh.forEach(toast);
      })
      .catch(function () {})
      .finally(function () {
        inFlight = false;
        setLive();
        if (again) { again = false; poll(); } else pollTimer = setTimeout(poll, POLL_MS);
      });
  }

  function setLive() {
    var offline = !lastOk || Date.now() - lastOk > POLL_MS * 3;
    document.querySelector(".app").classList.toggle("offline", offline);
    $("live-text").textContent = !lastOk ? "Connecting" : offline ? "Reconnecting" : "Watching live, checked " + fmtTime.format(new Date(lastOk));
  }

  function renderChrome() {
    var open = state.tickets.filter(isOpen);
    var waiting = open.filter(isWaiting);
    var setCount = function (id, n, hot) { var c = $(id); c.textContent = n ? String(n) : ""; c.classList.toggle("hot", !!hot); };
    setCount("n-waiting", waiting.length, waiting.some(function (t) { return t.severity === "P1"; }));
    setCount("n-open", open.length);
    setCount("n-calls", state.calls.length);
    setCount("n-incidents", state.incidents.filter(function (i) { return i.status !== "resolved"; }).length);
    if (state.password_required) {
      $("who").textContent = "Signed in as " + state.signed_in_as;
      if (state.session_expires) $("session").textContent = "Secure session until " + fmtTime.format(new Date(state.session_expires));
    } else {
      $("who").replaceChildren("Working as " + (myName() || "Incident handler") + " ", el("button", { class: "linkish-dark", type: "button", text: "Change", onclick: askName }));
      $("session").textContent = "Demo desk, no sign-in";
      var so = document.querySelector(".side-foot form");
      if (so) so.hidden = true;
    }
  }

  function askName() {
    var n = window.prompt("Your name, shown on notes you add:", myName());
    if (n === null) return;
    try { localStorage.setItem("iw_name", n.trim().slice(0, 40)); } catch (e) {}
    renderChrome();
  }

  // ---------- alerts ----------
  function toast(t) {
    var box = el("div", { class: "toast", dataset: { sev: t.severity }, role: "status" }, [
      sevBadge(t.severity),
      el("p", null, [el("b", { text: "New ticket from Aggie" }), t.ticket_ref + ": " + title(t) + ", " + t.caller_name]),
      el("a", { class: "btn", href: "#/tickets/" + encodeURIComponent(t.ticket_ref), text: "Open", onclick: function () { box.remove(); } }),
    ]);
    $("toasts").append(box);
    setTimeout(function () { box.remove(); }, 15000);
    var app = document.querySelector(".app");
    app.classList.remove("alert"); void app.offsetWidth; app.classList.add("alert");
    setTimeout(function () { app.classList.remove("alert"); }, 3000);
  }

  // ---------- routing ----------
  function parse() {
    var h = location.hash.replace(/^#\/?/, "");
    var parts = h.split("/");
    return { view: parts[0] || "overview", arg: parts[1] ? decodeURIComponent(parts[1]) : null };
  }
  function route(navigated, fresh) {
    if (!state) return;
    var r = parse();
    var navKey = r.view === "tickets" ? "tickets" : r.view;
    document.querySelectorAll("[data-nav]").forEach(function (a) {
      if (a.dataset.nav === navKey) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
    });
    var titles = { overview: "Overview", tickets: r.arg ? r.arg : "Tickets", calls: "Calls", incidents: "Known incidents" };
    var t = titles[r.view] || "Overview";
    $("page-title").textContent = t;
    document.title = t + ", Ironwatch incident desk";

    if (r.view === "tickets" && r.arg) renderTicket(r.arg, navigated);
    else if (r.view === "tickets") renderQueue(navigated, fresh || []);
    else if (r.view === "calls") renderCalls();
    else if (r.view === "incidents") renderIncidents();
    else renderOverview(fresh || []);
    if (navigated) { $("view").focus({ preventScroll: true }); window.scrollTo(0, 0); }
  }
  window.addEventListener("hashchange", function () { route(true); });

  function mount(key, nodes) {
    mountedView = key;
    $("view").replaceChildren.apply($("view"), nodes);
  }

  // ---------- overview ----------
  function renderOverview(fresh) {
    var open = state.tickets.filter(isOpen);
    var waiting = open.filter(isWaiting).sort(function (a, b) {
      return SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.created_at.localeCompare(b.created_at);
    });

    var verdict, sub;
    if (waiting.length) {
      verdict = waiting.length === 1 ? "1 incident is waiting for a handler" : waiting.length + " incidents are waiting for a handler";
      sub = "The longest has waited " + dur(Date.now() - new Date(waiting.slice().sort(function (a, b) { return a.created_at.localeCompare(b.created_at); })[0].created_at).getTime()) + ". Highest priority first below.";
    } else if (open.length) {
      verdict = "Every open incident has a handler";
      sub = open.length + " open ticket" + (open.length === 1 ? " is" : "s are") + " being worked on.";
    } else {
      verdict = "All quiet on the watch";
      sub = "No open tickets. New ones appear here the moment Aggie raises them.";
    }

    var rail = el("div", { class: "rail" }, ["P1", "P2", "P3", "P4"].map(function (s) {
      var n = open.filter(function (t) { return t.severity === s; }).length;
      var w = open.filter(function (t) { return t.severity === s && isWaiting(t); }).length;
      return el("a", { class: "panel", href: "#/tickets", dataset: { sev: s }, onclick: function () { filters.sev = { P1: false, P2: false, P3: false, P4: false }; filters.sev[s] = true; filters.status = "open"; } }, [
        el("b", { class: n ? "" : "zero", text: String(n) }),
        el("span", { text: "Priority " + s.slice(1) }),
        el("small", null, [
          el("span", { text: n ? "open" + (w ? ", " + w + " waiting" : "") : "none open" }),
          el("span", { class: "rail-target", text: "Response target " + dur(TARGET_MIN[s] * 60000) }),
        ]),
      ]);
    }));

    var waitList = waiting.length
      ? el("ul", { class: "waiting" }, waiting.map(function (t) {
          return el("li", null, [el("a", { href: "#/tickets/" + encodeURIComponent(t.ticket_ref), class: fresh.indexOf(t.ticket_ref) !== -1 ? "arrived" : null }, [
            sevBadge(t.severity),
            el("span", null, [
              el("span", { class: "title", text: title(t) }),
              el("span", { class: "meta" }, [el("span", { class: "ref", text: t.ticket_ref }), "  ", t.caller_name + (t.organisation ? ", " + t.organisation : "")]),
            ]),
            clock(t),
          ])]);
        }))
      : el("p", { class: "empty" }, [el("b", { text: "Nothing waiting" }), "Every open ticket has at least one handler update."]);

    var feed = state.activity.length
      ? el("ol", { class: "feed" }, state.activity.slice(0, 12).map(function (e) {
          var link = e.ticket_ref ? el("a", { href: "#/tickets/" + encodeURIComponent(e.ticket_ref), class: "ref", text: e.ticket_ref }) : null;
          var verb = e.kind === "raised" ? "Raised by Aggie: " : e.kind === "status" ? "" : e.kind === "note" ? "Note: " : "";
          return el("li", { class: "kind-" + e.kind }, [
            el("time", { datetime: e.at, text: when(e.at) }),
            el("span", null, [link, link ? " " : "", verb + e.text, el("span", { class: "by", text: e.kind === "raised" ? "" : " (" + e.by + ")" })]),
          ]);
        }))
      : el("p", { class: "empty", text: "No activity yet." });

    mount("overview", [
      el("p", { class: "verdict", text: verdict }),
      el("p", { class: "verdict-sub", text: sub }),
      rail,
      el("div", { class: "split" }, [
        el("section", { class: "panel", "aria-labelledby": "h-wait" }, [
          el("div", { class: "panel-head" }, [el("h2", { id: "h-wait", text: "Waiting for a handler" }), el("a", { href: "#/tickets", class: "linkish", text: "See all tickets" })]),
          waitList,
        ]),
        el("section", { class: "panel", "aria-labelledby": "h-feed" }, [
          el("div", { class: "panel-head" }, [el("h2", { id: "h-feed", text: "Latest activity" })]),
          feed,
        ]),
      ]),
    ]);
  }

  // ---------- ticket queue ----------
  function renderQueue(navigated, fresh) {
    if (mountedView !== "tickets") {
      var q = el("input", { type: "search", placeholder: "Search reference, caller or organisation", "aria-label": "Search tickets", value: filters.q,
        oninput: function () { filters.q = q.value; drawQueue([]); } });
      var chips = el("div", { class: "chips", role: "group", "aria-label": "Filter by priority" }, ["P1", "P2", "P3", "P4"].map(function (s) {
        var b = el("button", { class: "chip", type: "button", dataset: { sev: s }, "aria-pressed": String(filters.sev[s]), text: s,
          onclick: function () { filters.sev[s] = !filters.sev[s]; b.setAttribute("aria-pressed", String(filters.sev[s])); drawQueue([]); } });
        return b;
      }));
      var sel = el("select", { "aria-label": "Filter by status", onchange: function () { filters.status = sel.value; drawQueue([]); } }, [
        el("option", { value: "open", text: "Open tickets" }),
        el("option", { value: "waiting", text: "Waiting for a handler" }),
        el("option", { value: "done", text: "Resolved and closed" }),
        el("option", { value: "all", text: "All tickets" }),
      ]);
      sel.value = filters.status;
      mount("tickets", [
        el("div", { class: "toolbar" }, [
          el("label", { class: "search" }, [icon("i-search"), q]), chips, sel, el("span", { class: "result-count", id: "result-count", "aria-live": "polite" }),
        ]),
        el("section", { class: "panel" }, [el("ul", { class: "queue", id: "queue" })]),
      ]);
    }
    drawQueue(fresh);
  }

  function drawQueue(fresh) {
    var list = $("queue");
    if (!list) return;
    var anySev = Object.keys(filters.sev).some(function (k) { return filters.sev[k]; });
    var q = filters.q.trim().toLowerCase();
    var rows = state.tickets.filter(function (t) {
      if (anySev && !filters.sev[t.severity]) return false;
      if (filters.status === "open" && !isOpen(t)) return false;
      if (filters.status === "waiting" && !isWaiting(t)) return false;
      if (filters.status === "done" && isOpen(t)) return false;
      if (q && (t.ticket_ref + " " + t.caller_name + " " + (t.organisation || "") + " " + t.affected_system + " " + t.category).toLowerCase().indexOf(q) === -1) return false;
      return true;
    }).sort(function (a, b) {
      if (isOpen(a) !== isOpen(b)) return isOpen(a) ? -1 : 1;
      return SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || b.created_at.localeCompare(a.created_at);
    });
    $("result-count").textContent = rows.length + " of " + state.tickets.length + " tickets";
    if (!rows.length) {
      list.replaceChildren(el("li", { class: "empty" }, [el("b", { text: "No tickets match" }), "Clear the search or priority filters, or choose All tickets."]));
      return;
    }
    list.replaceChildren.apply(list, rows.map(function (t) {
      return el("li", null, [el("a", {
        class: "row" + (isOpen(t) ? "" : " done") + (fresh.indexOf(t.ticket_ref) !== -1 ? " arrived" : ""),
        href: "#/tickets/" + encodeURIComponent(t.ticket_ref), dataset: { sev: t.severity, ref: t.ticket_ref },
      }, [
        el("span", { class: "col-pri" }, [sevBadge(t.severity)]),
        el("span", { class: "col-ref ref", text: t.ticket_ref }),
        el("span", { class: "col-what" }, [el("span", { class: "title", text: CATEGORY[t.category] || t.category }), el("span", { class: "sub", text: t.affected_system + (t.linked_incident_ref ? ", part of " + t.linked_incident_ref : "") })]),
        el("span", { class: "col-caller" }, [el("span", { class: "title", text: t.caller_name }), el("span", { class: "sub" }, [verifBadge(t.verification_status), " ", t.organisation || ""])]),
        el("span", { class: "col-state" }, [stateBadge(t.status)]),
        el("span", { class: "col-clock" }, [clock(t)]),
        el("span", { class: "when", text: when(t.created_at) }),
      ])]);
    }));
  }

  // ---------- ticket page ----------
  var NEXT = {
    new: [["in_progress", "Start work", true], ["escalated", "Escalate"], ["resolved", "Mark resolved"]],
    triaged: [["in_progress", "Start work", true], ["escalated", "Escalate"], ["resolved", "Mark resolved"]],
    escalated: [["in_progress", "Start work", true], ["resolved", "Mark resolved"]],
    in_progress: [["resolved", "Mark resolved", true], ["escalated", "Escalate"]],
    resolved: [["closed", "Close ticket", true], ["in_progress", "Reopen"]],
    closed: [["in_progress", "Reopen", true]],
  };

  function renderTicket(ref, navigated) {
    var keepForm = mountedView === "ticket:" + ref ? $("note-form") : null;
    if (navigated || !keepForm) mount("ticket:" + ref, [el("p", { class: "muted", text: "Loading " + ref })]);
    api("/board/api/tickets/" + encodeURIComponent(ref))
      .then(function (d) { if (parse().arg === ref) drawTicket(d, keepForm); })
      .catch(function (e) {
        mount("ticket:" + ref, [
          el("a", { class: "back", href: "#/tickets", text: "All tickets" }),
          el("p", { class: "empty panel" }, [el("b", { text: "Couldn't open " + ref }), e.message]),
        ]);
      });
  }

  function update(ref, payload, msg) {
    msg.className = "msg"; msg.textContent = "Saving";
    return api("/board/api/tickets/" + encodeURIComponent(ref), {
      method: "POST", headers: { "Content-Type": "application/json", "X-Board-Request": "1" }, body: JSON.stringify(payload),
    }).then(function () { msg.textContent = "Saved"; poll(); })
      .catch(function (e) { msg.className = "msg err"; msg.textContent = e.message + " Try again."; throw e; });
  }

  function drawTicket(d, keepForm) {
    var t = d.ticket, calls = d.calls || [], inc = d.incident;
    var call = calls[0] || null;
    var msg = el("span", { class: "msg", role: "status" });
    var actions = el("div", { class: "actions" }, (NEXT[t.status] || []).map(function (a) {
      return el("button", { class: "btn" + (a[2] ? " btn-primary" : "") + (a[0] === "escalated" ? " btn-danger" : ""), type: "button", text: a[1],
        onclick: function (ev) { ev.target.disabled = true; update(t.ticket_ref, { status: a[0] }, msg).catch(function () { ev.target.disabled = false; }); } });
    }).concat([msg]));

    var head = el("section", { class: "panel ticket-head", dataset: { sev: t.severity } }, [
      el("div", { class: "ticket-id" }, [sevBadge(t.severity), el("span", { class: "ref", text: t.ticket_ref }), stateBadge(t.status)]),
      el("h2", { text: title(t) }),
      actions,
    ]);

    var facts = el("dl", { class: "facts" });
    [["Caller", t.caller_name], ["Organisation", t.organisation || "Unknown"], ["Phone", t.caller_phone || "Unknown"],
      ["Identity check", null], ["Discovered", t.time_detected ? when(t.time_detected) : "Unknown"],
      ["Assigned team", t.assigned_team], ["Raised", when(t.created_at)]].forEach(function (f) {
      facts.append(el("dt", { text: f[0] }), el("dd", null, [f[1] === null ? verifBadge(call && call.verification_status) : f[1]]));
    });

    var left = el("div", { class: "stack" }, [
      el("section", { class: "panel" }, [el("div", { class: "panel-head" }, [el("h3", { text: "What happened" })]), el("div", { class: "panel-body" }, [
        el("p", { text: t.description }),
        el("p", { class: "muted", text: "Already done by the caller: " + (t.containment_actions_taken && t.containment_actions_taken.length ? t.containment_actions_taken.join("; ") : "nothing reported") }),
      ])]),
      inc ? el("section", { class: "panel" }, [el("div", { class: "panel-head" }, [el("h3", { text: "Part of a known incident" }), el("a", { class: "linkish", href: "#/incidents", text: inc.incident_ref })]),
        el("div", { class: "panel-body" }, [el("p", null, [el("b", { text: inc.title })]), el("p", { class: "muted", text: "Status: " + (INCIDENT_STATUS[inc.status] || inc.status) })])]) : null,
      el("section", { class: "panel" }, [el("div", { class: "panel-head" }, [el("h3", { text: "Aggie's call" })]), el("div", { class: "panel-body" },
        calls.length ? calls.map(function (c) {
          return el("div", null, [
            el("p", null, [el("b", { text: when(c.logged_at) + "  " }), verifBadge(c.verification_status)]),
            el("p", { text: c.summary }),
            c.advice_given ? el("p", { class: "callout" }, [el("b", { text: "Advice Aggie gave" }), c.advice_given]) : null,
            c.notes ? el("p", { class: "callout" }, [el("b", { text: "Flag for the handler" }), c.notes]) : null,
          ]);
        }) : [el("p", { class: "muted", text: "No call log for this ticket. It may have been raised before call logging was added." })])]),
      el("section", { class: "panel" }, [el("div", { class: "panel-head" }, [el("h3", { text: "Caller" })]), el("div", { class: "panel-body" }, [facts])]),
    ]);

    var tl = el("ol", { class: "timeline" }, [el("li", { class: "tl-raised" }, [el("time", { text: when(t.created_at) + ", Aggie" }), "Ticket raised and assigned to " + t.assigned_team])]
      .concat((t.notes || []).map(function (n) {
        return el("li", { class: n.kind === "status" ? "tl-status" : "" }, [el("time", { text: when(n.at) + ", " + n.author }), n.text]);
      })));

    var form = keepForm || (function () {
      var ta = el("textarea", { id: "note-text", placeholder: "What you've done, found out or told the client" });
      var m = el("span", { class: "msg", role: "status" });
      var b = el("button", { class: "btn btn-primary", type: "submit", text: "Add note" });
      var f = el("form", { class: "note-form", id: "note-form", onsubmit: function (e) {
        e.preventDefault();
        if (!ta.value.trim()) { m.className = "msg err"; m.textContent = "Write a note first."; ta.focus(); return; }
        b.disabled = true;
        update(t.ticket_ref, { note: ta.value.trim() }, m).then(function () { ta.value = ""; }).catch(function () {}).finally(function () { b.disabled = false; });
      } }, [el("label", { for: "note-text", class: "muted", text: "Add a note to the timeline" }), ta, el("div", { class: "row-end" }, [m, b])]);
      return f;
    })();

    var right = el("div", { class: "stack" }, [
      el("section", { class: "panel" }, [el("div", { class: "panel-head" }, [el("h3", { text: "Response clock" })]), el("div", { class: "panel-body" }, [clock(t)])]),
      el("section", { class: "panel" }, [el("div", { class: "panel-head" }, [el("h3", { text: "Timeline" })]), el("div", { class: "panel-body" }, [tl, form])]),
    ]);

    mount("ticket:" + t.ticket_ref, [
      el("a", { class: "back", href: "#/tickets", text: "All tickets" }),
      head,
      el("div", { class: "ticket-grid", dataset: { sev: t.severity } }, [left, right]),
    ]);
  }

  // ---------- calls ----------
  function renderCalls() {
    var calls = state.calls.filter(function (c) { return callFilter === "all" || c.verification_status !== "Verified"; });
    var sel = el("select", { "aria-label": "Filter calls", onchange: function () { callFilter = sel.value; renderCalls(); } }, [
      el("option", { value: "all", text: "All calls" }),
      el("option", { value: "flagged", text: "Unverified and failed checks" }),
    ]);
    sel.value = callFilter;
    var body = calls.length
      ? el("table", { class: "table" }, [
          el("thead", null, [el("tr", null, ["Time", "Caller", "Identity check", "What they wanted", "Ticket", "Aggie's summary"].map(function (h) { return el("th", { scope: "col", text: h }); }))]),
          el("tbody", null, calls.map(function (c) {
            return el("tr", null, [
              el("td", { text: when(c.logged_at) }),
              el("td", null, [el("b", { text: c.caller_name || "Unknown caller" }), el("br"), el("span", { class: "muted", text: c.organisation || "" })]),
              el("td", null, [verifBadge(c.verification_status)]),
              el("td", { text: REASON[c.call_reason] || c.call_reason }),
              el("td", null, [c.ticket_ref ? el("a", { class: "linkish ref", href: "#/tickets/" + encodeURIComponent(c.ticket_ref), text: c.ticket_ref }) : el("span", { class: "muted", text: "None" })]),
              el("td", { class: "sum" }, [c.summary, c.notes ? el("span", null, [el("br"), el("b", { text: "Flag: " }), c.notes]) : null]),
            ]);
          })),
        ])
      : el("p", { class: "empty" }, [el("b", { text: "No calls to show" }), callFilter === "all" ? "Each call Aggie handles is logged here when she hands over." : "No unverified or failed calls."]);
    mount("calls", [
      el("div", { class: "toolbar" }, [sel, el("span", { class: "result-count", text: calls.length + " of " + state.calls.length + " calls" })]),
      el("section", { class: "panel" }, [body]),
    ]);
  }

  // ---------- known incidents ----------
  function renderIncidents() {
    mount("incidents", [
      el("p", { class: "verdict-sub", text: "Incidents Ironwatch is already handling. When a caller's problem matches one, Aggie reassures them with the guidance below and links their ticket." }),
      el("div", { class: "incidents" }, state.incidents.map(function (i) {
        return el("section", { class: "panel incident" }, [
          el("div", { class: "panel-head" }, [
            el("div", null, [el("span", { class: "ref muted", text: i.incident_ref }), el("h3", { text: i.title })]),
            el("span", { class: "state", dataset: { status: i.status === "resolved" ? "resolved" : "in_progress" }, text: INCIDENT_STATUS[i.status] || i.status }),
          ]),
          el("div", { class: "panel-body" }, [
            el("p", { class: "muted", text: "Started " + when(i.started_at) }),
            el("div", { class: "tags" }, i.affected_systems.map(function (s) { return el("span", { class: "tag", text: s }); })),
            el("p", { class: "callout" }, [el("b", { text: "What Aggie tells callers" }), i.caller_guidance]),
            el("p", null, i.linked_tickets.length
              ? ["Linked tickets: "].concat(i.linked_tickets.map(function (r, n) { return el("span", null, [n ? ", " : "", el("a", { class: "linkish ref", href: "#/tickets/" + encodeURIComponent(r), text: r })]); }))
              : [el("span", { class: "muted", text: "No tickets linked yet." })]),
          ]),
        ]);
      })),
    ]);
  }

  // ---------- start ----------
  // Response clocks tick on their own, so redraw the clock views every 30 seconds.
  setInterval(function () {
    setLive();
    var v = state && parse();
    if (v && (v.view === "overview" || (v.view === "tickets" && !v.arg))) route(false, []);
  }, 30000);
  if (!location.hash) history.replaceState(null, "", "#/overview");
  poll();
})();
