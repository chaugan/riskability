/*
 * Accept a risk, from the Findings page.
 *
 * The button lives here rather than inside riskability_grid because that
 * component is on five dashboards and only this one can accept a risk. The
 * grid publishes its selection as a DOM event; this listens.
 *
 * Everything it writes goes through /services/riskability/exceptions, which is
 * gated on the riskability_accept_risk capability. It never touches the KV
 * Store directly: a collection ACL cannot express "the holder of this
 * capability", so authorising in the browser would be authorising nothing.
 */
(function () {
    "use strict";

    var SELECTION_EVENT = "riskability-grid-selection";

    // Findings selected on the Findings page.
    var selection = [];
    // Exception rows selected on the register page. Two grids there, so the
    // selection is tracked per grid: choosing a row in one must not leave a
    // stale selection arming the other one's buttons.
    var regSelection = [];
    var expSelection = [];

    function splunkRoot() {
        var path = window.location.pathname;
        var i = path.indexOf("/app/");
        return i < 0 ? "" : path.slice(0, i);
    }

    function endpoint() {
        return splunkRoot() + "/splunkd/__raw/services/riskability/exceptions";
    }

    function csrfToken() {
        var m = document.cookie.match(/splunkweb_csrf_token_\d+=([^;]+)/);
        return m ? decodeURIComponent(m[1]) : "";
    }

    function post(body) {
        return fetch(endpoint(), {
            method: "POST",
            credentials: "same-origin",
            headers: {
                "X-Splunk-Form-Key": csrfToken(),
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/json",
            },
            body: JSON.stringify(body),
        }).then(function (r) {
            return r.text().then(function (text) {
                var data;
                try { data = JSON.parse(text); } catch (e) { data = { error: text }; }
                if (!r.ok || data.error) {
                    // 403 here means the account does not hold
                    // riskability_accept_risk. Say that rather than "failed".
                    if (r.status === 403) {
                        throw new Error("Your account does not have permission to accept " +
                                        "risks. This needs the riskability_accept_risk " +
                                        "capability.");
                    }
                    throw new Error(data.error || ("HTTP " + r.status));
                }
                return data;
            });
        });
    }

    function el(tag, cls, text) {
        var e = document.createElement(tag);
        if (cls) { e.className = cls; }
        if (text !== undefined) { e.textContent = text; }
        return e;
    }

    /* Distinct values of one column across the selection. */
    function distinct(rows, field) {
        var seen = {}, out = [];
        rows.forEach(function (r) {
            var v = r[field];
            if (v === undefined || v === null || v === "") { return; }
            if (!(v in seen)) { seen[v] = true; out.push(v); }
        });
        return out;
    }

    // ---- selection state ---------------------------------------------------

    function summarise() {
        var summary = document.getElementById("rk-exc-summary");
        var button = document.getElementById("rk-exc-accept");
        if (!summary || !button) { return; }

        if (!selection.length) {
            summary.textContent = "";
            summary.className = "rk-exc-summary";
            button.disabled = true;
            return;
        }

        var cves = distinct(selection, "CVE");
        var hosts = distinct(selection, "Host");

        if (cves.length > 1) {
            // Refused rather than silently split into several exceptions. One
            // justification covering several unrelated vulnerabilities is how
            // a pile of things gets accepted that nobody actually assessed.
            summary.textContent = selection.length + " rows selected across " + cves.length +
                " different CVEs. Narrow it to one CVE — a single justification cannot " +
                "honestly cover several vulnerabilities.";
            summary.className = "rk-exc-summary rk-exc-bad";
            button.disabled = true;
            return;
        }

        summary.textContent = selection.length + " finding" + (selection.length === 1 ? "" : "s") +
            " · " + cves[0] + " · " + hosts.length + " host" +
            (hosts.length === 1 ? "" : "s");
        summary.className = "rk-exc-summary rk-exc-ok";
        button.disabled = false;
    }

    function summariseRegister(rows, summaryId, buttonIds, verb) {
        var summary = document.getElementById(summaryId);
        if (!summary) { return; }
        var ok = rows.length === 1;
        summary.textContent = !rows.length ? ""
            : (ok ? rows[0].CVE + " · " + (rows[0]["Applies to"] || "")
                  : rows.length + " selected — " + verb + " one at a time, so each keeps its own justification.");
        summary.className = "rk-exc-summary " + (ok ? "rk-exc-ok" : (rows.length ? "rk-exc-bad" : ""));
        buttonIds.forEach(function (id) {
            var b = document.getElementById(id);
            if (b) { b.disabled = !ok; }
        });
    }

    document.addEventListener(SELECTION_EVENT, function (e) {
        var detail = e.detail || {};
        var rows = detail.rows || [];
        // Attribute the event by its COLUMNS, not by its rows. An empty
        // selection carries no rows to inspect, and that is exactly the case
        // that has to be handled: deselecting the last row is what clears the
        // buttons. Identifying the grid from row contents meant an empty
        // selection could not be attributed at all, so nothing was cleared and
        // the toolbar kept offering to edit a row that was no longer selected.
        var columns = detail.columns || (rows.length ? Object.keys(rows[0]) : []);
        var onRegisterPage = !!document.getElementById("rk-exc-reg-toolbar");

        if (!onRegisterPage) {
            selection = rows;
            summarise();
            return;
        }
        if (columns.indexOf("Applies to") === -1) { return; }
        if (columns.indexOf("State") !== -1) {
            expSelection = rows;
            summariseRegister(rows, "rk-exc-exp-summary", ["rk-exc-exp-reaccept"], "re-accept");
        } else {
            regSelection = rows;
            summariseRegister(rows, "rk-exc-reg-summary",
                              ["rk-exc-reg-edit", "rk-exc-reg-revoke"], "edit");
        }
    });

    // ---- the dialog --------------------------------------------------------

    function closeDialog() {
        var d = document.getElementById("rk-exc-dialog");
        if (d && d.parentNode) { d.parentNode.removeChild(d); }
    }

    function field(parent, labelText, control, help) {
        var wrap = el("div", "rk-exc-field");
        var label = el("label", null, labelText);
        wrap.appendChild(label);
        wrap.appendChild(control);
        if (help) { wrap.appendChild(el("div", "rk-exc-help", help)); }
        parent.appendChild(wrap);
        return control;
    }

    /* mode: "create" from Findings, or "edit"/"reactivate" from the register. */
    function openDialog(mode, existing) {
        closeDialog();
        mode = mode || "create";
        var editing = mode !== "create";
        var cve = editing ? existing.CVE : distinct(selection, "CVE")[0];
        var hosts = editing ? [] : distinct(selection, "Host");
        var kev = !editing && selection.some(function (r) {
            return String(r.KEV || "").toLowerCase() === "yes";
        });

        var overlay = el("div", "rk-exc-overlay");
        overlay.id = "rk-exc-dialog";
        var box = el("div", "rk-exc-dialog");

        box.appendChild(el("h3", null,
            (mode === "create" ? "Accept risk — " :
             mode === "reactivate" ? "Re-accept — " : "Edit exception — ") + cve));

        if (editing) {
            var ctx = el("div", "rk-exc-help");
            ctx.style.marginBottom = "12px";
            ctx.textContent = "Applies to " + (existing["Applies to"] || "") +
                ". Created by " + (existing.By || "unknown") + ". Editing keeps one record " +
                "for this decision; the change is recorded in the audit trail.";
            box.appendChild(ctx);
        }

        if (kev) {
            // Allowed, but never by accident. A KEV finding is one CISA says is
            // being exploited right now, and accepting it also stops the KEV
            // alert paging anyone.
            var warn = el("div", "rk-exc-warn");
            warn.appendChild(el("b", null, "This is on the CISA known-exploited list."));
            warn.appendChild(el("span", null,
                " It is being exploited in the wild. Accepting it removes it from the KEV " +
                "panel and stops the known-exploited alert firing for it. That may be exactly " +
                "what you intend; it should not be a surprise."));
            box.appendChild(warn);
        }

        var scopeSel = el("select", "rk-exc-input");
        if (editing) { scopeSel.disabled = true; }
        var scopeOpts = [
            ["finding", "Only the " + selection.length + " selected finding" +
                        (selection.length === 1 ? "" : "s") + " — this exact path"],
            ["host_cve", "This CVE on " +
                         (hosts.length === 1 ? hosts[0] : hosts.length + " selected hosts") +
                         " — every path"],
            ["fleet_cve", "This CVE on EVERY host, including ones added later"],
        ];
        scopeOpts.forEach(function (o) {
            var opt = el("option", null, o[1]);
            opt.value = o[0];
            scopeSel.appendChild(opt);
        });

        // What each choice would really cover, asked of the server rather than
        // guessed from the rows the grid happens to have loaded.
        var scopeNote = el("div", "rk-exc-scopewarn");
        if (!editing) {
            post({
                action: "preview",
                cve_id: cve,
                hostnames: hosts,
                finding_keys: selection.map(function (r) { return r.Key; }),
            }).then(function (c) {
                scopeSel.options[0].textContent =
                    "Only the selected finding" + (c.finding === 1 ? "" : "s") +
                    " — this exact path (" + c.finding + ")";
                scopeSel.options[1].textContent =
                    "This CVE on " + (hosts.length === 1 ? hosts[0] : hosts.length + " hosts") +
                    " — every path (" + c.host_cve + ")";
                scopeSel.options[2].textContent =
                    "This CVE on EVERY host, now and in future (" + c.fleet_cve +
                    " across " + c.fleet_hosts + " host" + (c.fleet_hosts === 1 ? "" : "s") + ")";

                if (c.host_cve > c.finding) {
                    // The common case, not an edge case: the same CVE usually
                    // appears at several paths on one host, and one copy being
                    // unreachable says nothing about the others.
                    scopeNote.textContent =
                        "This CVE appears " + c.host_cve + " times on " +
                        (hosts.length === 1 ? "this host" : "these hosts") + ", at different " +
                        "paths. You selected " + c.finding + ". Accepting it host-wide also " +
                        "accepts the " + (c.host_cve - c.finding) + " you did not look at — " +
                        "a copy inside an unused container base says nothing about the copy " +
                        "the service actually loads.";
                    scopeNote.className = "rk-exc-scopewarn rk-exc-scopewarn-on";
                    scopeSel.value = "finding";
                }
            }).catch(function () {
                scopeNote.textContent = "Could not check how many findings each choice covers.";
                scopeNote.className = "rk-exc-scopewarn rk-exc-scopewarn-on";
            });
        }
        if (editing) {
            var fixed = el("option", null, existing["Applies to"] || existing.Scope || "");
            fixed.value = existing.Scope || "host_cve";
            scopeSel.innerHTML = "";
            scopeSel.appendChild(fixed);
        }
        box.appendChild(scopeNote);
        field(box, "What is being accepted", scopeSel,
              editing
                ? "Fixed. Changing what an exception covers is a different decision — withdraw " +
                  "this one and accept the new scope, so the trail shows both."
                : "Per-path is the safe default when a CVE appears more than once on a host: " +
                  "each copy is judged on its own. Host-wide is fewer entries and survives a " +
                  "rebuild that moves the package, but it accepts every copy — including ones " +
                  "you have not looked at.");

        var reasonSel = el("select", "rk-exc-input");
        [["compensating_control", "A compensating control is in place"],
         ["risk_accepted", "Risk accepted without further control"],
         ["false_positive", "We believe the finding is wrong"]
        ].forEach(function (o) {
            var opt = el("option", null, o[1]);
            opt.value = o[0];
            reasonSel.appendChild(opt);
        });
        field(box, "Why", reasonSel,
              "If most entries end up as “the finding is wrong”, that is a matcher " +
              "problem worth reporting rather than a register of accepted risk.");

        var control = el("textarea", "rk-exc-input rk-exc-area");
        control.rows = 3;
        if (editing) { control.value = existing["Control in place"] || ""; }
        control.placeholder = "e.g. Host is on an isolated VLAN with no inbound 443, and the " +
                              "service is not reachable from user networks.";
        field(box, "What is in place instead (required)", control,
              "Written down because in six months nobody remembers, and an auditor will ask.");

        var expiry = el("input", "rk-exc-input");
        expiry.type = "datetime-local";
        var d = new Date(Date.now() + 90 * 86400000);
        expiry.value = new Date(d.getTime() - d.getTimezoneOffset() * 60000)
            .toISOString().slice(0, 16);
        field(box, "Review by", expiry,
              "Defaults to 90 days. After this the finding returns to the pool automatically, " +
              "and you can re-accept it from the Risk exceptions page. Clear the field to make " +
              "it permanent.");

        var notes = el("textarea", "rk-exc-input rk-exc-area");
        notes.rows = 2;
        if (editing) { notes.value = existing.Notes || ""; }
        notes.placeholder = "Ticket reference, who agreed it, anything else worth keeping.";
        field(box, "Notes", notes);

        var msg = el("div", "rk-exc-msg");
        box.appendChild(msg);

        var actions = el("div", "rk-exc-actions");
        var cancel = el("button", "rk-exc-btn", "Cancel");
        cancel.type = "button";
        cancel.addEventListener("click", closeDialog);
        var submit = el("button", "rk-exc-btn rk-exc-btn-primary",
            mode === "create" ? "Accept risk" : mode === "reactivate" ? "Re-accept" : "Save changes");
        submit.type = "button";
        actions.appendChild(cancel);
        actions.appendChild(submit);
        box.appendChild(actions);

        submit.addEventListener("click", function () {
            if (!control.value.trim()) {
                msg.textContent = "Say what is in place instead. An entry with no justification " +
                                  "is indistinguishable from hiding the number.";
                msg.className = "rk-exc-msg rk-exc-bad";
                return;
            }
            submit.disabled = true;
            msg.textContent = "Saving…";
            msg.className = "rk-exc-msg";

            var scope = scopeSel.value;
            var expires = expiry.value
                ? Math.floor(new Date(expiry.value).getTime() / 1000)
                : null;

            if (editing) {
                // One record per decision. Editing and re-accepting both update
                // the row that already exists, so the history of a decision
                // stays on one line rather than becoming a pile of near
                // duplicates nobody can follow.
                post({
                    action: mode === "reactivate" ? "reactivate" : "update",
                    exception_key: existing.Key,
                    // scope_kind, cve_id, hostname and finding_key are not sent:
                    // the endpoint takes them from the stored record, so what an
                    // exception covers cannot be changed by an edit.
                    reason_kind: reasonSel.value,
                    control: control.value.trim(),
                    notes: notes.value.trim(),
                    expires_at: expires,
                }).then(function (r) {
                    msg.textContent = mode === "reactivate"
                        ? "Back in force. It covers " + r.findings_affected +
                          " finding" + (r.findings_affected === 1 ? "" : "s") +
                          "; they leave the risk numbers within the hour."
                        : "Saved. The change is in the audit trail below.";
                    msg.className = "rk-exc-msg rk-exc-ok";
                    submit.disabled = true;
                    setTimeout(function () { closeDialog(); window.location.reload(); }, 2500);
                }).catch(function (err) {
                    msg.textContent = String(err.message || err);
                    msg.className = "rk-exc-msg rk-exc-bad";
                    submit.disabled = false;
                });
                return;
            }

            // One request per rule. A host-scoped accept over several hosts is
            // several rules with the same justification, not one rule that
            // quietly means "all of them".
            var targets;
            if (scope === "fleet_cve") {
                targets = [{ scope_kind: "fleet_cve" }];
            } else if (scope === "finding") {
                targets = selection.map(function (r) {
                    return { scope_kind: "finding", hostname: r.Host, finding_key: r.Key };
                });
            } else {
                targets = hosts.map(function (h) {
                    return { scope_kind: "host_cve", hostname: h };
                });
            }

            var payloads = targets.map(function (t) {
                return Object.assign({
                    action: "create",
                    cve_id: cve,
                    reason_kind: reasonSel.value,
                    control: control.value.trim(),
                    notes: notes.value.trim(),
                    expires_at: expires,
                }, t);
            });

            Promise.all(payloads.map(post)).then(function (results) {
                var covered = results.reduce(function (a, r) {
                    return a + (r.findings_affected || 0);
                }, 0);
                msg.textContent = "Accepted. " + results.length + " entr" +
                    (results.length === 1 ? "y" : "ies") + " recorded, covering " + covered +
                    " finding" + (covered === 1 ? "" : "s") +
                    ". They disappear from the risk numbers within the hour, once the " +
                    "reconciler runs.";
                msg.className = "rk-exc-msg rk-exc-ok";
                submit.disabled = true;
                setTimeout(closeDialog, 4000);
            }).catch(function (err) {
                msg.textContent = String(err.message || err);
                msg.className = "rk-exc-msg rk-exc-bad";
                submit.disabled = false;
            });
        });

        overlay.appendChild(box);
        overlay.addEventListener("click", function (e) {
            if (e.target === overlay) { closeDialog(); }
        });
        document.body.appendChild(overlay);
        control.focus();
    }

    function confirmRevoke() {
        var row = regSelection[0];
        if (!row) { return; }
        var overlay = el("div", "rk-exc-overlay");
        overlay.id = "rk-exc-dialog";
        var box = el("div", "rk-exc-dialog");
        box.appendChild(el("h3", null, "Return to the risk pool — " + row.CVE));
        box.appendChild(el("div", "rk-exc-help",
            "The findings this covers start counting again immediately, and will reappear in " +
            "every risk number within the hour. The record is kept and marked withdrawn, not " +
            "deleted, so the trail still shows it was once accepted and by whom."));
        var msg = el("div", "rk-exc-msg");
        box.appendChild(msg);
        var actions = el("div", "rk-exc-actions");
        var cancel = el("button", "rk-exc-btn", "Cancel");
        cancel.type = "button";
        cancel.addEventListener("click", closeDialog);
        var go = el("button", "rk-exc-btn rk-exc-btn-primary", "Return to risk pool");
        go.type = "button";
        go.addEventListener("click", function () {
            go.disabled = true;
            msg.textContent = "Withdrawing…";
            post({ action: "revoke", exception_key: row.Key }).then(function () {
                msg.textContent = "Withdrawn.";
                msg.className = "rk-exc-msg rk-exc-ok";
                setTimeout(function () { closeDialog(); window.location.reload(); }, 1800);
            }).catch(function (err) {
                msg.textContent = String(err.message || err);
                msg.className = "rk-exc-msg rk-exc-bad";
                go.disabled = false;
            });
        });
        actions.appendChild(cancel);
        actions.appendChild(go);
        box.appendChild(actions);
        overlay.appendChild(box);
        overlay.addEventListener("click", function (e) {
            if (e.target === overlay) { closeDialog(); }
        });
        document.body.appendChild(overlay);
    }

    function bind(id, handler) {
        var b = document.getElementById(id);
        if (!b || b.dataset.rkWired) { return false; }
        b.dataset.rkWired = "1";
        b.addEventListener("click", handler);
        return true;
    }

    function wire() {
        var any = false;
        any = bind("rk-exc-accept", function () { openDialog("create"); }) || any;
        any = bind("rk-exc-reg-edit", function () { openDialog("edit", regSelection[0]); }) || any;
        any = bind("rk-exc-reg-revoke", confirmRevoke) || any;
        any = bind("rk-exc-exp-reaccept", function () {
            openDialog("reactivate", expSelection[0]);
        }) || any;
        if (any) { summarise(); }
        return any;
    }

    // The html panel is rendered by Splunk after this script runs, so wait for
    // the button rather than assuming it exists.
    // Splunk renders html panels after this script runs, and the register page
    // has three buttons across two panels that appear at different moments, so
    // the observer keeps binding rather than disconnecting on the first hit.
    wire();
    var observer = new MutationObserver(wire);
    observer.observe(document.body, { childList: true, subtree: true });
})();
