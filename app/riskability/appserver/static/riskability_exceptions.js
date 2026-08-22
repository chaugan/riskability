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
    var selection = [];

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

    document.addEventListener(SELECTION_EVENT, function (e) {
        selection = (e.detail && e.detail.rows) || [];
        summarise();
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

    function openDialog() {
        closeDialog();
        var cve = distinct(selection, "CVE")[0];
        var hosts = distinct(selection, "Host");
        var kev = selection.some(function (r) { return String(r.KEV || "").toLowerCase() === "yes"; });

        var overlay = el("div", "rk-exc-overlay");
        overlay.id = "rk-exc-dialog";
        var box = el("div", "rk-exc-dialog");

        box.appendChild(el("h3", null, "Accept risk — " + cve));

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
        [["host_cve", "This CVE on " + (hosts.length === 1 ? hosts[0] : hosts.length + " selected hosts")],
         ["finding", "Only the " + selection.length + " selected finding" +
                     (selection.length === 1 ? "" : "s") + " (exact path)"],
         ["fleet_cve", "This CVE on EVERY host, including ones added later"]
        ].forEach(function (o) {
            var opt = el("option", null, o[1]);
            opt.value = o[0];
            scopeSel.appendChild(opt);
        });
        field(box, "What is being accepted", scopeSel,
              "Host-and-CVE is the usual choice: it survives a rebuild that moves the package, " +
              "and one entry covers every copy on that host. Fleet-wide also covers hosts that " +
              "do not exist yet.");

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
        notes.placeholder = "Ticket reference, who agreed it, anything else worth keeping.";
        field(box, "Notes", notes);

        var msg = el("div", "rk-exc-msg");
        box.appendChild(msg);

        var actions = el("div", "rk-exc-actions");
        var cancel = el("button", "rk-exc-btn", "Cancel");
        cancel.type = "button";
        cancel.addEventListener("click", closeDialog);
        var submit = el("button", "rk-exc-btn rk-exc-btn-primary", "Accept risk");
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

    function wire() {
        var button = document.getElementById("rk-exc-accept");
        if (!button || button.dataset.rkWired) { return; }
        button.dataset.rkWired = "1";
        button.addEventListener("click", openDialog);
        summarise();
    }

    // The html panel is rendered by Splunk after this script runs, so wait for
    // the button rather than assuming it exists.
    if (document.getElementById("rk-exc-accept")) {
        wire();
    } else {
        var observer = new MutationObserver(function () {
            if (document.getElementById("rk-exc-accept")) {
                wire();
                observer.disconnect();
            }
        });
        observer.observe(document.body, { childList: true, subtree: true });
    }
})();
