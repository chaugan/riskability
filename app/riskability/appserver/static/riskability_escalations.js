/*
 * Escalation rules: the list, and the switch.
 *
 * Reads /riskability/escalations for the rules as the search head sees them
 * (the conf, parsed by the same validator the engine uses) and whether the
 * compiled macro is in force. A toggle POSTs the one field this endpoint will
 * change. Everything else about a rule is read-only here on purpose.
 */
(function () {
    "use strict";

    function el(tag, cls, text) {
        var n = document.createElement(tag);
        if (cls) n.className = cls;
        if (text !== undefined && text !== null) n.textContent = String(text);
        return n;
    }
    function splunkRoot() {
        var i = window.location.pathname.indexOf("/app/");
        return i < 0 ? "" : window.location.pathname.slice(0, i);
    }
    function endpoint() { return splunkRoot() + "/splunkd/__raw/services/riskability/escalations"; }
    function csrf() {
        var m = document.cookie.match(/splunkweb_csrf_token_\d+=([^;]+)/);
        return m ? decodeURIComponent(m[1]) : "";
    }
    function call(method, body) {
        var opts = {method: method, credentials: "same-origin",
                    headers: {"X-Splunk-Form-Key": csrf(), "X-Requested-With": "XMLHttpRequest"}};
        if (body) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
        return fetch(endpoint(), opts).then(function (r) {
            return r.json().then(function (j) { if (!r.ok) throw new Error(j.error || ("HTTP " + r.status)); return j; });
        });
    }

    var root = document.getElementById("riskability-escalation-rules");
    if (!root) return;

    function render(data) {
        root.textContent = "";
        if (!data.in_force) {
            var warn = el("div", "rk-status rk-bad");
            warn.appendChild(el("b", null, "The compiled rule set is not what the conf says."));
            warn.appendChild(el("span", null, "Somebody changed riskability_escalations.conf "
                + "without recompiling, so the evaluation search is running a stale set. "
                + "Flipping any switch below recompiles it from the conf as it stands."));
            root.appendChild(warn);
        }
        var problems = {};
        (data.problems || []).forEach(function (p) { problems[p.rule] = p; });
        // A rule the validator refused is still a rule somebody wrote, and an
        // operator looking for it must find it here with the reason, not
        // conclude it was never shipped. It gets a row and a locked switch.
        var listed = {};
        (data.rules || []).forEach(function (r) { listed[r.name] = true; });
        var rows = (data.rules || []).slice();
        (data.problems || []).forEach(function (p) {
            if (!listed[p.rule]) {
                listed[p.rule] = true;
                rows.push({name: p.rule, description: p.description || "", when: p.when || "",
                           bump: p.bump || "", enabled: false, refused: true});
            }
        });

        var tbl = el("table", "rk-table rk-esc-table");
        var head = el("tr");
        ["Rule", "On", "Bump", "Condition", "Why it exists"].forEach(function (h) { head.appendChild(el("th", null, h)); });
        tbl.appendChild(head);
        rows.forEach(function (r) {
            var tr = el("tr");
            tr.appendChild(el("td", "rk-esc-name", r.name));

            var td = el("td");
            var problem = problems[r.name];
            var sw = el("button", "rk-esc-switch " + (r.enabled ? "is-on" : ""), r.enabled ? "on" : "off");
            sw.type = "button";
            sw.setAttribute("role", "switch");
            sw.setAttribute("aria-checked", r.enabled ? "true" : "false");
            if (problem && (problem.kind === "unproduced" || r.refused)) {
                sw.disabled = true;
                sw.title = "Cannot be switched on: " + problem.detail;
            } else {
                sw.title = (r.enabled ? "Switch off " : "Switch on ") + r.name;
                sw.addEventListener("click", function () {
                    sw.disabled = true; sw.textContent = "…";
                    call("POST", {rule: r.name, enabled: !r.enabled}).then(load).catch(function (e) {
                        sw.disabled = false; sw.textContent = r.enabled ? "on" : "off";
                        var err = el("div", "rk-status rk-bad");
                        err.appendChild(el("b", null, "Not changed."));
                        err.appendChild(el("span", null, e.message));
                        root.insertBefore(err, root.firstChild);
                    });
                });
            }
            td.appendChild(sw);
            if (problem) td.appendChild(el("div", "rk-dim rk-esc-problem", problem.detail));
            tr.appendChild(td);

            tr.appendChild(el("td", "rk-num", r.bump));
            tr.appendChild(el("td", "rk-esc-when", r.when));
            tr.appendChild(el("td", "rk-esc-desc", r.description));
            tbl.appendChild(tr);
        });
        root.appendChild(tbl);
    }

    function load() {
        return call("GET").then(render).catch(function (e) {
            root.textContent = "";
            var err = el("div", "rk-status rk-bad");
            err.appendChild(el("b", null, "The escalation rules could not be read."));
            err.appendChild(el("span", null, e.message));
            root.appendChild(err);
        });
    }
    load();
})();
