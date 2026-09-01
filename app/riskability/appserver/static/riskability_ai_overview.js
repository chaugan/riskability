/*
 * AI prioritization overview -- the user-facing page of the analysis pipeline.
 *
 * The whole page is drawn here rather than in the dashboard XML, and the
 * reason is the gate at the top of this file: before anything is rendered the
 * script asks /riskability/ai_status whether AI prioritisation is switched
 * on. That endpoint is the only AI endpoint a normal user can reach, and it
 * answers one bit. When the bit is off, this page draws nothing, removes
 * itself from the navigation bar, and stops. A user of an instance whose
 * admin never configured AI sees no AI page, no empty panels, and no message
 * about anything missing -- there is nothing to be missing, as far as the
 * app is concerned.
 *
 * The page's DATA rides on the same GET (the server runs the searches and
 * returns rows directly). Browser-issued search POSTs through the splunkd
 * proxy are not survivable on this Splunk build (splunkd 500s inside its
 * own proxy), so everything the page shows is computed server-side by the
 * status handler under the reader's own permissions.
 *
 * Everything the server returns is rendered with textContent, never HTML:
 * the rationale column is text a model on another machine wrote; the same
 * discipline the feed page applies to third-party feed titles applies here.
 */
(function () {
    "use strict";

    function el(tag, className, text) {
        var node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null) node.textContent = String(text);
        return node;
    }

    function splunkRoot() {
        var path = window.location.pathname;
        var i = path.indexOf("/app/");
        if (i < 0) return "";
        return path.slice(0, i);
    }

    function statusEndpoint() {
        return splunkRoot() + "/splunkd/__raw/services/riskability/ai_status";
    }

    function csrfToken() {
        var m = document.cookie.match(/splunkweb_csrf_token_\d+=([^;]+)/);
        return m ? decodeURIComponent(m[1]) : "";
    }

    function fetchStatus() {
        return fetch(statusEndpoint(), {
            method: "GET",
            headers: { "X-Splunk-Form-Key": csrfToken(), "X-Requested-With": "XMLHttpRequest" },
            credentials: "same-origin"
        }).then(function (r) {
            return r.text().then(function (text) {
                if (!r.ok) throw new Error("HTTP " + r.status);
                return JSON.parse(text);
            });
        });
    }

    function hideNavItem() {
        try {
            document.querySelectorAll('a[href$="riskability_ai"]').forEach(function (a) {
                var item = a.closest("li") || a.parentElement;
                if (item) item.style.display = "none";
            });
        } catch (e) { /* an unusual nav theme is not worth breaking the page for */ }
    }

    function humanAge(epochSeconds) {
        if (!epochSeconds) return "never";
        var secs = Math.floor(Date.now() / 1000) - epochSeconds;
        if (secs < 0) secs = 0;
        if (secs < 3600) return Math.max(0, Math.floor(secs / 60)) + " minutes ago";
        if (secs < 86400) return Math.floor(secs / 3600) + " hours ago";
        return Math.floor(secs / 86400) + " days ago";
    }

    var TIER_CLASS = {
        "P0": "rk-ai-p0", "P1": "rk-ai-p1", "P2": "rk-ai-p2",
        "P3": "rk-ai-p3", "P4": "rk-ai-p4"
    };

    function tierBadge(tier) {
        return el("span", "rk-ai-tier " + (TIER_CLASS[tier] || "rk-ai-p4"), tier || "?");
    }

    var root = document.getElementById("riskability-ai-overview");
    if (!root) return;

    request(statusEndpoint()).then(function (state) {
        if (!state || state.enabled !== true) {
            hideNavItem();
            return; // draw nothing at all
        }
        render(state);
    }).catch(function () {
        hideNavItem(); // unreachable status endpoint: same silence as "off"
    });

    function request(url, method, body) {
        var headers = { "X-Splunk-Form-Key": csrfToken(), "X-Requested-With": "XMLHttpRequest" };
        var opts = { method: method, headers: headers, credentials: "same-origin" };
        if (body !== undefined) {
            headers["Content-Type"] = "application/json";
            opts.body = JSON.stringify(body);
        }
        return fetch(url, opts).then(function (r) {
            return r.text().then(function (text) {
                var data;
                try { data = JSON.parse(text); } catch (e) { data = { error: text }; }
                if (!r.ok || data.error) {
                    throw new Error(data.error || ("HTTP " + r.status));
                }
                return data;
            });
        });
    }

    function render(state) {
        root.textContent = "";
        var ov = state.overview || {};

        buildSummary(ov);
        buildCoverage(ov);
        buildTable(ov);
        buildRuns(ov);

        if (ov.overview_error) {
            var warn = el("div", "rk-status rk-warn");
            warn.appendChild(el("b", null, "Part of this page could not be loaded. "));
            warn.appendChild(el("span", null, ov.overview_error));
            root.appendChild(warn);
        }
    }

    function tile(value, label, cls) {
        var t = el("div", "rk-ai-tile " + (cls || ""));
        t.appendChild(el("div", "rk-ai-num", value));
        t.appendChild(el("div", "rk-ai-label", label));
        return t;
    }

    function buildSummary(ov) {
        var strip = el("div", "rk-ai-summary");
        strip.appendChild(tile(ov.p0 || 0, "P0 — patch now", "rk-ai-p0"));
        strip.appendChild(tile(ov.p1 || 0, "P1 — urgent", "rk-ai-p1"));
        strip.appendChild(tile(ov.findings || 0, "assets × CVEs analyzed"));
        strip.appendChild(tile(humanAge(ov.latest_at), "last analysis"));
        root.appendChild(strip);
        root.appendChild(el("p", "rk-dim",
            "Priorities are produced by an AI model running on separate infrastructure, " +
            "combining Riskability's own measurements — reach, version evidence, EPSS and " +
            "KEV — with reasoning about exploitability. A tier is advice about order of " +
            "work, not a measurement; the underlying reach and exploit data on the other " +
            "pages is where the facts live."));
    }

    function buildCoverage(ov) {
        var strip = el("div", "rk-ai-summary");
        strip.appendChild(tile(ov.analyzed_cves || 0, "distinct CVEs analysed"));
        var awaiting = Math.max(0, (ov.open_cves || 0) - (ov.analyzed_cves || 0));
        strip.appendChild(tile(awaiting, "awaiting analysis budget"));
        if (ov.failed_analyses > 0) {
            strip.appendChild(tile(ov.failed_analyses, "analyses failed (fallback rows)", "rk-ai-p2"));
        }
        root.appendChild(strip);
    }

    function buildTable(ov) {
        var card = el("div", "rk-card");
        card.appendChild(el("h3", null, "Current priorities"));
        card.appendChild(el("p", "rk-dim",
            "The most recent prioritization per CVE per asset, worst first."));
        root.appendChild(card);

        var rows = ov.top || [];
        if (!rows.length) {
            card.appendChild(el("p", "rk-dim",
                "No analysis results yet. The first run happens after the queue " +
                "search next completes and the GPU server works through it."));
            return;
        }
        var tbl = el("table", "rk-table rk-ai-table");
        var head = el("tr");
        ["Tier", "Score", "CVE", "Asset", "Action", "Exposure", "Evidence", "Why"].forEach(function (h) {
            head.appendChild(el("th", null, h));
        });
        tbl.appendChild(head);
        rows.forEach(function (row) {
            var tr = el("tr");
            var tier = el("td");
            tier.appendChild(tierBadge(row.priority_tier));
            tr.appendChild(tier);

            var score = el("td", "rk-num");
            score.appendChild(el("b", null, row.priority_score));
            score.appendChild(el("div", "rk-dim",
                "confidence " + (row.confidence !== undefined && row.confidence !== "" ? row.confidence : "?")));
            tr.appendChild(score);

            tr.appendChild(el("td", "rk-mono", row.cve_id));
            tr.appendChild(el("td", "rk-mono", row.asset_id));
            tr.appendChild(el("td", null, row.recommended_action));

            var ev = el("td", "rk-dim");
            ev.appendChild(el("div", null,
                (row.exposure_zone || "?") + (row.kev === "true" ? " · KEV" : "") +
                (row.epss !== undefined && row.epss !== "" && row.epss !== null ? " · EPSS " + row.epss : "")));
            ev.appendChild(el("div", null, row.severity || ""));
            var tech = [].concat(row.attck_techniques || []);
            if (tech.length) {
                ev.appendChild(el("div", null, "ATT&CK " + tech.join(", ")));
            }
            tr.appendChild(ev);

            var why = el("td", "rk-ai-why");
            why.appendChild(el("div", null, row.rationale || ""));
            var mits = [].concat(row.recommended_mitigations || []);
            if (mits.length) {
                var ul = el("ul", "rk-ai-mit");
                mits.forEach(function (m) { ul.appendChild(el("li", null, m)); });
                why.appendChild(ul);
            }
            why.appendChild(el("div", "rk-dim",
                (row.analysis_source || "") + " · " + humanAge(Number(row.analysed_at) || 0)));
            tr.appendChild(why);
            tbl.appendChild(tr);
        });
        card.appendChild(tbl);
        if (rows.length >= 10) {
            card.appendChild(el("p", "rk-dim", "Showing the 10 highest-priority findings."));
        }
    }

    function buildRuns(ov) {
        var card = el("div", "rk-card");
        card.appendChild(el("h3", null, "Analysis runs"));
        root.appendChild(card);
        var runs = ov.runs || [];
        if (!runs.length) {
            card.appendChild(el("p", "rk-dim", "No runs have reported yet."));
            return;
        }
        var tbl = el("table", "rk-table");
        var head = el("tr");
        ["Run", "When", "Findings analyzed", "Assets", "P0"].forEach(function (h) {
            head.appendChild(el("th", null, h));
        });
        tbl.appendChild(head);
        runs.forEach(function (row) {
            var tr = el("tr");
            tr.appendChild(el("td", "rk-mono", row.run_id));
            tr.appendChild(el("td", null, humanAge(Number(row.at) || 0)));
            tr.appendChild(el("td", "rk-num", row.analyzed));
            tr.appendChild(el("td", "rk-num", row.assets));
            tr.appendChild(el("td", "rk-num", row.p0));
            tbl.appendChild(tr);
        });
        card.appendChild(tbl);
    }
})();
