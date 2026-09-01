/*
 * AI prioritization overview -- the user-facing page of the analysis pipeline.
 *
 * The whole page is drawn here rather than in the dashboard XML, and the
 * reason is the gate at the top of this file: before anything is rendered the
 * script asks /riskability/ai_status whether AI prioritisation is switched
 * on. That endpoint is the only AI endpoint a normal user can reach, and it
 * answers one bit plus a precomputed overview. When the bit is off, this page
 * draws nothing, removes itself from the navigation bar, and stops.
 *
 * The overview data comes entirely from the KV Store (verdicts cache +
 * summary row), read by the status handler on the server side. No searches
 * run on page load: the expansion search precomputes everything and this
 * page renders instantly.
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
        var secs = Math.floor(Date.now() / 1000) - Number(epochSeconds);
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

    // The gate: one bit + precomputed overview, no searches on page load.
    fetch(statusEndpoint(), {
        method: "GET",
        headers: { "X-Splunk-Form-Key": csrfToken(), "X-Requested-With": "XMLHttpRequest" },
        credentials: "same-origin"
    }).then(function (r) {
        return r.text().then(function (text) {
            if (!r.ok) throw new Error("HTTP " + r.status);
            return JSON.parse(text);
        });
    }).then(function (state) {
        if (!state || state.enabled !== true) {
            hideNavItem();
            return; // draw nothing at all
        }
        render(state.overview || {});
    }).catch(function () {
        hideNavItem(); // unreachable status endpoint: same silence as "off"
    });

    function render(ov) {
        root.textContent = "";

        buildSummary(ov);
        buildCoverage(ov);
        buildTable(ov);
        buildFooter(ov);
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
        strip.appendChild(tile(ov.analyzed_cves || 0, "distinct CVEs analysed"));
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
        var awaiting = Math.max(0, (ov.open_cves || 0) - (ov.analyzed_cves || 0));
        if (ov.open_cves) strip.appendChild(tile(ov.open_cves, "open CVEs in fleet"));
        if (awaiting > 0) strip.appendChild(tile(awaiting, "awaiting analysis budget"));
        if (ov.failed_analyses > 0) {
            strip.appendChild(tile(ov.failed_analyses, "analyses failed (fallback rows)", "rk-ai-p2"));
        }
        if (strip.children.length > 0) root.appendChild(strip);
    }

    function buildTable(ov) {
        var card = el("div", "rk-card");
        card.appendChild(el("h3", null, "Current priorities"));
        card.appendChild(el("p", "rk-dim",
            "The highest-scoring CVEs from the verdict cache, worst first."));
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
        ["Tier", "Score", "CVE", "Action", "Why"].forEach(function (h) {
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
                "confidence " + (row.confidence || "?")));
            tr.appendChild(score);

            tr.appendChild(el("td", "rk-mono", row.cve_id));
            tr.appendChild(el("td", null, row.recommended_action));

            var why = el("td", "rk-ai-why");
            why.appendChild(el("div", null, row.rationale || ""));
            var mits = [].concat(row.recommended_mitigations || []);
            if (mits.length) {
                var ul = el("ul", "rk-ai-mit");
                mits.forEach(function (m) { ul.appendChild(el("li", null, m)); });
                why.appendChild(ul);
            }
            why.appendChild(el("div", "rk-dim",
                (row.analysis_source || "") + " · " + humanAge(row.analysed_at)));
            tr.appendChild(why);
            tbl.appendChild(tr);
        });
        card.appendChild(tbl);
        if (rows.length >= 10) {
            card.appendChild(el("p", "rk-dim", "Showing the 10 highest-scoring CVEs."));
        }
    }

    function buildFooter(ov) {
        if (ov.overview_error) {
            var warn = el("div", "rk-status rk-warn");
            warn.appendChild(el("b", null, "Part of this page could not be loaded. "));
            warn.appendChild(el("span", null, ov.overview_error));
            root.appendChild(warn);
        }
    }
})();
