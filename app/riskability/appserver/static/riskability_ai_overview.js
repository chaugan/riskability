/*
 * AI prioritization overview -- the user-facing page of the analysis pipeline.
 *
 * Reads entirely from precomputed KV (verdicts cache + summary), served by
 * the status handler in under a second. No searches on page load.
 *
 * Features:
 * - Tier filter buttons with live counts (All / P0 / P1 / P2 / P3 / P4)
 * - CVE links to the encyclopedia
 * - Advisory title, package, severity, EPSS, KEV, exposure context
 * - Coverage tiles (analysed / awaiting / failed)
 * - Self-hiding when AI is switched off
 */
(function () {
    "use strict";

    var state = null;      // the status endpoint reply
    var tierFilter = "all"; // current filter selection

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
        } catch (e) {}
    }

    function humanAge(epochSeconds) {
        if (!epochSeconds) return "never";
        var secs = Math.floor(Date.now() / 1000) - Number(epochSeconds);
        if (secs < 0) secs = 0;
        if (secs < 3600) return Math.max(0, Math.floor(secs / 60)) + " min ago";
        if (secs < 86400) return Math.floor(secs / 3600) + " h ago";
        return Math.floor(secs / 86400) + " d ago";
    }

    var TIER_CLASS = { "P0": "rk-ai-p0", "P1": "rk-ai-p1", "P2": "rk-ai-p2", "P3": "rk-ai-p3", "P4": "rk-ai-p4" };
    var TIERS = ["P0", "P1", "P2", "P3", "P4"];

    function tierBadge(tier) {
        return el("span", "rk-ai-tier " + (TIER_CLASS[tier] || "rk-ai-p4"), tier || "?");
    }

    var root = document.getElementById("riskability-ai-overview");
    if (!root) return;

    fetch(statusEndpoint(), {
        method: "GET",
        headers: { "X-Splunk-Form-Key": csrfToken(), "X-Requested-With": "XMLHttpRequest" },
        credentials: "same-origin"
    }).then(function (r) {
        return r.text().then(function (text) {
            if (!r.ok) throw new Error("HTTP " + r.status);
            return JSON.parse(text);
        });
    }).then(function (s) {
        if (!s || s.enabled !== true) { hideNavItem(); return; }
        state = s;
        render();
    }).catch(function () { hideNavItem(); });

    function render() {
        root.textContent = "";
        var ov = state.overview || {};
        buildSummary(ov);
        buildCoverage(ov);
        buildTierFilter(ov);
        buildTable(ov);
    }

    function tile(value, label, cls) {
        var t = el("div", "rk-ai-tile " + (cls || ""));
        t.appendChild(el("div", "rk-ai-num", value));
        t.appendChild(el("div", "rk-ai-label", label));
        return t;
    }

    function buildSummary(ov) {
        var tc = ov.tier_counts || {};
        var strip = el("div", "rk-ai-summary");
        strip.appendChild(tile(tc.P0 || 0, "P0 — patch now", "rk-ai-p0"));
        strip.appendChild(tile(tc.P1 || 0, "P1 — urgent", "rk-ai-p1"));
        strip.appendChild(tile(ov.analyzed_cves || 0, "CVEs analysed"));
        strip.appendChild(tile(humanAge(ov.latest_at), "last analysis"));
        root.appendChild(strip);
        root.appendChild(el("p", "rk-dim",
            "Priorities combine Riskability's own measurements — reach, version evidence, EPSS and KEV — " +
            "with model reasoning about exploitability. A tier is advice about order of work, not a measurement."));
    }

    function buildCoverage(ov) {
        var strip = el("div", "rk-ai-summary");
        var awaiting = Math.max(0, (ov.open_cves || 0) - (ov.analyzed_cves || 0));
        if (ov.open_cves) strip.appendChild(tile(ov.open_cves, "open CVEs in fleet"));
        if (awaiting > 0) strip.appendChild(tile(awaiting, "awaiting analysis budget"));
        // No "failed analyses" tile: failures are reported per run and never
        // cached, so this page has no honest number for them. The analyze
        // saved search's job history is where a run's health is counted.
        if (strip.children.length > 0) root.appendChild(strip);
    }

    function buildTierFilter(ov) {
        var tc = ov.tier_counts || {};
        var all = (ov.results || []).length;
        var bar = el("div", "rk-ai-filter-bar");

        function btn(tier, label, count, cls) {
            var b = el("button", "rk-ai-filter-btn " + (cls || "") +
                       (tierFilter === tier ? " rk-ai-filter-active" : ""),
                       label + " (" + count + ")");
            b.type = "button";
            b.addEventListener("click", function () {
                tierFilter = tier;
                render();
            });
            return b;
        }

        bar.appendChild(btn("all", "All", all, ""));
        TIERS.forEach(function (t) {
            bar.appendChild(btn(t, t, tc[t] || 0, TIER_CLASS[t]));
        });
        root.appendChild(bar);
    }

    function buildTable(ov) {
        var card = el("div", "rk-card");
        card.appendChild(el("h3", null, "Prioritized CVEs"));
        card.appendChild(el("p", "rk-dim",
            "Sorted by score. Click a CVE to open the encyclopedia entry."));
        root.appendChild(card);

        var rows = ov.results || [];
        var filtered = tierFilter === "all" ? rows : rows.filter(function (r) {
            return r.priority_tier === tierFilter;
        });

        if (!filtered.length) {
            card.appendChild(el("p", "rk-dim",
                rows.length ? "No " + tierFilter + " findings — try another tier."
                : "No analysis results yet. The first run happens after the queue " +
                  "search completes and the GPU server works through it."));
            return;
        }

        var tbl = el("table", "rk-table rk-ai-table");
        var head = el("tr");
        ["Tier", "Score", "CVE / Advisory", "Software", "Action", "Why"].forEach(function (h) {
            head.appendChild(el("th", null, h));
        });
        tbl.appendChild(head);

        filtered.forEach(function (row) {
            var tr = el("tr");

            var tier = el("td");
            tier.appendChild(tierBadge(row.priority_tier));
            tr.appendChild(tier);

            var score = el("td", "rk-num");
            score.appendChild(el("b", null, row.priority_score));
            score.appendChild(el("div", "rk-dim", "conf " + (row.confidence || "?")));
            tr.appendChild(score);

            var cveCell = el("td", "rk-ai-cve");
            var link = el("a", null, row.cve_id);
            link.href = splunkRoot() + "/app/riskability/riskability_cve?form.cve_tok=" +
                        encodeURIComponent(row.cve_id || "");
            cveCell.appendChild(link);
            // The advisory title is shown in full. It used to be cut at 90
            // characters in JavaScript, with no ellipsis and nowhere to read
            // the rest, which truncated most advisories mid-sentence. The
            // column wraps instead; CSS decides the width, not a magic number.
            if (row.title) {
                cveCell.appendChild(el("div", "rk-ai-title", String(row.title)));
            }
            var signals = [];
            if (row.severity) signals.push(row.severity);
            if (row.kev === "true") signals.push("KEV");
            if (row.epss && row.epss !== "" && row.epss !== "0") signals.push("EPSS " + row.epss);
            if (row.exposure_zone) signals.push(row.exposure_zone);
            if (signals.length) {
                cveCell.appendChild(el("div", "rk-ai-signals", signals.join(" · ")));
            }
            tr.appendChild(cveCell);

            // Whose software, which product, which copy. A priority list that
            // names a CVE and not the thing the CVE is in makes the reader go
            // and look it up, which is the work this page exists to save.
            // vendor is absent for software the inventory reported without one
            // (most Linux packages), and the line simply omits it rather than
            // printing "unknown": the package name is the identity there.
            var sw = el("td", "rk-ai-sw");
            if (row.package) {
                sw.appendChild(el("div", "rk-ai-pkg", row.package));
            } else {
                sw.appendChild(el("div", "rk-dim", "not identified"));
            }
            if (row.vendor) {
                sw.appendChild(el("div", "rk-dim", row.vendor));
            }
            if (row.installed_version) {
                sw.appendChild(el("div", "rk-dim", "installed " + row.installed_version));
            }
            tr.appendChild(sw);

            tr.appendChild(el("td", null, row.recommended_action));

            var why = el("td", "rk-ai-why");
            why.appendChild(el("div", null, row.rationale || ""));
            var mits = [].concat(row.recommended_mitigations || []);
            if (mits.length) {
                var ul = el("ul", "rk-ai-mit");
                mits.forEach(function (m) { ul.appendChild(el("li", null, m)); });
                why.appendChild(ul);
            }
            var tech = [].concat(row.attck_techniques || []);
            if (tech.length) {
                why.appendChild(el("div", "rk-dim", "ATT&CK " + tech.join(", ")));
            }
            why.appendChild(el("div", "rk-dim",
                (row.analysis_source || "") + " · " + humanAge(row.analysed_at)));
            tr.appendChild(why);
            tbl.appendChild(tr);
        });
        card.appendChild(tbl);
        if (filtered.length > 20) {
            card.appendChild(el("p", "rk-dim",
                "Showing " + filtered.length + " of " + rows.length + " analysed CVEs."));
        }
    }
})();
