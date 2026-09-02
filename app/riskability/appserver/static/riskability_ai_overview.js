/*
 * AI prioritization overview -- the user-facing page of the analysis pipeline.
 *
 * Reads entirely from precomputed KV (verdicts cache + summary), served by
 * the status handler in under a second. No searches on page load.
 *
 * Features:
 * - Tier filter buttons with live counts (All / P0 / P1 / P2 / P3 / P4)
 * - CVE links to the encyclopedia
 * - Advisory title in full, software with vendor and installed version,
 *   severity, EPSS, KEV, exposure context
 * - On-demand deep explanation per row, cached with the verdict
 * - Coverage tiles (analysed / awaiting)
 * - Self-hiding when AI is switched off
 */
(function () {
    "use strict";

    var state = null;      // the status endpoint reply
    var tierFilter = "all"; // current filter selection
    var page = 0;          // zero based page index into the filtered rows
    var pageSize = 25;

    // Why this table is paged rather than long. Every analysed CVE used to be
    // written into the DOM at once: on the fleet this was built against that
    // is 5,753 rows, each carrying a rationale, a mitigation list and an
    // explain button, and the page measured over a million pixels tall. A
    // reader cannot use a million pixels and a browser should not have to lay
    // them out. Paging is also the honest shape for the content: this is a
    // work queue read from the top, so the rows that matter are the first
    // ones, and anything past the first page is being browsed rather than
    // worked.
    var PAGE_SIZES = [25, 50, 100];

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

    function explainCve(cveId) {
        return fetch(splunkRoot() + "/splunkd/__raw/services/riskability/ai_explain",
                     {method: "POST",
                      headers: {"Content-Type": "application/json",
                                "X-Splunk-Form-Key": csrfToken(),
                                "X-Requested-With": "XMLHttpRequest"},
                      credentials: "same-origin",
                      body: JSON.stringify({cve_id: cveId})})
            .then(function (r) {
                return r.json().then(function (j) {
                    if (!r.ok) { throw new Error(j.error || ("HTTP " + r.status)); }
                    return j;
                });
            });
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

    var cveFilter = null;   // set by clicking a stem in the sea chart

    function render() {
        root.textContent = "";
        var ov = state.overview || {};
        buildSummary(ov);
        buildCoverage(ov);
        buildMethod();
        buildSea(ov);
        buildTierFilter(ov);
        buildTable(ov);
    }

    // The sea, and what rises out of it. Drawn above the table and never
    // instead of it: the picture answers "how much is there and how little
    // matters", the table answers "and what exactly do I do". Clicking a stem
    // filters the table rather than replacing it, so the two stay one page.
    function buildSea(ov) {
        if (typeof window.RiskabilityAIChart === "undefined") return;
        var bands = {};
        ["0", "1", "2", "3", "4"].forEach(function (b) {
            bands[b] = Number(ov["sea_" + b] || 0);
        });
        var card = el("div", "rk-card");
        card.appendChild(el("h3", null, "The sea, and what rises out of it"));
        card.appendChild(el("p", "rk-dim",
            "Every open CVE in the fleet, banded by exploit likelihood. The few "
            + "the pipeline lifted above the waterline are drawn as stems. Hover "
            + "one for the reasoning, click it to filter the table below."));
        var host = el("div", "rk-ai-sea");
        card.appendChild(host);
        root.appendChild(card);
        try {
            var chart = window.RiskabilityAIChart.render(
                host, {seaBands: bands, results: ov.results || []},
                function (cveId) {
                    cveFilter = (cveFilter === cveId) ? null : cveId;
                    page = 0;
                    render();
                });
            window.addEventListener("resize", function () {
                try { chart.resize(); } catch (e) {}
            });
        } catch (e) {
            host.parentNode.removeChild(host);
            card.appendChild(el("p", "rk-dim", "The overview chart could not be drawn."));
        }
    }

    // The weights, repeated here so a reader can check the arithmetic against
    // the number in front of them.
    //
    // THESE MUST MATCH ai_config.py. They are duplicated rather than served,
    // because the status endpoint returns verdicts and not the scoring table,
    // and a second endpoint for six constants is not worth the moving part.
    // tools/test_ai_mod.py fails if these drift from the Python, which is the
    // only reason it is safe to write them twice.
    var SCORE_ROWS = [
        ["On CISA KEV", "+45", "known exploited in the wild, so the largest single term"],
        ["EPSS \u2265 50%", "+40", "exploit likelihood in the next 30 days"],
        ["EPSS 20\u201350%", "+30", ""],
        ["EPSS 5\u201320%", "+20", ""],
        ["EPSS 1\u20135%", "+8", ""],
        ["EPSS < 1%", "0", ""],
        ["CVSS \u2265 9", "+22", "severity, banded so ordinary rescoring does not churn"],
        ["CVSS 7\u20139", "+16", ""],
        ["CVSS 4\u20137", "+8", ""],
        ["CVSS < 4, or none", "0", ""],
        ["Internet-facing", "+25", "measured from how the process bound its socket"],
        ["Internal", "+8", ""],
        ["Exposure unknown", "+4", "not assessed is not the same as safe"],
        ["Isolated", "0", ""],
        ["Version confirmed vulnerable", "+22", "the installed version is in the affected range"],
        ["Version unknown", "+4", ""],
        ["Version confirmed NOT vulnerable", "\u221225", "the only negative term on the page"]
    ];

    var TIER_ROWS = [
        ["P0", "85\u2013100", "patch now"],
        ["P1", "65\u201384", "urgent"],
        ["P2", "45\u201364", "planned"],
        ["P3", "25\u201344", "routine"],
        ["P4", "0\u201324", "backlog"]
    ];

    function methodSection(title, open) {
        var d = el("details", "rk-ai-method");
        if (open) d.open = true;
        d.appendChild(el("summary", null, title));
        return d;
    }

    function buildMethod() {
        var card = el("div", "rk-card rk-ai-method-card");
        card.appendChild(el("h3", null, "How this page works"));

        // --- what the page is -------------------------------------------------
        var what = methodSection("What you are looking at", true);
        var p1 = el("p", null,
            "Every open CVE in the fleet is scored from measured facts, and the "
            + "few that score highest are sent to a language model for reasoning. "
            + "The chart shows the whole sea of CVEs banded by exploit "
            + "likelihood; the stems are the ones lifted above the waterline. "
            + "The table is the work queue, in score order.");
        what.appendChild(p1);
        what.appendChild(el("p", "rk-dim",
            "A tier is advice about the order of work, not a measurement. Nothing "
            + "here is a statement that a vulnerability is or is not exploitable "
            + "on your estate."));
        card.appendChild(what);

        // --- the division of labour, which is the part people get wrong --------
        var who = methodSection("What the model does, and what it cannot do", false);
        who.appendChild(el("p", null,
            "The score is arithmetic. The model is not asked for it and cannot "
            + "change it."));
        var ul = el("ul", "rk-ai-method-list");
        [["The app decides", "the score, the tier and the ordering, from KEV, EPSS, "
          + "CVSS, measured exposure and version evidence."],
         ["The model decides", "the words: the rationale you read in the Why "
          + "column, the suggested mitigations and the ATT&CK technique ids."],
         ["Why it is split that way", "asked directly for a 0\u2013100 score on 1,020 "
          + "real findings, the model returned seven distinct integers, 663 of them "
          + "the value 85, and a tier that contradicted its own score on 842 of "
          + "them. It is good at explaining and bad at ranking, so it is asked "
          + "only to explain."],
         ["What follows from it", "no prompt, no advisory wording and no future "
          + "model swap can inflate a priority."]
        ].forEach(function (pair) {
            var li = el("li");
            li.appendChild(el("b", null, pair[0] + ": "));
            li.appendChild(document.createTextNode(pair[1]));
            ul.appendChild(li);
        });
        who.appendChild(ul);
        card.appendChild(who);

        // --- the arithmetic ---------------------------------------------------
        var how = methodSection("How the score is calculated", false);
        how.appendChild(el("p", null,
            "Each term below is added once. The total is clamped to 0\u2013100 and "
            + "then read off the tier table."));
        var t = el("table", "rk-table rk-ai-weights");
        var h = el("tr");
        ["Signal", "Weight", "Why it is there"].forEach(function (x) {
            h.appendChild(el("th", null, x));
        });
        t.appendChild(h);
        SCORE_ROWS.forEach(function (r) {
            var tr = el("tr");
            tr.appendChild(el("td", null, r[0]));
            tr.appendChild(el("td", "rk-num rk-ai-weight", r[1]));
            tr.appendChild(el("td", "rk-dim", r[2]));
            t.appendChild(tr);
        });
        how.appendChild(t);

        var t2 = el("table", "rk-table rk-ai-tiers");
        var h2 = el("tr");
        ["Tier", "Score", "Means"].forEach(function (x) { h2.appendChild(el("th", null, x)); });
        t2.appendChild(h2);
        TIER_ROWS.forEach(function (r) {
            var tr = el("tr");
            var td = el("td");
            td.appendChild(tierBadge(r[0]));
            tr.appendChild(td);
            tr.appendChild(el("td", "rk-num", r[1]));
            tr.appendChild(el("td", "rk-dim", r[2]));
            t2.appendChild(tr);
        });
        how.appendChild(t2);
        how.appendChild(el("p", "rk-dim",
            "A row's own signals are listed under its CVE id. CVSS band and "
            + "version evidence are inputs to the score but are not stored on the "
            + "cached verdict, so they are not repeated per row: the score was "
            + "computed from them at analysis time."));
        card.appendChild(how);

        // --- confidence, which is not the score -------------------------------
        var conf = methodSection("Confidence, freshness and what is missing", false);
        conf.appendChild(el("p", null,
            "The confidence under each score is the model's own reported "
            + "confidence in its reasoning. It is deliberately not multiplied "
            + "into the score: a weak explanation of a KEV-listed, "
            + "internet-facing flaw is still that flaw."));
        conf.appendChild(el("p", "rk-dim",
            "Each row records which pass produced it and how long ago. A verdict "
            + "is re-analysed when the facts behind it move, not on a timer, so an "
            + "old timestamp on an unchanged CVE is correct rather than stale."));
        conf.appendChild(el("p", "rk-dim",
            "CVEs beyond the analysis budget are counted in the tiles above and "
            + "are absent from this table rather than shown as low priority. "
            + "Not yet analysed is not the same as not important."));
        card.appendChild(conf);

        root.appendChild(card);
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
        strip.appendChild(tile(tc.P0 || 0, "P0, patch now", "rk-ai-p0"));
        strip.appendChild(tile(tc.P1 || 0, "P1, urgent", "rk-ai-p1"));
        strip.appendChild(tile(ov.analyzed_cves || 0, "CVEs analysed"));
        strip.appendChild(tile(humanAge(ov.latest_at), "last analysis"));
        root.appendChild(strip);
        root.appendChild(el("p", "rk-dim",
            "Priorities combine Riskability's own measurements (reach, version evidence, EPSS and KEV) " +
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
                page = 0;
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
        if (cveFilter) {
            filtered = filtered.filter(function (r) { return r.cve_id === cveFilter; });
            var clear = el("button", "rk-ai-filter-btn", "showing " + cveFilter + ", clear");
            clear.type = "button";
            clear.addEventListener("click", function () {
                cveFilter = null; page = 0; render();
            });
            card.appendChild(clear);
        }

        if (!filtered.length) {
            card.appendChild(el("p", "rk-dim",
                rows.length ? "No " + tierFilter + " findings. Try another tier."
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

        var pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
        if (page > pageCount - 1) page = pageCount - 1;
        if (page < 0) page = 0;
        var start = page * pageSize;
        var pageRows = filtered.slice(start, start + pageSize);

        card.appendChild(pager(filtered.length, pageCount, start, pageRows.length));

        pageRows.forEach(function (row) {
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

            // Explain in depth, on demand, for the one row somebody stopped on.
            // The scheduled pass answers a closed schema in 400 tokens because
            // it is ranking thousands; this asks the same model to write for a
            // person, and only when a person asked. The answer is cached with
            // the verdict, so the second reader pays nothing.
            var explain = el("button", "rk-ai-explain", "Explain in depth");
            explain.type = "button";
            var out = el("div", "rk-ai-explanation");
            explain.addEventListener("click", function () {
                explain.disabled = true;
                explain.textContent = "Asking the model…";
                explainCve(row.cve_id).then(function (res) {
                    out.textContent = res.explanation || "";
                    explain.parentNode.removeChild(explain);
                }).catch(function (e) {
                    out.textContent = "Could not explain: " + e.message;
                    explain.disabled = false;
                    explain.textContent = "Try again";
                });
            });
            why.appendChild(explain);
            why.appendChild(out);
            tr.appendChild(why);
            tbl.appendChild(tr);
        });
        card.appendChild(tbl);
        if (pageCount > 1) {
            card.appendChild(pager(filtered.length, pageCount, start, pageRows.length));
        }
    }

    // One pager, rendered above the table and again below it when there is
    // more than one page. Above, because a reader needs to know how much they
    // are looking at before they start reading; below, because after twenty
    // five rows the top of the page is a long way back.
    function pager(total, pageCount, start, shown) {
        var bar = el("div", "rk-ai-pager");

        var count = el("span", "rk-ai-pager-count");
        if (total === 0) {
            count.textContent = "nothing to show";
        } else {
            count.textContent = "showing " + (start + 1) + "\u2013" + (start + shown) +
                                " of " + total + (total === 1 ? " CVE" : " CVEs");
        }
        bar.appendChild(count);

        if (pageCount > 1) {
            var nav = el("span", "rk-ai-pager-nav");
            function step(label, target, enabled, title) {
                var b = el("button", "rk-ai-pager-btn", label);
                b.type = "button";
                if (title) b.title = title;
                b.disabled = !enabled;
                if (enabled) {
                    b.addEventListener("click", function () {
                        page = target;
                        render();
                        // Back to the top of the table, not the top of the
                        // document: the chart above is context the reader
                        // already has, and re-reading it every page turn is
                        // the sort of thing that makes a pager feel broken.
                        var t = document.querySelector(".rk-ai-table");
                        if (t && t.scrollIntoView) {
                            t.scrollIntoView({block: "start", behavior: "smooth"});
                        }
                    });
                }
                return b;
            }
            nav.appendChild(step("\u00ab first", 0, page > 0, "first page"));
            nav.appendChild(step("\u2039 prev", page - 1, page > 0, "previous page"));
            nav.appendChild(el("span", "rk-ai-pager-page",
                               "page " + (page + 1) + " of " + pageCount));
            nav.appendChild(step("next \u203a", page + 1, page < pageCount - 1, "next page"));
            nav.appendChild(step("last \u00bb", pageCount - 1, page < pageCount - 1, "last page"));
            bar.appendChild(nav);
        }

        var sizes = el("span", "rk-ai-pager-size");
        sizes.appendChild(el("span", "rk-dim", "rows "));
        PAGE_SIZES.forEach(function (n) {
            var b = el("button", "rk-ai-pager-btn" +
                       (n === pageSize ? " rk-ai-pager-active" : ""), String(n));
            b.type = "button";
            b.addEventListener("click", function () {
                // Keep the reader where they are rather than where the old
                // arithmetic put them: the row at the top of the current page
                // stays at the top of the new one.
                var anchor = page * pageSize;
                pageSize = n;
                page = Math.floor(anchor / pageSize);
                render();
            });
            sizes.appendChild(b);
        });
        bar.appendChild(sizes);
        return bar;
    }
})();
