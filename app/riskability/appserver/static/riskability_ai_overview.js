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
    // Sort and text filter over the loaded verdicts, client side, on top of
    // the tier filter and the pager. Score descending is the queue's natural
    // order and stays the default; a click on a header sorts by it, a second
    // click reverses, and the filter box matches any word against the CVE,
    // title, software, vendor, action and rationale of every loaded row.
    var sortKey = "priority_score";
    var sortDir = -1;
    var textFilter = "";

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

    function explainCve(cveId, force) {
        return fetch(splunkRoot() + "/splunkd/__raw/services/riskability/ai_explain",
                     {method: "POST",
                      headers: {"Content-Type": "application/json",
                                "X-Splunk-Form-Key": csrfToken(),
                                "X-Requested-With": "XMLHttpRequest"},
                      credentials: "same-origin",
                      body: JSON.stringify({cve_id: cveId, force: force ? "1" : "0"})})
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
        if (!s || s.enabled !== true) {
            // The page's ACL keeps it out of every non-admin's navigation while
            // AI is off, so anybody who can see this is an administrator, and
            // a blank panel tells them nothing. Say what the state is and
            // where it is changed.
            hideNavItem();
            renderDisabled();
            return;
        }
        state = s;
        render();
    }).catch(function () {
        hideNavItem();
        renderUnreachable();
    });

    function notice(title, body, cls) {
        var box = el("div", "rk-status " + (cls || ""));
        box.appendChild(el("b", null, title));
        box.appendChild(el("span", null, body));
        root.textContent = "";
        root.appendChild(box);
    }

    function renderDisabled() {
        notice("AI analysis is currently switched off by an administrator.",
               "Nothing on this page runs and no data is sent to a model endpoint "
               + "while it is off. An administrator can switch it on under "
               + "Riskability Configuration, AI analysis. Priorities elsewhere in "
               + "the app are unaffected: they are computed from measured facts, "
               + "not from the model.", "rk-warn");
    }

    function renderUnreachable() {
        notice("The AI status endpoint did not answer.",
               "This page could not find out whether AI analysis is switched on. "
               + "That is a search head problem rather than a model problem: the "
               + "endpoint is local to Splunk and makes no outbound call. Reload, "
               + "and if it persists check splunkd's log for riskability_ai_status.",
               "rk-bad");
    }

    var cveFilter = null;   // set by clicking a stem in the sea chart

    // Re-rendering empties the root, which collapses the document for one
    // frame; the browser clamps the scroll position to the new, short page,
    // and the reader lands at the top every time they turn a page or change
    // the rows per page. Everything that re-renders goes through this, which
    // remembers the offset and puts it back once the new content has laid
    // out. A pager that moves the page is a pager people stop using.
    function preserveScroll(fn) {
        var y = window.scrollY || window.pageYOffset || 0;
        fn();
        window.scrollTo(0, y);
        if (window.requestAnimationFrame) {
            window.requestAnimationFrame(function () { window.scrollTo(0, y); });
        }
    }

    function render() {
        preserveScroll(renderNow);
    }

    function renderNow() {
        root.textContent = "";
        var ov = state.overview || {};
        buildSummary(ov);
        buildCoverage(ov);
        buildAnswerQuality(ov);
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
        // Sent, received, used. Written in that order because that is the
        // order a reader needs it in, and because the first question anybody
        // asks about an app that calls a model is what left the building.
        var sent = methodSection("What is sent to the model", false);
        sent.appendChild(el("p", null,
            "One request per finding. Everything the model is given about your "
            + "estate is on this list, and nothing else leaves:"));
        var ul0 = el("ul", "rk-ai-method-list");
        [["From the CVE feed", "the CVE id, the CWE id, the CVSS vector with "
          + "its base score and severity, the EPSS score, whether it is on "
          + "CISA KEV, the advisory description, and the affected product and "
          + "version."],
         ["From your inventory", "the process name, its version and path, the "
          + "ports it listens on, the asset id and its criticality, the "
          + "exposure zone, and whether the installed version matches the "
          + "affected range."],
         ["Nothing else", "no host names, no addresses, no file contents, no "
          + "user or account data, and no other finding. The model sees one "
          + "finding at a time and never the fleet."]
        ].forEach(function (pair) {
            var li = el("li");
            li.appendChild(el("b", null, pair[0] + ": "));
            li.appendChild(document.createTextNode(pair[1]));
            ul0.appendChild(li);
        });
        sent.appendChild(ul0);
        sent.appendChild(el("p", "rk-dim",
            "The model is told it has never heard of this CVE and must reason "
            + "from the vector, the CWE and the description it was given, "
            + "because in six months that will be true of most of them and a "
            + "confident sentence about a CVE it was not told about is "
            + "indistinguishable from a correct one."));
        card.appendChild(sent);

        var got = methodSection("What comes back, and how each answer is used", false);
        got.appendChild(el("p", null,
            "One JSON object per finding, against a fixed schema. This is where "
            + "each field ends up:"));
        var t3 = el("table", "rk-table rk-ai-weights");
        var h3 = el("tr");
        ["The model returns", "Where it is used"].forEach(function (x) {
            h3.appendChild(el("th", null, x));
        });
        t3.appendChild(h3);
        [["rationale", "the Why column, on this page and on every finding the "
          + "verdict is expanded to"],
         ["recommended_action", "the Action column"],
         ["recommended_mitigations", "the bullets under Why"],
         ["attck_techniques", "the ATT&CK line under Why"],
         ["confidence", "the conf figure under each score, and carried onto "
          + "each expanded finding"],
         ["priority_score, priority_tier", "not used to order anything. The "
          + "priority is computed by this app from measured facts; asking the "
          + "model to commit to a ranking is what makes its rationale worth "
          + "reading, and its answer is kept so the two can be compared"],
         ["exploitability_signal", "shown beside the CVE with severity, KEV "
          + "and EPSS. It is the one judgement here the app cannot measure "
          + "for itself"],
         ["exposure_signal, process_match_confidence", "checked against what "
          + "the app measured. They repeat facts the payload already carried, "
          + "so they are worth nothing as answers and everything as a check: "
          + "when one contradicts the measurement, that row is marked and the "
          + "rate is reported above"]
        ].forEach(function (r) {
            var tr = el("tr");
            tr.appendChild(el("td", "rk-ai-schema", r[0]));
            tr.appendChild(el("td", null, r[1]));
            t3.appendChild(tr);
        });
        got.appendChild(t3);
        got.appendChild(el("p", "rk-dim",
            "So the model writes what you read and this app decides what you "
            + "read first. That split is deliberate: no prompt, no advisory "
            + "wording and no future model swap can move a finding up the "
            + "queue."));
        card.appendChild(got);

        // Which rows the model never saw. The source is stamped on every row
        // and, until now, was printed as a bare "T0" or "T2" that the page
        // never explained: a reader looking at a T0 row believed they were
        // reading the model's reasoning when they were reading a rule.
        var src = methodSection("Not every row went to the model (T0 and T2)", false);
        src.appendChild(el("p", null,
            "Each row records which pass produced it, next to its age."));
        var ul2 = el("ul", "rk-ai-method-list");
        [["T0", "answered by deterministic rules without calling the model at "
          + "all, at both ends of the range: known-exploited and "
          + "internet-facing with the version confirmed, or low CVSS with "
          + "negligible EPSS, no KEV entry and the version confirmed NOT "
          + "affected. The rationale on a T0 row was written by this app, not "
          + "by a model. It costs nothing and cannot hallucinate."],
         ["T2", "sent to the model. Everything the rules do not settle, in "
          + "score order, until the analysis budget runs out."]
        ].forEach(function (pair) {
            var li = el("li");
            li.appendChild(el("b", null, pair[0] + ": "));
            li.appendChild(document.createTextNode(pair[1]));
            ul2.appendChild(li);
        });
        src.appendChild(ul2);
        src.appendChild(el("p", "rk-dim",
            "ATT&CK technique ids come from a small BERT classifier when an "
            + "administrator has configured one, and are asked of the model "
            + "otherwise, which is slightly less precise. Which one answered is "
            + "not recorded per row."));
        card.appendChild(src);

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

    // Markdown to DOM, for the explanation. Built with createElement and
    // textContent throughout, so nothing the model writes is ever parsed as
    // HTML: a model answer is untrusted text that happens to have structure.
    // Supports what the explain prompt produces and no more: headings,
    // paragraphs, bulleted and numbered lists, fenced code, and inline bold,
    // italic and code. Anything else renders as the literal characters, which
    // is the right failure for a security page.
    function renderMarkdown(text, into) {
        // The model returns the whole answer on one line: bold labels inline,
        // and two spaces where a paragraph break would be (measured: 3,042
        // characters, zero newlines). Runs of two or more spaces are read as
        // paragraph breaks before anything else, and a paragraph that is only
        // a bold label is rendered as a heading rather than as a one-word
        // paragraph. Fenced code is excluded from the space rule, since
        // indentation inside it is content.
        var src = String(text || "").replace(/\r\n?/g, "\n");
        if (src.indexOf("```") < 0) {
            src = src.replace(/[ \t]{2,}/g, "\n\n");
            // List items written inline: "- **Label**: text - **Label**: text"
            // and "1. **Label**: text 2. **Label**: text". Each marker that is
            // followed by a bold label starts its own line, which the list
            // rules below then pick up. Only the labelled form is split, so a
            // hyphen or a number inside ordinary prose is left alone.
            src = src.replace(/(^|[^\n])\s+-\s+(?=\*\*)/g, "$1\n- ");
            src = src.replace(/(^|[^\n])\s+(\d{1,2})[.)]\s+(?=\*\*)/g, "$1\n$2. ");
        }
        var lines = src.split("\n");
        var i = 0, para = [];

        function inline(str, parent) {
            var re = /(`[^`]+`|\*\*[^*]+\*\*|__[^_]+__|\*[^*\n]+\*|_[^_\n]+_)/g;
            var last = 0, m;
            while ((m = re.exec(str)) !== null) {
                if (m.index > last) parent.appendChild(document.createTextNode(str.slice(last, m.index)));
                var tok = m[0], node;
                if (tok[0] === "`") { node = el("code", null, tok.slice(1, -1)); }
                else if (tok.slice(0, 2) === "**" || tok.slice(0, 2) === "__") { node = el("strong", null, tok.slice(2, -2)); }
                else { node = el("em", null, tok.slice(1, -1)); }
                parent.appendChild(node);
                last = m.index + tok.length;
            }
            if (last < str.length) parent.appendChild(document.createTextNode(str.slice(last)));
        }
        function flush() {
            if (!para.length) return;
            var joined = para.join(" ");
            var label = /^\*\*([^*]{2,80})\*\*:?$/.exec(joined.trim());
            var pnode = el(label ? "h4" : "p");
            if (label) { pnode.textContent = label[1]; }
            else { inline(joined, pnode); }
            into.appendChild(pnode);
            para = [];
        }
        while (i < lines.length) {
            var line = lines[i];
            var h = /^(#{1,6})\s+(.*)$/.exec(line);
            var fence = /^```/.test(line);
            var bullet = /^\s*[-*+]\s+(.*)$/.exec(line);
            var number = /^\s*\d+[.)]\s+(.*)$/.exec(line);
            if (fence) {
                flush();
                var code = [];
                i += 1;
                while (i < lines.length && !/^```/.test(lines[i])) { code.push(lines[i]); i += 1; }
                var pre = el("pre"); pre.appendChild(el("code", null, code.join("\n")));
                into.appendChild(pre);
                i += 1; continue;
            }
            if (h) {
                flush();
                var level = Math.min(6, h[1].length + 2);   // h1 in the model's answer is an h3 on the page
                var hn = el("h" + level); inline(h[2], hn); into.appendChild(hn);
                i += 1; continue;
            }
            if (bullet || number) {
                flush();
                var list = el(number ? "ol" : "ul");
                while (i < lines.length) {
                    var b = /^\s*[-*+]\s+(.*)$/.exec(lines[i]);
                    var n = /^\s*\d+[.)]\s+(.*)$/.exec(lines[i]);
                    var item = number ? n : b;
                    if (!item) break;
                    var li = el("li"); inline(item[1], li); list.appendChild(li);
                    i += 1;
                }
                into.appendChild(list);
                continue;
            }
            if (!line.trim()) { flush(); i += 1; continue; }
            para.push(line.trim());
            i += 1;
        }
        flush();
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
            "Priorities are computed from Riskability's own measurements: reach, version evidence, " +
            "EPSS, CVSS and KEV. The model writes the reasoning you read beside each one and does " +
            "not decide the order. A tier is advice about order of work, not a measurement."));
    }

    // How often the model contradicted its own evidence. Rendered as a caption
    // under the tiles rather than as a tile of its own: it is a statement about
    // how much to trust the words on this page, which belongs next to the
    // sentence that introduces them, not competing with the counts for
    // attention.
    function buildAnswerQuality(ov) {
        var checked = Number(ov.grounding_checked || 0);
        var flagged = Number(ov.grounding_flagged || 0);
        if (!checked || !flagged) { return; }
        var pct = Math.round(flagged * 1000 / checked) / 10;
        var line = el("p", "rk-dim rk-ai-quality");
        line.appendChild(el("b", null, flagged + " of the " + checked
                            + " answers checked so far (" + pct + "%) "));
        line.appendChild(document.createTextNode(
            "contradict evidence the app measured and gave to the model. Those "
            + "rows are marked in the table. The priority is unaffected: it is "
            + "computed from the measurement, not from the answer."));
        if (checked < Number(ov.analyzed_cves || 0)) {
            line.appendChild(el("span", "rk-dim",
                " Answers written before this check existed are in neither "
                + "half of that figure, so it covers " + checked + " of "
                + ov.analyzed_cves + " analysed CVEs and grows as the fleet is "
                + "re-analysed."));
        }
        root.appendChild(line);
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

        card.appendChild(filterBox(filtered.length));
        var needle = textFilter.trim().toLowerCase();
        if (needle) {
            var words = needle.split(/\s+/);
            filtered = filtered.filter(function (r) {
                var hay = [r.cve_id, r.title, r.package, r.vendor, r.installed_version,
                           r.recommended_action, r.rationale, r.priority_tier,
                           r.exploitability_signal, r.exposure_zone]
                    .join(" ").toLowerCase();
                return words.every(function (w) { return hay.indexOf(w) >= 0; });
            });
        }
        filtered = sorted(filtered);

        if (!filtered.length) {
            card.appendChild(el("p", "rk-dim",
                needle ? "Nothing matches \u201c" + textFilter.trim() + "\u201d in this tier."
                : rows.length ? "No " + tierFilter + " findings. Try another tier."
                : "No analysis results yet. The first run happens after the queue " +
                  "search completes and the GPU server works through it."));
            return;
        }

        var tbl = el("table", "rk-table rk-ai-table");
        var head = el("tr");
        [["Tier", "priority_score"], ["Score", "priority_score"], ["CVE / Advisory", "cve_id"],
         ["Software", "package"], ["Action", "recommended_action"], ["Why", null]].forEach(function (h) {
            var th = el("th", h[1] ? "rk-ai-sortable" : null, h[0]);
            if (h[1]) {
                if (sortKey === h[1]) {
                    th.className += " rk-ai-sorted";
                    th.appendChild(el("span", "rk-ai-sort-arrow", sortDir < 0 ? " \u25be" : " \u25b4"));
                }
                th.title = "Sort by " + h[0];
                th.addEventListener("click", function () {
                    if (sortKey === h[1]) { sortDir = -sortDir; }
                    else { sortKey = h[1]; sortDir = (h[1] === "priority_score") ? -1 : 1; }
                    page = 0;
                    render();
                });
            }
            head.appendChild(th);
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
            // The model's exploitability read, shown at last. It is the one
            // judgement on this page the app cannot measure for itself, it was
            // being requested on every call, and nothing rendered it.
            if (row.exploitability_signal &&
                    row.exploitability_signal !== "none") {
                signals.push(row.exploitability_signal);
            }
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
            // Where this answer contradicts the evidence it was given. Shown
            // against the sentence it undermines rather than in a summary
            // somewhere else, because the reader who needs it is the one
            // reading that sentence right now. The rationale is still printed
            // in full: it remains the best explanation available, and a reader
            // told which part to distrust is better served than one shown a
            // blank cell.
            var ground = [].concat(row.grounding || []);
            if (ground.length) {
                var warn = el("div", "rk-ai-ungrounded");
                warn.appendChild(el("b", null, "Check this against the evidence: "));
                warn.appendChild(document.createTextNode(ground.join("; ") + "."));
                why.appendChild(warn);
            }
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
            // person, and only when a person asked. The answer is stored with
            // the verdict and shared: whoever asks first pays the model call,
            // everyone after reads the stored answer, and a re-run replaces it.
            var out = el("div", "rk-ai-explanation");
            var explain = el("button", "rk-ai-explain", "Explain in depth");
            explain.type = "button";
            var meta = el("div", "rk-dim rk-ai-explain-meta");
            var rerun = el("button", "rk-ai-explain rk-ai-rerun", "Re-run");
            rerun.type = "button";
            rerun.title = "Ask the model again and replace the saved answer";
            rerun.hidden = true;

            // A saved answer is not shown until asked for. A page of 25 rows
            // with a rendered essay under each is unreadable, so a row with a
            // saved explanation shows a green button saying one exists, and
            // the answer opens under it on click. Re-run sits beside it once
            // the answer is open.
            var shown = false;
            var saved = null;   // {text, when}

            function showAnswer() {
                out.textContent = "";
                renderMarkdown(saved.text, out);
                out.hidden = false;
                shown = true;
                meta.textContent = "saved" + (saved.when ? ", " + humanAge(saved.when) : "")
                    + ". Re-run asks the model again and replaces it.";
                explain.textContent = "Hide explanation";
                explain.className = "rk-ai-explain";
                rerun.hidden = false;
            }
            function hideAnswer() {
                out.hidden = true;
                shown = false;
                meta.textContent = "";
                explain.textContent = "Saved explanation available";
                explain.className = "rk-ai-explain rk-ai-saved";
                rerun.hidden = true;
            }
            function ask(force) {
                explain.disabled = true; rerun.disabled = true;
                explain.textContent = "Asking the model\u2026";
                explainCve(row.cve_id, force).then(function (res) {
                    saved = {text: res.explanation || "", when: res.explained_at};
                    showAnswer();
                    if (res.stored === false) {
                        meta.textContent += " This answer could not be stored, so the next reader will ask again.";
                    }
                }).catch(function (e) {
                    out.textContent = "Could not explain: " + e.message;
                    out.hidden = false;
                    explain.textContent = saved ? "Hide explanation" : "Try again";
                }).then(function () { explain.disabled = false; rerun.disabled = false; });
            }
            explain.addEventListener("click", function () {
                if (saved && shown) { hideAnswer(); }
                else if (saved) { showAnswer(); }
                else { ask(false); }
            });
            rerun.addEventListener("click", function () { ask(true); });
            if (row.explanation) {
                saved = {text: row.explanation, when: row.explained_at};
                hideAnswer();
            }
            var controls = el("div", "rk-ai-explain-controls");
            controls.appendChild(explain);
            controls.appendChild(rerun);
            why.appendChild(controls);
            why.appendChild(meta);
            why.appendChild(out);
            tr.appendChild(why);
            tbl.appendChild(tr);
        });
        // The table lives in its own scroll container. Splunk Web's header is
        // 960px wide at minimum, so below that the PAGE scrolls sideways
        // whatever this table does; above it the table must fit, and the
        // column minimums below are chosen so it does at 960. The container is
        // the backstop: if a future column pushes it wider, the table scrolls
        // inside its card and the page does not.
        var wrap = el("div", "rk-ai-table-wrap");
        wrap.appendChild(tbl);
        card.appendChild(wrap);
        if (pageCount > 1) {
            card.appendChild(pager(filtered.length, pageCount, start, pageRows.length));
        }
    }

    function sorted(rows) {
        var key = sortKey, dir = sortDir;
        var out = rows.slice();
        out.sort(function (a, b) {
            var x = a[key], y = b[key];
            if (key === "priority_score") { x = Number(x) || 0; y = Number(y) || 0; }
            else { x = String(x || "").toLowerCase(); y = String(y || "").toLowerCase(); }
            if (x < y) return -1 * dir;
            if (x > y) return 1 * dir;
            // Ties keep score order, so sorting by software still lists the
            // worst finding for that software first.
            return (Number(b.priority_score) || 0) - (Number(a.priority_score) || 0);
        });
        return out;
    }

    var filterTimer = null;
    function filterBox(total) {
        var bar = el("div", "rk-ai-filter-row");
        var input = el("input", "rk-ai-filter-input");
        input.type = "search";
        input.placeholder = "Filter these " + total + " rows: CVE, software, vendor, action, words in the reasoning";
        input.value = textFilter;
        input.setAttribute("aria-label", "Filter the table");
        // Debounced, and re-rendered without losing the caret: the whole
        // table is rebuilt on each change, so the input is recreated and
        // given back its value and focus.
        input.addEventListener("input", function () {
            var v = input.value;
            clearTimeout(filterTimer);
            filterTimer = setTimeout(function () {
                textFilter = v;
                page = 0;
                render();
                var again = document.querySelector(".rk-ai-filter-input");
                if (again) { again.focus(); again.setSelectionRange(v.length, v.length); }
            }, 180);
        });
        bar.appendChild(input);
        if (textFilter.trim()) {
            var clear = el("button", "rk-ai-pager-btn", "clear");
            clear.type = "button";
            clear.addEventListener("click", function () { textFilter = ""; page = 0; render(); });
            bar.appendChild(clear);
        }
        return bar;
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
                        // Stay exactly where the reader is. An earlier version
                        // scrolled to the table after the re-render, which read
                        // as the page jumping about, because the re-render had
                        // already thrown the position away and the scroll was
                        // a second movement on top of the first.
                        render();
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
