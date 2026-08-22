/*
 * Feed administration page.
 *
 * Talks to the app's own REST endpoint through Splunk Web's splunkd proxy. Two
 * things about that are easy to get wrong and are handled explicitly here:
 *
 *  - The proxy requires a CSRF token, taken from the splunkweb_csrf_token_<port>
 *    cookie and sent as X-Splunk-Form-Key. Without it every POST is a 401 that
 *    looks like a permissions problem.
 *  - URLs must be built relative to the Splunk root endpoint. This instance may
 *    be served under a path prefix by a reverse proxy, so anything hard-coded to
 *    start with /en-US/ breaks the moment it is.
 */
(function () {
    "use strict";

    // Everything from the server is treated as text, never as markup: advisory
    // titles and source names come from third-party feeds.
    function el(tag, className, text) {
        var node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null) node.textContent = String(text);
        return node;
    }

    // Static assets are served from the app's own namespace, and like every
    // other URL here it must be built relative to the Splunk root endpoint so
    // it survives being served under a reverse-proxy path prefix.
    function staticUrl(rel) {
        return splunkRoot() + "/static/app/riskability/" + rel;
    }

    function splunkRoot() {
        // .../app/riskability/riskability_admin -> everything before /app/
        var path = window.location.pathname;
        var i = path.indexOf("/app/");
        if (i < 0) return "";
        var base = path.slice(0, i);          // e.g. /share/<token>/en-US
        return base;
    }

    function endpoint() {
        return splunkRoot() + "/splunkd/__raw/services/riskability/feed";
    }

    function csrfToken() {
        var m = document.cookie.match(/splunkweb_csrf_token_\d+=([^;]+)/);
        return m ? decodeURIComponent(m[1]) : "";
    }

    function request(method, body) {
        var headers = { "X-Splunk-Form-Key": csrfToken(), "X-Requested-With": "XMLHttpRequest" };
        var opts = { method: method, headers: headers, credentials: "same-origin" };
        if (body !== undefined) {
            headers["Content-Type"] = "application/json";
            opts.body = JSON.stringify(body);
        }
        return fetch(endpoint(), opts).then(function (r) {
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

    function humanBytes(n) {
        if (n === null || n === undefined) return "unknown";
        var units = ["B", "KB", "MB", "GB"], i = 0;
        while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
        return (i === 0 ? n : n.toFixed(1)) + " " + units[i];
    }

    function humanAge(epochSeconds) {
        if (!epochSeconds) return "never";
        var secs = Math.floor(Date.now() / 1000) - epochSeconds;
        if (secs < 3600) return Math.max(0, Math.floor(secs / 60)) + " minutes ago";
        if (secs < 86400) return Math.floor(secs / 3600) + " hours ago";
        return Math.floor(secs / 86400) + " days ago";
    }

    function ageClass(epochSeconds) {
        if (!epochSeconds) return "rk-bad";
        var days = (Date.now() / 1000 - epochSeconds) / 86400;
        if (days > 30) return "rk-bad";
        if (days > 7) return "rk-warn";
        return "rk-good";
    }

    var root = document.getElementById("riskability-admin");
    if (!root) return;

    function render(state) {
        root.textContent = "";

        // ---- active feed ------------------------------------------------
        var feed = state.feed;
        var card = el("div", "rk-card");
        card.appendChild(el("h3", null, "Active vulnerability feed"));

        var st = state.status || {};
        if (["queued", "importing", "cleaning"].indexOf(st.state) >= 0) {
            var prog = el("div", "rk-status rk-warn");
            var loaded = st.loaded_ranges || 0, want = st.expected_ranges || 0;
            var pct = want ? Math.min(99, Math.round(loaded * 100 / want)) : 0;
            prog.appendChild(el("b", null,
                st.state === "queued"
                    ? "Queued — the feed worker starts within a minute"
                    : st.state === "cleaning"
                        ? "Import complete — removing the previous feed…"
                        : "Importing " + (st.bundle_version || "") + " — " + pct + "%"));
            prog.appendChild(el("span", null,
                " The feed below stays live and searchable until this finishes. " +
                "The import continues on the server whether or not this page is open."));
            if (want) {
                prog.appendChild(el("div", "rk-dim",
                    loaded.toLocaleString() + " of " + want.toLocaleString() + " ranges loaded"));
            }
            card.appendChild(prog);
        } else if (st.state === "failed") {
            var bad = el("div", "rk-status rk-bad");
            bad.appendChild(el("b", null, "The last import failed."));
            bad.appendChild(el("span", null,
                " " + (st.error || "") + " The previous feed is still live and intact."));
            card.appendChild(bad);
        }

        // A truncated collection must never look like a healthy feed.
        var v = state.verify;
        if (v && v.consistent === false) {
            var warn = el("div", "rk-status rk-bad");
            warn.appendChild(el("b", null, "The stored feed does not match what was imported."));
            warn.appendChild(el("span", null,
                " Searches will under-report until this is corrected. Re-import the bundle."));
            warn.appendChild(el("div", "rk-dim", v.reason || ""));
            card.appendChild(warn);
        }

        if (!feed) {
            var none = el("div", "rk-status rk-bad");
            none.appendChild(el("b", null, "No feed imported."));
            none.appendChild(el("span", null,
                " Riskability cannot report any vulnerability until a bundle is imported. " +
                "Dashboards will show zero findings, which means “no data”, not “no risk”."));
            card.appendChild(none);
        } else {
            var age = el("div", "rk-status " + ageClass(feed.imported_at));
            age.appendChild(el("b", null, "Imported " + humanAge(feed.imported_at)));
            age.appendChild(el("span", null,
                " — an offline feed is only as current as its last import, so this number " +
                "bounds how much the findings below can be trusted."));
            card.appendChild(age);

            // A bundle built while a source was unreachable is not obviously
            // different from a complete one -- it just silently lacks, say,
            // every known-exploited flag. The build host recorded what it
            // could not reach; this is the only place anyone will read it.
            if (feed.warnings && feed.warnings.length) {
                var inc = el("div", "rk-status rk-warn");
                inc.appendChild(el("b", null, "This bundle is incomplete."));
                inc.appendChild(el("span", null,
                    " The machine that built it could not reach every source, so findings "
                    + "may be missing enrichment or whole ecosystems: "
                    + feed.warnings.join("; ")
                    + ". Rebuild it on a host that can reach those sources."));
                card.appendChild(inc);
            }

            var dl = el("dl", "rk-facts");
            [["Bundle", feed.bundle_version || feed.bundle_id],
             ["Bundle id", feed.bundle_id],
             ["Imported by", feed.imported_by || "unknown"],
             ["Advisories", (feed.advisory_count || 0).toLocaleString()],
             ["Affected ranges", (feed.range_count || 0).toLocaleString()],
             ["Vendor “not affected”", (feed.notaffected_count || 0).toLocaleString()]
            ].forEach(function (pair) {
                dl.appendChild(el("dt", null, pair[0]));
                dl.appendChild(el("dd", null, pair[1]));
            });
            card.appendChild(dl);

            if (feed.sources && feed.sources.length) {
                card.appendChild(el("h4", null, "Sources in this bundle"));
                var tbl = el("table", "rk-table");
                var thead = el("tr");
                ["Source", "Records", "Fetched", "Licence"].forEach(function (h) {
                    thead.appendChild(el("th", null, h));
                });
                tbl.appendChild(thead);
                feed.sources.forEach(function (s) {
                    var tr = el("tr");
                    tr.appendChild(el("td", null, s.name));
                    tr.appendChild(el("td", "rk-num", (s.records || 0).toLocaleString()));
                    tr.appendChild(el("td", null, humanAge(s.fetched_at)));
                    tr.appendChild(el("td", "rk-licence", s.licence || ""));
                    tbl.appendChild(tr);
                });
                card.appendChild(tbl);
            }
        }
        root.appendChild(card);

        // ---- staged bundles ---------------------------------------------
        var staged = el("div", "rk-card");
        staged.appendChild(el("h3", null, "Staged bundles"));
        var dir = el("p", "rk-dim");
        dir.appendChild(document.createTextNode("Copy bundles to "));
        dir.appendChild(el("code", null, state.incoming_dir));
        dir.appendChild(document.createTextNode(" on this search head, or upload one below."));
        staged.appendChild(dir);

        if (!state.incoming || !state.incoming.length) {
            staged.appendChild(el("p", "rk-dim", "Nothing staged."));
        } else {
            state.incoming.forEach(function (item) {
                var row = el("div", "rk-staged");
                var info = el("div", "rk-staged-info");
                info.appendChild(el("div", "rk-staged-name", item.filename));
                if (item.error) {
                    info.appendChild(el("div", "rk-bad-text", "Unreadable: " + item.error));
                } else if (item.manifest) {
                    var m = item.manifest;
                    var counts = m.counts || {};
                    info.appendChild(el("div", "rk-dim",
                        humanBytes(item.size_bytes) + " · " +
                        (counts.advisories || 0).toLocaleString() + " advisories · " +
                        (counts.ranges || 0).toLocaleString() + " ranges · built " +
                        humanAge(m.created_at)));
                    info.appendChild(el("div", "rk-dim",
                        "sources: " + (m.sources || []).join(", ")));
                }
                row.appendChild(info);

                var actions = el("div", "rk-staged-actions");
                if (!item.error) {
                    var imp = el("button", "rk-btn rk-btn-primary", "Import");
                    imp.addEventListener("click", function () {
                        if (!window.confirm(
                            "Import " + item.filename + "?\n\n" +
                            "This replaces the active feed. Searches keep using the current " +
                            "feed until the import completes, and the import continues even " +
                            "if you close this page.")) return;
                        actions.textContent = "";
                        actions.appendChild(el("span", "rk-dim", "Starting…"));
                        request("POST", { action: "import", filename: item.filename })
                            .then(function () { poll(); })
                            .catch(function (e) { fail(e, actions); });
                    });
                    actions.appendChild(imp);
                }
                var del = el("button", "rk-btn", "Delete");
                del.addEventListener("click", function () {
                    if (!window.confirm("Delete the staged file " + item.filename + "?")) return;
                    request("POST", { action: "delete", filename: item.filename })
                        .then(load)
                        .catch(function (e) { fail(e, actions); });
                });
                actions.appendChild(del);
                row.appendChild(actions);
                staged.appendChild(row);
            });
        }

        // ---- upload -------------------------------------------------------
        staged.appendChild(el("h4", null, "Upload a bundle"));
        var up = el("div", "rk-upload");
        var file = el("input");
        file.type = "file";
        file.accept = ".gz,.tar.gz";
        up.appendChild(file);
        var btn = el("button", "rk-btn rk-btn-primary", "Upload");
        var msg = el("div", "rk-dim");
        btn.addEventListener("click", function () {
            var f = file.files && file.files[0];
            if (!f) { msg.textContent = "Choose a file first."; return; }
            if (f.size > 64 * 1024 * 1024) {
                msg.textContent = "That file is " + humanBytes(f.size) +
                    ". Uploads are capped at 64 MB because the whole body is held in memory; " +
                    "copy it to the staging directory instead.";
                return;
            }
            msg.textContent = "Uploading …";
            var reader = new FileReader();
            reader.onload = function () {
                var b64 = String(reader.result).split(",")[1] || "";
                request("POST", { action: "upload", filename: f.name, data: b64 })
                    .then(function () { msg.textContent = ""; load(); })
                    .catch(function (e) { msg.textContent = "Upload failed: " + e.message; });
            };
            reader.onerror = function () { msg.textContent = "Could not read that file."; };
            reader.readAsDataURL(f);
        });
        up.appendChild(btn);
        staged.appendChild(up);
        staged.appendChild(msg);
        root.appendChild(staged);

        root.appendChild(buildScriptsCard());
        root.appendChild(onlineCard(state));
    }

    // ---- build scripts --------------------------------------------------

    function buildScriptsCard() {
        var card = el("div", "rk-card");
        card.appendChild(el("h3", null, "Build a bundle on a connected machine"));
        card.appendChild(el("p", "rk-dim",
            "One archive holding the builder and a wrapper script for each platform. "
            + "Unpack it on a machine that has internet access, run the wrapper for that "
            + "platform, then bring the resulting .tar.gz back here and upload it above. "
            + "Python 3.8 or later is the only requirement, and there is nothing to install."));

        // Deliberately a single self-contained download. The page used to offer
        // build-feed.sh and build-feed.ps1 on their own, and both failed on
        // first run with "riskability-feed not found": they are wrappers around
        // a builder that nobody installing from Splunkbase had any way to get.
        var row = el("div", "rk-scripts");
        var box = el("div", "rk-script");
        var a = el("a", "rk-btn rk-btn-primary", "Download riskability-feedbuilder.zip");
        a.href = staticUrl("scripts/riskability-feedbuilder.zip");
        a.setAttribute("download", "riskability-feedbuilder.zip");
        box.appendChild(a);
        box.appendChild(el("div", "rk-dim",
            "Linux and macOS: ./build-feed.sh \u00b7 Windows: .\\build-feed.ps1"));
        row.appendChild(box);
        card.appendChild(row);

        // Spelled out rather than summarised. The wrappers take a profile, but
        // the two platforms spell it differently -- a positional flag on the
        // shell script, a named parameter in PowerShell -- and a reader who
        // guesses gets an unhelpful error rather than a hint.
        card.appendChild(el("h4", null, "Choosing what goes in the bundle"));

        var tbl = el("table", "rk-table");
        var head = el("tr");
        ["Profile", "Linux / macOS", "Windows", "What it fetches"].forEach(function (h) {
            head.appendChild(el("th", null, h));
        });
        tbl.appendChild(head);
        [["Linux (default on the .sh)",
          "./build-feed.sh",
          ".\\build-feed.ps1 -FeedProfile Linux",
          "Ubuntu, Debian, Alpine, npm, PyPI, Go, Maven, plus KEV, EPSS and the MITRE mapping"],
         ["Windows (default on the .ps1)",
          "./build-feed.sh --windows",
          ".\\build-feed.ps1",
          "The above plus NVD CPE data for 2015-2026, which is the only source that can assess Windows software"],
         ["Everything",
          "./build-feed.sh --everything",
          ".\\build-feed.ps1 -FeedProfile Everything",
          "Every distribution and ecosystem, and all NVD years. Much larger and much slower"]
        ].forEach(function (row) {
            var tr = el("tr");
            tr.appendChild(el("td", null, row[0]));
            tr.appendChild(el("td", "rk-mono", row[1]));
            tr.appendChild(el("td", "rk-mono", row[2]));
            tr.appendChild(el("td", "rk-dim", row[3]));
            tbl.appendChild(tr);
        });
        card.appendChild(tbl);

        var opts = el("div", "rk-dim");
        opts.style.marginTop = "10px";
        opts.appendChild(el("b", null, "Other options"));
        var ul = el("ul");
        [["-OutDir <path>", "PowerShell only. Where to write the bundle. Defaults to the current directory."],
         ["Driving the builder directly",
          "Both wrappers are convenience over one command. For a bundle covering only what you "
          + "run, call it yourself: python3 riskability-feed.pyz build --out feed.tar.gz "
          + "--ecosystem Ubuntu --ecosystem npm --kev --epss --mitre --nvd 2020-2026"],
         ["Listing the sources", "python3 riskability-feed.pyz sources  (add --check to query live download sizes)"]
        ].forEach(function (o) {
            var li = el("li");
            li.appendChild(el("code", null, o[0]));
            li.appendChild(document.createTextNode(" \u2014 " + o[1]));
            ul.appendChild(li);
        });
        opts.appendChild(ul);
        card.appendChild(opts);

        var note = el("div", "rk-status rk-warn");
        note.style.marginTop = "10px";
        note.appendChild(el("b", null, "Windows estates need the Windows profile."));
        note.appendChild(el("span", null,
            "Windows software is not installed by a package manager, so it carries no PURL "
            + "and only NVD's CPE data can assess it. Findings reached that way are always "
            + "reported at low confidence, because the product identity is inferred from a "
            + "display name rather than read from a package record. Trim the ecosystem list "
            + "to what your fleet actually runs: every entry is a download, and a feed you "
            + "do not need is only bulk to carry across the air gap."));
        card.appendChild(note);
        return card;
    }

    // ---- online fetch ---------------------------------------------------

    var onlineState = null;

    function onlineCard(state) {
        var card = el("div", "rk-card");
        card.appendChild(el("h3", null, "Fetch directly (needs internet access)"));
        card.appendChild(el("p", "rk-dim",
            "Riskability never reaches the network on its own. If this search head does have "
            + "outbound access, it can download and import a feed in one step instead of you "
            + "carrying a file. Nothing here is scheduled and nothing runs at install time."));

        var st = state.status || {};
        if (st.state === "fetching") {
            var prog = el("div", "rk-status rk-warn");
            prog.appendChild(el("b", null, "Fetching feeds\u2026"));
            prog.appendChild(el("span", null, " " + (st.message || "")));
            prog.appendChild(el("div", "rk-dim",
                "The current feed stays live until the download completes and imports."));
            card.appendChild(prog);
            return card;
        }

        var checkRow = el("div", "rk-upload");
        var checkBtn = el("button", "rk-btn", "Check connectivity");
        var checkMsg = el("div", "rk-dim", "");
        checkBtn.addEventListener("click", function () {
            checkMsg.textContent = "Checking\u2026";
            request("POST", { action: "online_check" }).then(function (r) {
                onlineState = r;
                checkMsg.textContent = "";
                renderReachability(card, r, checkMsg);
            }).catch(function (e) { checkMsg.textContent = "Check failed: " + e.message; });
        });
        checkRow.appendChild(checkBtn);
        card.appendChild(checkRow);
        card.appendChild(checkMsg);

        if (onlineState) {
            renderReachability(card, onlineState, checkMsg);
        } else {
            // Check once automatically on first load. Hiding the whole panel
            // behind a button meant an operator could not tell whether the
            // online path was even available without guessing that the button
            // did something -- and on an air-gapped search head the honest
            // answer ("nothing is reachable, build a bundle elsewhere") is the
            // one worth showing without being asked.
            checkMsg.textContent = "Checking which sources this search head can reach\u2026";
            request("POST", { action: "online_check" }).then(function (r) {
                onlineState = r;
                checkMsg.textContent = "";
                renderReachability(card, r, checkMsg);
            }).catch(function (e) {
                checkMsg.textContent = "Could not check connectivity: " + e.message;
            });
        }
        return card;
    }

    /* Sources that can be fetched by hand and handed to the builder. CISA in
     * particular refuses whole datacentre ranges, so a perfectly connected
     * build host can still never retrieve KEV -- and KEV is the strongest
     * prioritisation signal available offline, so being stuck on it matters
     * more than being stuck on anything else here. */
    var REMEDY = {
        kev: {
            text: "download known_exploited_vulnerabilities.json from cisa.gov " +
                  "on any machine that can reach it, then ",
            flag: "--kev-file <path>",
        },
        epss: {
            text: "download the EPSS csv or csv.gz from first.org on any " +
                  "machine that can reach it, then ",
            flag: "--epss-file <path>",
        },
    };

    function renderReachability(card, r, anchor) {
        var old = card.querySelector(".rk-reach");
        if (old) old.remove();
        var wrap = el("div", "rk-reach");

        var tbl = el("table", "rk-table");
        var head = el("tr");
        ["Source", "Reachable", "Detail"].forEach(function (h) { head.appendChild(el("th", null, h)); });
        tbl.appendChild(head);
        var any = false;
        Object.keys(r.reachable || {}).forEach(function (k) {
            var res = r.reachable[k] || {};
            // Older builds returned a bare boolean here.
            var ok = (typeof res === "object") ? !!res.ok : !!res;
            var detail = (typeof res === "object") ? (res.detail || "") : "";
            if (ok) any = true;
            var tr = el("tr");
            tr.appendChild(el("td", null, k));
            tr.appendChild(el("td", ok ? "rk-good-text" : "rk-bad-text", ok ? "yes" : "no"));
            // The reason matters: a firewall rule is fixable here, a CDN
            // blocking this IP range is not. And where the answer is "fetch it
            // by hand", say so -- a diagnosis with no remedy just tells
            // somebody they are stuck.
            var cell = el("td", "rk-dim");
            if (!ok) {
                cell.appendChild(document.createTextNode(detail));
                var fix = REMEDY[k];
                if (fix) {
                    var note = el("div", "rk-remedy");
                    note.appendChild(el("b", null, "Workaround: "));
                    note.appendChild(document.createTextNode(fix.text + "pass "));
                    note.appendChild(el("code", null, fix.flag));
                    note.appendChild(document.createTextNode(
                        " to the feed builder. The bundle then carries it exactly as if it "
                        + "had been fetched."));
                    cell.appendChild(note);
                }
            }
            tr.appendChild(cell);
            tbl.appendChild(tr);
        });
        wrap.appendChild(tbl);
        wrap.appendChild(el("div", "rk-dim",
            "Allow outbound HTTPS to: " + (r.hosts || []).join(", ")));

        if (!any) {
            var none = el("div", "rk-status rk-bad");
            none.appendChild(el("b", null, "No upstream source is reachable."));
            none.appendChild(el("span", null,
                " This search head is offline, which is the expected case. Build a bundle "
                + "elsewhere with one of the scripts above and import it."));
            wrap.appendChild(none);
            card.appendChild(wrap);
            return;
        }

        wrap.appendChild(el("h4", null, "What to fetch"));
        var picks = el("div", "rk-picks");
        var chosen = {};
        ["Ubuntu", "Debian", "Alpine", "Red Hat", "npm", "PyPI", "Go", "Maven"].forEach(function (eco) {
            var lab = el("label", "rk-pick");
            var cb = el("input");
            cb.type = "checkbox";
            cb.checked = ["Ubuntu", "Debian", "npm", "PyPI", "Go"].indexOf(eco) >= 0;
            chosen[eco] = cb;
            lab.appendChild(cb);
            lab.appendChild(document.createTextNode(" " + eco));
            picks.appendChild(lab);
        });
        wrap.appendChild(picks);

        var extras = el("div", "rk-picks");
        var nvdCb = el("input"); nvdCb.type = "checkbox";
        var nvdLab = el("label", "rk-pick");
        nvdLab.appendChild(nvdCb);
        nvdLab.appendChild(document.createTextNode(" NVD CPE data (needed for Windows)"));
        extras.appendChild(nvdLab);

        var mitreCb = el("input"); mitreCb.type = "checkbox"; mitreCb.checked = true;
        var mitreLab = el("label", "rk-pick");
        mitreLab.appendChild(mitreCb);
        mitreLab.appendChild(document.createTextNode(" MITRE ATT&CK mapping"));
        extras.appendChild(mitreLab);

        var overlayCb = el("input"); overlayCb.type = "checkbox"; overlayCb.checked = true;
        var overlayLab = el("label", "rk-pick");
        overlayLab.appendChild(overlayCb);
        overlayLab.appendChild(document.createTextNode(" KEV and EPSS"));
        extras.appendChild(overlayLab);
        wrap.appendChild(extras);

        var go = el("button", "rk-btn rk-btn-primary", "Fetch and import now");
        var goMsg = el("div", "rk-dim", "");
        go.addEventListener("click", function () {
            var ecosystems = Object.keys(chosen).filter(function (k) { return chosen[k].checked; });
            if (!window.confirm(
                "Download the selected feeds and import them?\n\n"
                + "This contacts the hosts listed above. With NVD selected it can take "
                + "several minutes. The current feed stays live until it finishes.")) return;
            goMsg.textContent = "Starting\u2026";
            request("POST", {
                action: "fetch",
                ecosystems: ecosystems,
                nvd: nvdCb.checked ? "2015-2026" : "",
                mitre: mitreCb.checked,
                kev: overlayCb.checked,
                epss: overlayCb.checked
            }).then(function () { poll(); })
              .catch(function (e) { goMsg.textContent = "Failed: " + e.message; });
        });
        wrap.appendChild(go);
        wrap.appendChild(goMsg);
        card.appendChild(wrap);
    }

    function fail(err, container) {
        var box = el("div", "rk-status rk-bad");
        box.appendChild(el("b", null, "Failed. "));
        box.appendChild(el("span", null, err.message));
        if (container) { container.textContent = ""; container.appendChild(box); }
        else { root.appendChild(box); }
    }

    // While an import runs, refresh often enough to look alive without
    // hammering an endpoint that counts KV Store rows.
    var pollTimer = null;
    function poll() {
        if (pollTimer) clearTimeout(pollTimer);
        pollTimer = setTimeout(load, 3000);
    }

    function load() {
        request("GET").then(function (state) {
            render(state);
            var st = state.status && state.status.state;
            if (["queued", "importing", "cleaning", "fetching"].indexOf(st) >= 0) poll();
        }).catch(function (err) {
            root.textContent = "";
            var box = el("div", "rk-status rk-bad");
            box.appendChild(el("b", null, "Could not read feed state. "));
            box.appendChild(el("span", null, err.message));
            box.appendChild(el("div", "rk-dim",
                "This page needs the admin_all_objects capability, and the KV Store must be " +
                "running — check 'splunk show kvstore-status' if this persists."));
            root.appendChild(box);
        });
    }

    load();
})();
