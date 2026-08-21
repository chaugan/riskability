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
                            "feed until the import completes.")) return;
                        actions.textContent = "";
                        actions.appendChild(el("span", "rk-dim", "Importing…"));
                        request("POST", { action: "import", filename: item.filename })
                            .then(load)
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
    }

    function fail(err, container) {
        var box = el("div", "rk-status rk-bad");
        box.appendChild(el("b", null, "Failed. "));
        box.appendChild(el("span", null, err.message));
        if (container) { container.textContent = ""; container.appendChild(box); }
        else { root.appendChild(box); }
    }

    function load() {
        request("GET").then(render).catch(function (err) {
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
