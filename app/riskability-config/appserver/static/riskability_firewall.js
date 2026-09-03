/*
 * Firewall data source settings.
 *
 * One form, three buttons. Test runs the generated edge reduction over the
 * last day and reports what it found without saving anything. Save writes the
 * settings and regenerates the macros. The state line at the top says whether
 * the pipeline is configured at all and whether the macros on this search
 * head match the settings, which is how a hand-edited macro shows up.
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
    function endpoint() { return splunkRoot() + "/splunkd/__raw/services/riskability/firewall"; }
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

    var root = document.getElementById("riskability-firewall-admin");
    if (!root) return;

    // Fields are grouped by which source mode reads them. The mode dropdown
    // shows one group at a time, so an administrator on a data model never
    // sees an index box and wonders whether to fill it in. Both groups are
    // saved regardless; the mode decides which one the macro is generated
    // from, and switching back later finds the old values still there.
    var MODE = ["mode", "Source", "Where edges come from. Index: raw events, reduced on every run. Accelerated data model: tstats over a model that is already summarised on the indexers; the right choice for a real firewall volume.", "select",
                [["index", "Index (raw events)"], ["datamodel", "Accelerated data model (tstats)"]]];
    var INDEX_FIELDS = [
        ["index", "Index", "The index holding the firewall's flow events. Empty = not configured.", "text"],
        ["sourcetype", "Sourcetype (optional)", "Restrict to one sourcetype, for example pan:traffic.", "text"],
        ["extra_filter", "Extra filter (optional)", "Search terms ANDed in, for example dvc=edge-fw-1. A filter, not a search.", "text"],
        ["src_field", "Source address field", "CIM default src_ip.", "text"],
        ["dest_field", "Destination address field", "CIM default dest_ip.", "text"],
        ["port_field", "Destination port field", "CIM default dest_port.", "text"],
        ["proto_field", "Protocol field", "CIM default transport.", "text"],
        ["action_field", "Action field", "Only permitted flows are edges. Empty skips the filter.", "text"]
    ];
    var DM_FIELDS = [
        ["datamodel", "Data model", "Must be accelerated: tstats runs summariesonly, so an unaccelerated model yields no edges rather than a slow search. CIM default Network_Traffic.", "text"],
        ["dm_object", "Dataset", "The dataset within the model. CIM default All_Traffic.", "text"],
        ["dm_src_field", "Source address field", "As the model exposes it, dataset-prefixed. CIM default All_Traffic.src.", "text"],
        ["dm_dest_field", "Destination address field", "CIM default All_Traffic.dest.", "text"],
        ["dm_port_field", "Destination port field", "CIM default All_Traffic.dest_port.", "text"],
        ["dm_proto_field", "Protocol field", "CIM default All_Traffic.transport.", "text"],
        ["dm_action_field", "Action field", "Only permitted flows are edges. Empty skips the filter. CIM default All_Traffic.action.", "text"],
        ["dm_where", "Extra WHERE (optional)", "Extra tstats WHERE terms, for example All_Traffic.dvc=\"edge-fw-1\". A filter, not a search.", "text"]
    ];
    var COMMON_FIELDS = [
        ["action_allowed", "Value meaning permitted", "For example allowed, or allow. Used by both modes.", "text"],
        ["entry_points", "Entry points", "One per line: cidr | name | constant or occasional. Only a constant entry point can produce \"not observed\". Do not declare 0.0.0.0/0 unless internal ranges really are the internet to you: containment is all a range means.", "textarea"],
        ["fresh_days", "Fresh for (days)", "An edge newer than this grades confirmed observed.", "number"],
        ["stale_days", "Feed stale after (days)", "No edge newer than this and the whole feed is stale.", "number"],
        ["identity_grace_days", "Identity grace (days)", "Widest gap in a host's hold on an address that still counts as continuous.", "number"]
    ];

    var inputs = {};

    function values() {
        var out = {};
        Object.keys(inputs).forEach(function (k) { out[k] = inputs[k].value; });
        return out;
    }

    function status(kind, title, text) {
        var box = el("div", "rk-status " + kind);
        box.appendChild(el("b", null, title));
        box.appendChild(el("span", null, text));
        return box;
    }

    function render(data) {
        root.textContent = "";
        var cfg = data.config || {};
        var macros = data.macros || {};
        var stale = Object.keys(macros).filter(function (k) { return macros[k] === false; });

        if (!data.configured) {
            root.appendChild(status("rk-warn", "Not configured.",
                "No index is named, so the network evidence pipeline reads nothing and "
                + "every grade is unknown. Fill in the source below, test it, then save."));
        } else if (stale.length) {
            root.appendChild(status("rk-bad", "The macros on this search head are not what these settings generate.",
                "Out of step: " + stale.join(", ") + ". Somebody edited a macro by hand. "
                + "Saving regenerates all five from the settings."));
        } else {
            root.appendChild(status("rk-good", "Configured.",
                (cfg.mode === "datamodel"
                    ? "Edges come from tstats over " + cfg.datamodel + "." + cfg.dm_object + " (accelerated)."
                    : "Edges are read from index " + cfg.index + (cfg.sourcetype ? ", sourcetype " + cfg.sourcetype : "") + ".")
                + " The five macros match these settings."));
        }

        function field(f, into) {
            var key = f[0], label = f[1], help = f[2], type = f[3], choices = f[4];
            var row = el("div", "rk-fw-row" + (type === "textarea" ? " rk-fw-wide" : ""));
            var lab = el("label", "rk-fw-label", label);
            var input;
            if (type === "select") {
                input = el("select", "rk-fw-input");
                choices.forEach(function (c) {
                    var o = el("option", null, c[1]); o.value = c[0]; input.appendChild(o);
                });
            } else if (type === "textarea") {
                input = el("textarea", "rk-fw-input"); input.rows = 5;
            } else {
                input = el("input", "rk-fw-input"); input.type = type;
                if (type === "number") { input.min = 1; input.max = 3650; }
            }
            input.value = cfg[key] !== undefined ? cfg[key] : "";
            input.id = "rk-fw-" + key;
            lab.htmlFor = input.id;
            inputs[key] = input;
            row.appendChild(lab);
            row.appendChild(input);
            row.appendChild(el("div", "rk-dim rk-fw-help", help));
            into.appendChild(row);
            return input;
        }

        var modeForm = el("div", "rk-fw-form");
        var modeInput = field(MODE, modeForm);
        root.appendChild(modeForm);

        var indexGroup = el("div", "rk-fw-form rk-fw-group");
        indexGroup.id = "rk-fw-group-index";
        INDEX_FIELDS.forEach(function (f) { field(f, indexGroup); });
        var dmGroup = el("div", "rk-fw-form rk-fw-group");
        dmGroup.id = "rk-fw-group-datamodel";
        DM_FIELDS.forEach(function (f) { field(f, dmGroup); });
        root.appendChild(indexGroup);
        root.appendChild(dmGroup);

        function showMode() {
            var dm = modeInput.value === "datamodel";
            indexGroup.hidden = dm;
            dmGroup.hidden = !dm;
        }
        modeInput.addEventListener("change", showMode);
        showMode();

        var common = el("div", "rk-fw-form");
        COMMON_FIELDS.forEach(function (f) { field(f, common); });
        root.appendChild(common);

        var bar = el("div", "rk-fw-actions");
        var test = el("button", "rk-fw-btn", "Test source");
        var save = el("button", "rk-fw-btn rk-fw-primary", "Save");
        test.type = "button"; save.type = "button";
        var out = el("div", "rk-fw-result");
        test.addEventListener("click", function () {
            test.disabled = true; test.textContent = "Testing…"; out.textContent = "";
            call("POST", {action: "test", config: values()}).then(function (r) {
                out.appendChild(status(r.edges ? "rk-good" : "rk-warn",
                    r.edges + " permitted edges in the last day, from " + r.sources + " sources to "
                    + r.destinations + " destinations.", r.verdict));
                var q = el("pre", "rk-fw-query", r.query);
                out.appendChild(q);
            }).catch(function (e) {
                out.appendChild(status("rk-bad", "The test could not run.", e.message));
            }).then(function () { test.disabled = false; test.textContent = "Test source"; });
        });
        save.addEventListener("click", function () {
            save.disabled = true; save.textContent = "Saving…"; out.textContent = "";
            call("POST", {action: "set", config: values()}).then(function () {
                return load();
            }).catch(function (e) {
                out.appendChild(status("rk-bad", "Not saved.", e.message));
                save.disabled = false; save.textContent = "Save";
            });
        });
        bar.appendChild(test); bar.appendChild(save);
        root.appendChild(bar);
        root.appendChild(out);
    }

    function load() {
        return call("GET").then(render).catch(function (e) {
            root.textContent = "";
            root.appendChild(status("rk-bad", "The firewall settings could not be read.", e.message));
        });
    }
    load();
})();
