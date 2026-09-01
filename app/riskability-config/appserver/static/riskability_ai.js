/*
 * AI analysis administration page.
 *
 * Talks to /riskability/ai (capability riskability_ai_admin) through Splunk
 * Web's splunkd proxy, with the same CSRF and relative-URL handling as the
 * feed page: the proxy wants X-Splunk-Form-Key on every POST, and URLs are
 * built relative to the Splunk root so a reverse-proxy path prefix survives.
 *
 * One rule governs the form: the password field never receives the stored
 * secret back. The server replies with password_set only; a typed password
 * replaces the stored one on save, an empty field leaves it alone. Test
 * buttons send the typed value (or the stored one, server-side) so an admin
 * can validate a change before saving it.
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

    function endpoint() {
        return splunkRoot() + "/splunkd/__raw/services/riskability/ai";
    }

    function csrfToken() {
        var m = document.cookie.match(/splunkweb_csrf_token_\d+=([^;]+)/);
        return m ? decodeURIComponent(m[1]) : "";
    }

    function request(method, body) {
        // Bounded: a request that never answers would leave a button spinning
        // forever with no way to know whether anything happened. 180s fits
        // the slowest legal call (Test analysis on a loaded small GPU at the
        // default timeout), and an abort becomes an explicit message rather
        // than an eternal spinner.
        var controller = new AbortController();
        var timer = setTimeout(function () { controller.abort(); }, 180000);
        var headers = { "X-Splunk-Form-Key": csrfToken(), "X-Requested-With": "XMLHttpRequest" };
        var opts = { method: method, headers: headers, credentials: "same-origin",
                     signal: controller.signal };
        if (body !== undefined) {
            headers["Content-Type"] = "application/json";
            opts.body = JSON.stringify(body);
        }
        return fetch(endpoint(), opts).then(function (r) {
            clearTimeout(timer);
            return r.text().then(function (text) {
                var data;
                try { data = JSON.parse(text); } catch (e) { data = { error: text }; }
                if (!r.ok || data.error) {
                    throw new Error(data.error || ("HTTP " + r.status));
                }
                return data;
            });
        }).catch(function (err) {
            clearTimeout(timer);
            if (err && err.name === "AbortError") {
                throw new Error("no answer after 180 seconds - reload the page "
                    + "and check splunkd's health before retrying");
            }
            throw err;
        });
    }

    var root = document.getElementById("riskability-ai-admin");
    if (!root) return;

    // The fields of [connection], split by the card they render on. Every
    // entry here MUST have a matching input created in renderConnection or
    // renderHardware — formValues() reads them all, and a field listed here
    // but never rendered made Save throw "Cannot read properties of
    // undefined" before the request was even sent, freezing the button on
    // "Saving…". That mismatch is exactly what this split makes visible:
    // both loops iterate their own list, and formValues iterates the union.
    var CONNECTION_FIELDS = [
        ["endpoint_url", "Endpoint URL (OpenAI-compatible, no /v1)", "https://gpu-cve-01.internal:8000"],
        ["model", "Model name, exactly as /v1/models reports it", "foundation-sec-8b"]
    ];
    var PIPELINE_FIELDS = [
        ["request_timeout", "Request timeout (seconds)", "120"],
        ["t2_concurrency", "Concurrent bulk analyses (T2)", "8"],
        ["t2_max_tokens", "Bulk answer length, max tokens (T2)", "400"],
        ["t3_max_tokens", "Deep-reasoning answer length, max tokens (T3)", "1200"],
        ["t3_deep_threshold", "Deep-reasoning threshold (T2 score at or above)", "70"],
        ["candidate_cap", "Largest queue sent per run (findings)", "5000"]
    ];
    var ALL_FIELDS = CONNECTION_FIELDS.concat(PIPELINE_FIELDS);

    var state = null;   // the GET reply
    var form = {};      // input elements by field name

    function inputFor(name) { return form[name]; }

    function formValues() {
        var out = {};
        ALL_FIELDS.forEach(function (f) {
            out[f[0]] = inputFor(f[0]).value;
        });
        out.auth_type = form.auth_type.value;
        out.username = form.username.value;
        out.bert_url = form.bert_url.value;
        out.verify_tls = form.verify_tls.checked ? "1" : "0";
        out.trigger_command = form.trigger_command.value;
        return out;
    }

    function typedPassword() {
        return form.password.value;
    }

    function renderStatus(card) {
        var cfg = state.config;
        var on = cfg.enabled === "1";
        var st = el("div", "rk-status " + (on ? "rk-good" : "rk-warn"));
        st.appendChild(el("b", null, on
            ? "AI analysis is switched ON."
            : "AI analysis is switched off."));
        st.appendChild(el("span", null, on
            ? " The AI prioritization page is visible to users, and the candidate queue "
              + "search is scheduled. Findings metadata is sent to the endpoint below; "
              + "switching off hides the page again and stops every schedule."
            : " The user-facing app shows no AI page at all, the queue search is "
              + "disabled, and nothing leaves this instance. Configure the connection, "
              + "run the tests, then switch it on."));
        card.appendChild(st);

        var dl = el("dl", "rk-facts");
        [["Endpoint", cfg.endpoint_url || "not set"],
         ["Auth", cfg.auth_type + (cfg.auth_type === "basic" ? " (" + (cfg.username || "no username") + ")" : "")],
         ["Secret", state.password_set ? "stored in Splunk's encrypted password store" : "not set"],
         ["Model", cfg.model],
         ["Classifier (optional)", cfg.bert_url || "not configured"],
         ["TLS verification", cfg.verify_tls === "1" ? "on" : "OFF — set only for a self-signed certificate"],
         ["Queue search", state.searches["Riskability AI - generate candidate queue"]
             && !state.searches["Riskability AI - generate candidate queue"].disabled
             ? "scheduled (hourly at :50)" : "disabled"],
         ["Run health watch", state.searches["Riskability AI - results stopped arriving"]
             && !state.searches["Riskability AI - results stopped arriving"].disabled
             ? "armed (daily)" : "disabled"],
         ["Last test", cfg.last_test || "never run"]
        ].forEach(function (pair) {
            dl.appendChild(el("dt", null, pair[0]));
            dl.appendChild(el("dd", null, pair[1]));
        });
        card.appendChild(dl);
    }

    function renderConnection(card) {
        card.appendChild(el("h4", null, "Connection"));
        var cfg = state.config;

        var grid = el("div", "rk-ai-grid");

        function addText(name, label, placeholder) {
            var wrap = el("label", "rk-ai-field");
            wrap.appendChild(el("span", null, label));
            var input = el("input", "rk-input");
            input.type = "text";
            input.value = cfg[name] || "";
            input.placeholder = placeholder || "";
            input.spellcheck = false;
            form[name] = input;
            wrap.appendChild(input);
            grid.appendChild(wrap);
        }

        CONNECTION_FIELDS.forEach(function (f) { addText(f[0], f[1], f[2]); });

        var authWrap = el("label", "rk-ai-field");
        authWrap.appendChild(el("span", null, "Authentication"));
        var auth = el("select", "rk-select");
        [["none", "None"], ["bearer", "Bearer token (vLLM --api-key)"],
         ["basic", "Basic (username + password)"]].forEach(function (o) {
            var opt = el("option", null, o[1]);
            opt.value = o[0];
            if (cfg.auth_type === o[0]) opt.selected = true;
            auth.appendChild(opt);
        });
        form.auth_type = auth;
        authWrap.appendChild(auth);
        grid.appendChild(authWrap);

        addText("username", "Username (basic auth only)", "");

        var pwWrap = el("label", "rk-ai-field");
        pwWrap.appendChild(el("span", null,
            state.password_set ? "Secret (stored — type to replace)" : "Secret (API key or password)"));
        var pw = el("input", "rk-input");
        pw.type = "password";
        pw.autocomplete = "new-password";
        pw.placeholder = state.password_set ? "leave empty to keep the stored secret" : "";
        form.password = pw;
        pwWrap.appendChild(pw);
        grid.appendChild(pwWrap);

        var tlsWrap = el("label", "rk-ai-field rk-ai-check");
        var tls = el("input");
        tls.type = "checkbox";
        tls.checked = cfg.verify_tls === "1";
        form.verify_tls = tls;
        tlsWrap.appendChild(tls);
        tlsWrap.appendChild(el("span", null,
            "Verify TLS certificate (uncheck only for a self-signed certificate)"));
        grid.appendChild(tlsWrap);

        card.appendChild(grid);

        var btns = el("div", "rk-upload");
        var saveMsg = el("div", "rk-dim");

        var save = el("button", "rk-btn rk-btn-primary", "Save connection");
        save.type = "button";
        save.addEventListener("click", function () {
            save.disabled = true;
            saveMsg.textContent = "Saving…";
            var body = { action: "set", config: formValues() };
            if (typedPassword()) body.password = typedPassword();
            request("POST", body).then(function (r) {
                saveMsg.textContent = r.password_message || "Saved.";
                form.password.value = "";
                load();
            }).catch(function (e) {
                saveMsg.textContent = "Failed: " + e.message;
                save.disabled = false;
            });
        });
        btns.appendChild(save);

        var test = el("button", "rk-btn", "Test connection");
        test.type = "button";
        test.addEventListener("click", function () {
            test.disabled = true;
            saveMsg.textContent = "Testing…";
            request("POST", { action: "test_connection", config: formValues(),
                              password: typedPassword() })
                .then(function (r) {
                    test.disabled = false;
                    saveMsg.textContent = "Reachable in " + r.latency_ms + " ms. Models: " +
                        (r.models.join(", ") || "none listed");
                })
                .catch(function (e) {
                    test.disabled = false;
                    saveMsg.textContent = "Failed: " + e.message;
                });
        });
        btns.appendChild(test);

        var analyze = el("button", "rk-btn", "Test analysis");
        analyze.type = "button";
        analyze.addEventListener("click", function () {
            analyze.disabled = true;
            saveMsg.textContent = "Analyzing a synthetic finding — a small GPU card can take a minute…";
            request("POST", { action: "test_completion", config: formValues(),
                              password: typedPassword() })
                .then(function (r) {
                    analyze.disabled = false;
                    if (r.ok) {
                        var res = r.result;
                        saveMsg.textContent = "Valid result in " + r.latency_ms + " ms: " +
                            res.priority_tier + " score " + res.priority_score +
                            " (" + res.recommended_action + "). " + res.rationale;
                    } else {
                        saveMsg.textContent = "The endpoint answered but the result was rejected: " +
                            (r.validation_error || "unknown reason");
                    }
                })
                .catch(function (e) {
                    analyze.disabled = false;
                    saveMsg.textContent = "Failed: " + e.message;
                });
        });
        btns.appendChild(analyze);

        var clear = el("button", "rk-btn", "Remove stored secret");
        clear.type = "button";
        clear.addEventListener("click", function () {
            if (!window.confirm("Remove the stored secret? The pipeline cannot "
                    + "authenticate until a new one is saved.")) return;
            clear.disabled = true;
            request("POST", { action: "clear_password" }).then(load).catch(function (e) {
                clear.disabled = false;
                saveMsg.textContent = "Failed: " + e.message;
            });
        });
        btns.appendChild(clear);

        card.appendChild(btns);
        card.appendChild(saveMsg);
    }

    function renderClassifier(card) {
        card.appendChild(el("h4", null, "ATT&CK tactic classifier (optional)"));
        card.appendChild(el("p", "rk-dim",
            "A small BERT sidecar that pre-tags each finding with MITRE ATT&CK tactics "
            + "before the model reasons about it. The GPU build runs one on port 8001. "
            + "Without it the pipeline still works; the model is asked for techniques "
            + "itself, which is slightly less precise."));
        var cfg = state.config;
        var row = el("div", "rk-upload");
        var input = el("input", "rk-input");
        input.type = "text";
        input.value = cfg.bert_url || "";
        input.placeholder = "http://gpu-cve-01.internal:8001";
        input.style.minWidth = "340px";
        form.bert_url = input;
        row.appendChild(input);
        var test = el("button", "rk-btn", "Test classifier");
        test.type = "button";
        var msg = el("div", "rk-dim");
        test.addEventListener("click", function () {
            test.disabled = true;
            msg.textContent = "Testing…";
            request("POST", { action: "test_bert", config: formValues() })
                .then(function (r) {
                    test.disabled = false;
                    msg.textContent = r.ok
                        ? "Classified sample tactics: " + (r.tactics.join(", ") || "none")
                        : "Failed: " + r.error;
                })
                .catch(function (e) {
                    test.disabled = false;
                    msg.textContent = "Failed: " + e.message;
                });
        });
        row.appendChild(test);
        card.appendChild(row);
        card.appendChild(msg);
    }

    function renderHardware(card) {
        card.appendChild(el("h4", null, "Hardware profile"));
        card.appendChild(el("p", "rk-dim",
            "The pipeline is identical on every card; these numbers are how fast it runs. "
            + "A preset fills the fields and you can edit anything afterwards. The same "
            + "numbers must be set on the GPU box's orchestrator (T2_CONCURRENCY and "
            + "friends) — the save confirmation spells them out."));

        var row = el("div", "rk-upload");
        var pick = el("select", "rk-select");
        Object.keys(state.presets).forEach(function (key) {
            var opt = el("option", null, state.presets[key].label);
            opt.value = key;
            pick.appendChild(opt);
        });
        pick.value = "rtx3060";
        pick.addEventListener("change", function () {
            var preset = state.presets[pick.value];
            if (!preset) return;
            Object.keys(preset.values).forEach(function (k) {
                if (form[k]) form[k].value = preset.values[k];
            });
        });
        row.appendChild(pick);
        card.appendChild(row);

        // The pipeline numbers themselves — every PIPELINE_FIELDS entry gets
        // an input here, which is what formValues() reads on save. The preset
        // above is only a convenience that fills these; it never overrides
        // edits silently because it only runs on change.
        var grid = el("div", "rk-ai-grid");
        PIPELINE_FIELDS.forEach(function (f) {
            var wrap = el("label", "rk-ai-field");
            wrap.appendChild(el("span", null, f[1]));
            var input = el("input", "rk-input");
            input.type = "text";
            input.value = state.config[f[0]] || "";
            input.spellcheck = false;
            form[f[0]] = input;
            wrap.appendChild(input);
            grid.appendChild(wrap);
        });
        card.appendChild(grid);
    }

    function renderDispatch(card) {
        card.appendChild(el("h4", null, "Dispatch"));
        card.appendChild(el("p", "rk-dim",
            "When the candidate queue is built, Splunk runs this command to start the "
            + "analysis on the GPU box ($run_id$ is substituted). It runs as the Splunk "
            + "service account, and only an admin with the riskability_ai_admin "
            + "capability can set it."));

        var ta = el("textarea", "rk-input rk-ai-cmd");
        ta.rows = 3;
        ta.value = state.config.trigger_command || "";
        ta.placeholder = "ssh -i /opt/splunk/etc/auth/ssh/gpu_key cve-admin@gpu-cve-01 "
            + "\"sudo systemctl start cve-orchestrator@$run_id@.service\"";
        ta.spellcheck = false;
        form.trigger_command = ta;
        card.appendChild(ta);

        card.appendChild(el("p", "rk-dim",
            "Leave it empty if the GPU box polls Splunk for new queues itself — the "
            + "alert action then does nothing, by design, so a poller and a trigger "
            + "never run the same queue twice."));

        var save = el("button", "rk-btn", "Save dispatch");
        save.type = "button";
        var msg = el("div", "rk-dim");
        save.addEventListener("click", function () {
            save.disabled = true;
            msg.textContent = "Saving…";
            var cfg = formValues();
            request("POST", { action: "set", config: cfg }).then(function () {
                msg.textContent = "Saved.";
                save.disabled = false;
            }).catch(function (e) {
                msg.textContent = "Failed: " + e.message;
                save.disabled = false;
            });
        });
        card.appendChild(save);
        card.appendChild(msg);
    }

    function renderSwitch(card) {
        card.appendChild(el("h4", null, "Master switch"));
        var on = state.config.enabled === "1";
        var btn = el("button", "rk-btn rk-btn-primary",
                     on ? "Switch AI analysis OFF" : "Switch AI analysis ON");
        btn.type = "button";
        var msg = el("div", "rk-dim");
        btn.addEventListener("click", function () {
            var cfg = formValues();
            if (!on) {
                if (!cfg.endpoint_url) {
                    msg.textContent = "Set the endpoint URL and save the connection first.";
                    return;
                }
                if (!window.confirm(
                        "Switch AI analysis on?\n\n"
                        + "The candidate queue search becomes scheduled and sends open "
                        + "findings metadata (CVE ids, packages, hosts, reach and exploit "
                        + "signals) to the configured endpoint for analysis. Make sure the "
                        + "endpoint is one your organisation has approved for that data, "
                        + "and run 'Test analysis' first.")) return;
            } else if (!window.confirm(
                    "Switch AI analysis off?\n\nThe AI page disappears for every user, "
                    + "the queue search and the run-health watch are disabled, and no "
                    + "further data is sent. Existing results stay in their index.")) return;
            btn.disabled = true;
            msg.textContent = "Saving…";
            request("POST", { action: "set", config: Object.assign(cfg, { enabled: on ? "0" : "1" }) })
                .then(function (r) {
                    btn.disabled = false;
                    msg.textContent = (r.reminders || []).join(" ");
                    load();
                })
                .catch(function (e) {
                    btn.disabled = false;
                    msg.textContent = "Failed: " + e.message;
                });
        });
        card.appendChild(btn);
        card.appendChild(msg);
    }

    function renderContract(card) {
        card.appendChild(el("h4", null, "What the GPU box reads and writes"));
        var c = state.contract;
        var dl = el("dl", "rk-facts");
        [["Queue index", c.candidates_index_macro + " → " + c.candidate_sourcetype],
         ["Results index", c.prioritized_index_macro + " → " + c.prioritized_sourcetype],
         ["Alerts index", c.alerts_index_macro + " → " + c.alerts_sourcetype]
        ].forEach(function (pair) {
            dl.appendChild(el("dt", null, pair[0]));
            dl.appendChild(el("dd", null, pair[1]));
        });
        card.appendChild(dl);
        card.appendChild(el("p", "rk-dim",
            "Created by TA-riskability-ai on the indexers. The orchestrator on the GPU "
            + "box reads the queue over Splunk REST with a service account and writes "
            + "results back over HEC with a token allowed into those indexes."));
    }

    function renderHubs(card) {
        card.appendChild(el("h4", null, "No GPU box yet? Test against a hosted endpoint"));
        card.appendChild(el("p", "rk-dim",
            "The connection and tests here speak the OpenAI chat-completions dialect, so "
            + "they work unchanged against hosted inference before any hardware exists. "
            + "Set the hub's base URL, Bearer auth, and the hub's model id:"));
        var ul = el("ul", "rk-ai-hubs");
        [
            ["Hugging Face Inference Providers", "https://router.huggingface.co/v1",
             "fdtn-ai/Foundation-Sec-8B and the MITRE BERT classifier live on Hugging Face; "
             + "an HF token is the bearer secret"],
            ["OpenRouter", "https://openrouter.ai/api/v1",
             "open-weight models such as DeepSeek-R1-Distill-Qwen-7B for pipeline testing"],
            ["Together AI", "https://api.together.xyz/v1",
             "hosted Qwen and DeepSeek open-weight models"],
            ["Ollama, local", "http://127.0.0.1:11434/v1",
             "any GGUF model pulled locally — a laptop can stand in for the GPU box at "
             + "small scale"]
        ].forEach(function (hub) {
            var li = el("li");
            li.appendChild(el("b", null, hub[0] + " — "));
            li.appendChild(el("code", null, hub[1]));
            li.appendChild(document.createTextNode(" · " + hub[2]));
            ul.appendChild(li);
        });
        card.appendChild(ul);
        card.appendChild(el("p", "rk-dim",
            "A hosted model answers with its own judgement; the schema and the test "
            + "buttons are the same ones a real run uses, so everything except GPU "
            + "throughput can be validated before the hardware arrives. Remember this "
            + "sends findings metadata off-box: use synthetic or non-sensitive data "
            + "until the endpoint is approved."));
    }

    function render() {
        root.textContent = "";
        var status = el("div", "rk-card");
        status.appendChild(el("h3", null, "AI analysis pipeline"));
        renderStatus(status);
        root.appendChild(status);

        var conn = el("div", "rk-card");
        conn.appendChild(el("h3", null, "GPU connection"));
        renderConnection(conn);
        renderClassifier(conn);
        root.appendChild(conn);

        var hw = el("div", "rk-card");
        hw.appendChild(el("h3", null, "Hardware profile"));
        renderHardware(hw);
        root.appendChild(hw);

        var dispatch = el("div", "rk-card");
        dispatch.appendChild(el("h3", null, "Dispatch and schedules"));
        renderDispatch(dispatch);
        renderSwitch(dispatch);
        renderContract(dispatch);
        root.appendChild(dispatch);

        var hubs = el("div", "rk-card");
        hubs.appendChild(el("h3", null, "Testing without the GPU box"));
        renderHubs(hubs);
        root.appendChild(hubs);
    }

    function load() {
        request("GET").then(function (s) {
            state = s;
            render();
        }).catch(function (err) {
            root.textContent = "";
            var box = el("div", "rk-status rk-bad");
            box.appendChild(el("b", null, "Could not read the AI configuration. "));
            box.appendChild(el("span", null, err.message));
            box.appendChild(el("div", "rk-dim",
                "This page needs the riskability_ai_admin capability."));
            root.appendChild(box);
        });
    }

    load();
})();
