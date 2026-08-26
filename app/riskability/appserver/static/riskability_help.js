/*
 * Show or hide the explanatory text under each panel.
 *
 * Every panel in this app carries a caption saying what it means and, more
 * often, what it does not mean. That is the right default: the failure mode
 * these dashboards guard against is a reader who takes a calm number at face
 * value. But an operator who has read them once is reading past a paragraph on
 * every panel, which is its own kind of noise.
 *
 * The preference is stored in the browser rather than on the server. It is a
 * reading preference, not a setting: it changes nothing anyone else sees, needs
 * no capability, and should not cost a round trip on every page load. That does
 * mean it follows the browser rather than the account, so the same person on a
 * second machine starts with help on again, which for a default of "explain
 * yourself" is the right way round to be wrong.
 *
 * Deliberately not on the landing page, which is almost entirely explanation:
 * hiding it there would leave a page of headings.
 */
(function () {
    "use strict";

    var KEY = "riskability.help";
    var OFF = "rk-help-off";

    // A private window, cleared site data, or a browser set to block storage
    // all throw here rather than returning null. None of them is a reason to
    // lose the toggle, so the preference just stops persisting.
    function readPref() {
        try {
            return window.localStorage.getItem(KEY) === "off" ? "off" : "on";
        } catch (e) {
            return "on";
        }
    }

    function writePref(v) {
        try {
            window.localStorage.setItem(KEY, v);
        } catch (e) {
            /* not fatal: the toggle still works for this page view */
        }
    }

    function apply(state, button) {
        var on = state !== "off";
        document.body.classList.toggle(OFF, !on);
        if (button) {
            button.textContent = on ? "Hide the notes" : "Show the notes";
            button.setAttribute("aria-pressed", on ? "false" : "true");
            button.title = on
                ? "Hide the explanation under each panel"
                : "Show the explanation under each panel";
        }
    }

    function build() {
        if (document.querySelector(".rk-help-toggle")) { return; }

        var button = document.createElement("button");
        button.type = "button";
        button.className = "rk-help-toggle";

        var state = readPref();
        apply(state, button);

        button.addEventListener("click", function () {
            state = state === "off" ? "on" : "off";
            writePref(state);
            apply(state, button);
        });

        var bar = document.createElement("div");
        bar.className = "rk-help-bar";
        bar.appendChild(button);

        // Splunk's own header markup has moved between versions, so anchor on
        // the dashboard body and fall back to the top of the document rather
        // than depending on a class that may not be there.
        var host = document.querySelector(".dashboard-body")
                || document.querySelector(".dashboard-view-container")
                || document.body;
        host.insertBefore(bar, host.firstChild);
    }

    function start() {
        build();
        // Splunk renders rows after the document is ready, and a dashboard that
        // rebuilds its body would drop the button. Cheap to re-check.
        var tries = 0;
        var timer = setInterval(function () {
            if (!document.querySelector(".rk-help-toggle")) { build(); }
            if (++tries > 20) { clearInterval(timer); }
        }, 500);
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", start);
    } else {
        start();
    }
}());
