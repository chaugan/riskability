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
            button.classList.toggle("is-on", on);
            button.setAttribute("aria-checked", on ? "true" : "false");
            button.title = on
                ? "Hide the explanation under each panel"
                : "Show the explanation under each panel";
        }
    }

    function build() {
        if (document.querySelector(".rk-help-toggle")) { return; }

        // A labelled switch rather than a text button. The first version was a
        // ghost button in muted grey at the top of the page, which read as
        // decoration: nobody who did not already know it was there found it.
        // This says what it controls even when it is doing nothing.
        var button = document.createElement("button");
        button.type = "button";
        button.className = "rk-help-toggle";
        button.setAttribute("role", "switch");
        button.innerHTML =
            '<svg class="rk-help-icon" viewBox="0 0 16 16" aria-hidden="true" focusable="false">'
          + '<circle cx="8" cy="8" r="7" fill="none" stroke="currentColor" stroke-width="1.4"/>'
          + '<path d="M8 7.1v4.2" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>'
          + '<circle cx="8" cy="4.6" r="0.95" fill="currentColor"/>'
          + '</svg>'
          + '<span class="rk-help-label">Panel notes</span>'
          + '<span class="rk-help-switch"><span class="rk-help-knob"></span></span>';

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

        // Directly under the dashboard's own description, which is where the
        // page already explains itself: a control that turns the rest of the
        // explaining on and off belongs with it rather than among the filters.
        //
        // Every dashboard in this app has a description, so the first selector
        // normally wins. The filter band is kept as a fallback because Splunk's
        // header markup has moved between versions and a control that vanishes
        // is worse than one in the second-best place.
        var anchors = [
            ".dashboard-header .dashboard-description",
            ".dashboard-description",
            ".dashboard-header .description",
            ".dashboard-body .fieldset",
            ".fieldset"
        ];
        var after = null;
        for (var i = 0; i < anchors.length && !after; i++) {
            after = document.querySelector(anchors[i]);
        }
        if (after && after.parentNode) {
            after.parentNode.insertBefore(bar, after.nextSibling);
        } else {
            var host = document.querySelector(".dashboard-body")
                    || document.querySelector(".dashboard-view-container")
                    || document.body;
            host.insertBefore(bar, host.firstChild);
        }
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
