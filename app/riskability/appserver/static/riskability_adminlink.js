/*
 * Hide the "Admin" links unless the reader may actually follow them.
 *
 * The configuration app (riskability-config) is admin-only at the app level,
 * so for everyone else these links resolve to Splunk's 404 -- correct, but a
 * dead link is still a thing a user was shown and could not use, and it
 * advertises that an admin surface exists. This script asks splunkd, through
 * the same proxy every page here already uses, whether the current user can
 * read the feed-administration view. That one GET IS the authorisation check:
 * splunkd applies the app's own permissions, so an admin's request succeeds
 * and everyone else's does not. The links start hidden and are revealed only
 * on a yes, so a user on a slow connection sees the page without the link
 * rather than the link disappearing in front of them.
 */
(function () {
    "use strict";

    function splunkRoot() {
        var path = window.location.pathname;
        var i = path.indexOf("/app/");
        if (i < 0) return "";
        return path.slice(0, i);
    }

    var links = document.querySelectorAll(
        'a[href$="riskability-config/riskability_admin"]');
    if (!links.length) return;

    function hideAll() {
        links.forEach(function (a) { a.style.display = "none"; });
    }

    hideAll();

    fetch(splunkRoot() +
          "/splunkd/__raw/servicesNS/nobody/riskability/data/ui/views/riskability_admin",
          { credentials: "same-origin",
            headers: { "X-Requested-With": "XMLHttpRequest" } })
        .then(function (r) {
            if (r.ok) links.forEach(function (a) { a.style.display = ""; });
        })
        .catch(function () { hideAll(); });
})();
