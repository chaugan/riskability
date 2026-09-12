/*
 * Executive summary: the print control.
 *
 * "Print or save as PDF" is this page, printed by the reader's own browser,
 * as an A4 landscape sheet. Nothing is generated on the server and no library
 * is bundled: Splunk's built-in Export to PDF omits every custom
 * visualization, customer search heads are air-gapped, and a browser already
 * knows how to turn a page into a PDF. The stylesheet fixes the orientation
 * and the colours; the visualization re-renders each chart in its light
 * palette and stands a PNG in front of the canvas while the print runs. This
 * script only does what neither of those can: give the file a name, stamp the
 * moment it was printed, and start the print.
 *
 * Nothing is built on load, and nothing here runs for a reader who never
 * prints. The button is static markup in the dashboard, so Splunk's re-render
 * of its token-bearing panel keeps it; a delegated click handler on the
 * document finds it whenever it exists.
 */
(function () {
    "use strict";

    var savedTitle = null;

    function pad(n) { return (n < 10 ? "0" : "") + n; }

    function stampNow() {
        var d = new Date();
        var date = d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate());
        var time = pad(d.getHours()) + ":" + pad(d.getMinutes());
        var spans = document.querySelectorAll(".rk-exec-printed");
        for (var i = 0; i < spans.length; i++) { spans[i].textContent = date + " " + time; }
        return date;
    }

    // Browsers take the suggested PDF file name from document.title. Set it
    // for the print and put it back afterwards, so the tab does not carry the
    // date for the rest of the session.
    // The three sheets. Every row before the chart row is the figures sheet
    // (banners included: they are hidden unless they matter), the chart row
    // is the second, everything after it the third. The rows are moved into
    // three sections for the duration of the print and moved back after, so
    // the stylesheet has one page break per sheet to place and nothing else.
    // Splunk keeps its references to the panels; moving them does not
    // disturb it, and the screen layout is restored before anyone sees it.
    var sheets = null;

    function buildSheets() {
        if (sheets) { return; }
        var charts = document.getElementById("rk_exec_charts");
        if (!charts || !charts.parentNode) { return; }
        var parent = charts.parentNode;
        var rows = [];
        for (var i = 0; i < parent.children.length; i++) {
            if (parent.children[i].classList.contains("dashboard-row")) { rows.push(parent.children[i]); }
        }
        var groups = [[], [], []];
        var at = 0;
        for (var j = 0; j < rows.length; j++) {
            if (rows[j] === charts) { at = 1; groups[1].push(rows[j]); at = 2; continue; }
            groups[at].push(rows[j]);
        }
        sheets = [];
        for (var g = 0; g < groups.length; g++) {
            if (!groups[g].length) { continue; }
            var section = document.createElement("section");
            section.className = "rk-sheet";
            parent.insertBefore(section, groups[g][0]);
            for (var k = 0; k < groups[g].length; k++) { section.appendChild(groups[g][k]); }
            sheets.push(section);
        }
    }

    function unbuildSheets() {
        if (!sheets) { return; }
        for (var i = 0; i < sheets.length; i++) {
            var section = sheets[i];
            while (section.firstChild) { section.parentNode.insertBefore(section.firstChild, section); }
            section.parentNode.removeChild(section);
        }
        sheets = null;
    }

    function enterPrint() {
        var date = stampNow();
        if (savedTitle === null) { savedTitle = document.title; }
        document.title = "Riskability executive summary " + date;
        document.body.classList.add("rk-exec-printing");
        try { buildSheets(); } catch (e) { }
    }

    function leavePrint() {
        if (savedTitle !== null) { document.title = savedTitle; savedTitle = null; }
        document.body.classList.remove("rk-exec-printing");
        try { unbuildSheets(); } catch (e) { }
    }

    document.addEventListener("click", function (ev) {
        var btn = ev.target && ev.target.closest ? ev.target.closest(".rk-exec-print") : null;
        if (!btn) { return; }
        ev.preventDefault();
        enterPrint();
        // beforeprint fires inside print(), which is where the visualization
        // swaps its canvases; afterprint puts everything back whether the
        // reader saved or cancelled.
        try { window.print(); } catch (e) { leavePrint(); }
    });

    // Ctrl+P without the button still gets the name and the stamp.
    window.addEventListener("beforeprint", enterPrint);
    window.addEventListener("afterprint", leavePrint);
    if (window.matchMedia) {
        var mq = window.matchMedia("print");
        var onChange = function (e) { if (e.matches) { enterPrint(); } else { leavePrint(); } };
        if (mq.addEventListener) { mq.addEventListener("change", onChange); }
        else if (mq.addListener) { mq.addListener(onChange); }
    }
}());
