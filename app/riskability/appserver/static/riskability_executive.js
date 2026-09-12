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
    // The running footer is a page margin box, which is the only thing that
    // repeats cleanly on every sheet (a fixed element under a zoomed page
    // lands in the wrong place on the second sheet). A margin box cannot
    // read the page, so its text is written into a stylesheet here, from
    // the hidden footer element the dashboard's tokens have already filled.
    function setFooter() {
        var src = document.querySelector(".rk-exec-foot");
        if (!src) { return; }
        var text = (src.textContent || "").replace(/\s+/g, " ").trim();
        var style = document.getElementById("rk-exec-page-footer");
        if (!style) {
            style = document.createElement("style");
            style.id = "rk-exec-page-footer";
            document.head.appendChild(style);
        }
        style.textContent = '@page { @bottom-left { content: "' + text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')
            + '"; font-size: 7.5pt; color: #5c6773; width: 85%; } }';
    }

    function enterPrint() {
        var date = stampNow();
        setFooter();
        if (savedTitle === null) { savedTitle = document.title; }
        document.title = "Riskability executive summary " + date;
        document.body.classList.add("rk-exec-printing");
    }

    function leavePrint() {
        if (savedTitle !== null) { document.title = savedTitle; savedTitle = null; }
        document.body.classList.remove("rk-exec-printing");
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
