/*
 * Riskability grid -- a Tabulator-backed table.
 *
 * A SEPARATE visualization module from riskability_chart, deliberately. They
 * share nothing at runtime, and folding a grid into the chart bundle would make
 * every treemap panel download Tabulator it never uses.
 *
 * This exists for one thing the native Splunk table cannot do: filter per
 * column, in the browser, without re-running the search. That is genuinely
 * useful on Findings, where a few thousand rows are triaged by eye.
 *
 * It is also strictly worse than the native table in ways that matter, and the
 * panel says so rather than hiding it:
 *
 *   - Filtering here narrows what is DISPLAYED. It does not narrow the search,
 *     so it cannot reach rows the search did not return, and it does not update
 *     any other panel on the dashboard.
 *   - Splunk caps the rows handed to a visualization. A filter applied to a
 *     truncated result set looks exactly as authoritative as one applied to the
 *     whole, so truncation is stated on the panel, loudly.
 *   - Splunk's PDF/print export cannot render custom visualizations at all.
 *
 * Where those matter more than per-column filtering, the native <table> is the
 * better panel and should be kept.
 */
import { Tabulator, SortModule, FilterModule, FormatModule, EditModule,
         ResizeColumnsModule, PageModule, DownloadModule, MenuModule,
         TooltipModule, InteractionModule, SelectRowModule } from 'tabulator-tables';

import SplunkVisualizationBase from 'api/SplunkVisualizationBase';
import vizUtils from 'api/SplunkVisualizationUtils';

// InteractionModule is what emits cellClick/rowClick. Without it Tabulator
// still renders and filters perfectly, and on('cellClick') simply never fires
// -- no error, no warning, just a table where clicking does nothing. That is
// how the drilldown appeared to be a Splunk problem when it was a missing
// module here.
Tabulator.registerModule([
    SortModule, FilterModule, FormatModule, EditModule, ResizeColumnsModule,
    PageModule, DownloadModule, MenuModule, TooltipModule, InteractionModule,
    SelectRowModule,
]);

var ROW_CAP = 10000;

/* A floor under fitColumns, so a table with many columns is not squeezed into
 * unreadable slivers. On Findings scrolling really is the right answer, and
 * this is what forces it.
 *
 * It is a RANGE rather than one number, because a floor is a minimum that
 * fitColumns obeys even when obeying it pushes the table past the box it sits
 * in. Five columns at 90px is 450px; a half-width Splunk panel is about 438px
 * of usable width once the vertical scrollbar is out of it, and Splunk stops
 * narrowing panels below that however small the window gets. The table then
 * overflowed by twelve pixels and grew a horizontal scrollbar under columns
 * that visibly fit, scrolling twelve pixels of nothing. That is what the
 * Coverage grid was doing at any window under about 1000px wide -- which
 * includes a 1440px screen at 150% browser zoom, so it was not an exotic case.
 *
 * So the floor is the preferred width, relaxed as far as MIN but no further,
 * to whatever an equal share of the width actually available comes to. A table
 * with few enough columns to fit is always allowed to fit; one with genuinely
 * too many still scrolls, with columns no narrower than MIN. */
var PREF_COL_WIDTH = 90;
var MIN_COL_WIDTH = 80;

function columnFloor(available, count) {
    if (!available || available < 0 || !count) { return PREF_COL_WIDTH; }
    return Math.max(MIN_COL_WIDTH,
                    Math.min(PREF_COL_WIDTH, Math.floor(available / count)));
}

/* The same semantic colours the charts use, so a "high" is the same red
 * wherever it appears. Keyed on the VALUE, not the column, because the same
 * words carry the same meaning in confidence, severity and status columns. */
var VALUE_COLOR = {
    critical: '#a4302a', high: '#dc4e41',
    medium: '#f8be34', moderate: '#f8be34',
    low: '#708794',
    informational: '#5c6773', unrated: '#5c6773', unknown: '#f8be34',
    open: '#dc4e41', mitigated: '#53a051', removed: '#708794',
    yes: '#dc4e41', true: '#dc4e41',
    // Deliberately not a severity colour. An accepted risk is not less severe
    // than it was -- somebody decided to carry it -- so it reads as a state
    // somebody put it in rather than as a level on the same scale.
    accepted: '#c98a2e',
};

/* Columns whose values are worth colouring. Matched case-insensitively against
 * the column title, so it survives the SPL renaming its headers. */
var COLOURED = ['confidence', 'severity', 'kev', 'status', 'authority', 'accepted',
                'reason', 'state'];

function isColoured(title) {
    var t = String(title || '').toLowerCase();
    for (var i = 0; i < COLOURED.length; i++) {
        if (t.indexOf(COLOURED[i]) !== -1) { return true; }
    }
    return false;
}

/* Numeric-looking columns should sort numerically, or "9" lands after "10".
 * Decided from the data rather than the header, because the SPL renames
 * headers for humans and the names are not a contract. */
function looksNumeric(rows, index) {
    var seen = 0;
    for (var i = 0; i < rows.length && seen < 25; i++) {
        var v = rows[i][index];
        if (v === null || v === undefined || v === '') { continue; }
        seen++;
        if (isNaN(Number(v))) { return false; }
    }
    return seen > 0;
}

/* A select filter is far quicker to use than free text, but only while the
 * list is short enough to scan. Above that it becomes a scrolling menu that is
 * worse than typing. */
function distinctValues(rows, index, limit) {
    var seen = {}, out = [];
    for (var i = 0; i < rows.length; i++) {
        var v = rows[i][index];
        if (v === null || v === undefined || v === '') { continue; }
        v = String(v);
        if (!(v in seen)) {
            seen[v] = true;
            out.push(v);
            if (out.length > limit) { return null; }
        }
    }
    return out.sort();
}

export default SplunkVisualizationBase.extend({

    initialize: function () {
        SplunkVisualizationBase.prototype.initialize.apply(this, arguments);
        this.el.classList.add('riskability-grid');
        this.table = null;
        this._scrolledVertically = null;
    },

    getInitialDataParams: function () {
        return {
            outputMode: SplunkVisualizationBase.ROW_MAJOR_OUTPUT_MODE,
            count: ROW_CAP,
        };
    },

    _opt: function (config, name) {
        return config['display.visualizations.custom.riskability.riskability_grid.' + name];
    },

    _clear: function () {
        if (this.table) {
            // Tabulator keeps listeners and a virtual-DOM scroll observer;
            // dropping the element alone leaks both across dashboard nav.
            try { this.table.destroy(); } catch (e) { /* already gone */ }
            this.table = null;
        }
        this._scrolledVertically = null;
        while (this.el.firstChild) { this.el.removeChild(this.el.firstChild); }
    },

    _message: function (kind, title, detail) {
        this._clear();
        var box = document.createElement('div');
        box.className = 'rk-grid-msg rk-grid-' + kind;
        var b = document.createElement('b');
        b.textContent = title;
        var span = document.createElement('span');
        span.textContent = detail;
        box.appendChild(b);
        box.appendChild(span);
        this.el.appendChild(box);
    },

    updateView: function (data, config) {
        if (!data || !data.rows || !data.fields) { return; }

        var fields = data.fields;
        var rows = data.rows;
        var emptyText = this._opt(config, 'emptyText') ||
            'No rows matched this search. On a security dashboard an empty ' +
            'table means the search found nothing, which is not the same as ' +
            'there being nothing to find.';

        // A drilldown filter is invisible from inside the table: the row count
        // changes, but nothing says why, and the reader is left inferring it
        // from data they may never have seen unfiltered. The banner says it
        // where the numbers are, not only in a chip at the top of the page.
        var note = String(this._opt(config, 'filterNote') || '').trim();

        if (!rows.length) {
            // The empty case is the one where the filter matters most. A table
            // that a drilldown emptied looks exactly like a table with nothing
            // to report, and on a vulnerability dashboard those read the same
            // and mean opposite things -- so an accumulated or unintended
            // filter gets read as "this severity is clean". Say what is applied
            // before saying there is nothing to show under it.
            this._message('warn', 'Nothing to display', note
                ? 'No rows match the filter currently applied to this panel (' + note +
                  '). Clear the filter to see everything. \u2014 ' + emptyText
                : emptyText);
            return;
        }

        this._clear();

        if (note) {
            var fb = document.createElement('div');
            fb.className = 'rk-grid-filtered';
            var lab = document.createElement('b');
            lab.textContent = 'Filtered';
            fb.appendChild(lab);
            fb.appendChild(document.createTextNode(' \u00b7 ' + note +
                ' \u00b7 this table is showing part of the data'));
            this.el.appendChild(fb);
        }

        var truncated = rows.length >= ROW_CAP;
        if (truncated) {
            var warn = document.createElement('div');
            warn.className = 'rk-grid-truncated';
            warn.textContent =
                'Showing the first ' + ROW_CAP.toLocaleString() + ' rows; the ' +
                'search returned at least this many. Column filters below apply ' +
                'only to these rows, so a filter can hide matches that exist ' +
                'beyond the cut — narrow the search itself instead.';
            this.el.appendChild(warn);
        }

        var bar = document.createElement('div');
        bar.className = 'rk-grid-bar';
        var count = document.createElement('span');
        count.className = 'rk-grid-count';
        bar.appendChild(count);

        var self = this;
        var dl = document.createElement('button');
        dl.className = 'rk-grid-btn';
        dl.type = 'button';
        // Named for what it actually does. Splunk's own export takes the whole
        // job; this takes what is loaded and filtered, which is a different
        // thing and must not be mistaken for the full result set.
        dl.textContent = 'Download shown rows (CSV)';
        dl.addEventListener('click', function () {
            if (self.table) { self.table.download('csv', 'riskability-findings.csv'); }
        });
        bar.appendChild(dl);

        var clear = document.createElement('button');
        clear.className = 'rk-grid-btn';
        clear.type = 'button';
        clear.textContent = 'Clear filters';
        clear.addEventListener('click', function () {
            if (self.table) { self.table.clearHeaderFilter(); }
        });
        bar.appendChild(clear);
        this.el.appendChild(bar);

        var host = document.createElement('div');
        host.className = 'rk-grid-host';
        this.el.appendChild(host);

        var hidden = String(this._opt(config, 'hideColumns') || '')
            .split(',').map(function (x) { return x.trim().toLowerCase(); })
            .filter(Boolean);

        // The exact floor is settled once the table exists and the holder can be
        // measured (_fitColumnFloor below); this is the starting estimate, and
        // it only has to be close.
        var visibleCount = fields.filter(function (f, i) {
            return hidden.indexOf(String(f.name).toLowerCase()) === -1;
        }).length;
        var floor = columnFloor(host.clientWidth - 2, visibleCount);

        var columns = fields.map(function (f, i) {
            var title = f.name;
            var numeric = looksNumeric(rows, i);
            var choices = numeric ? null : distinctValues(rows, i, 25);

            var col = {
                title: title,
                field: 'c' + i,
                headerFilter: choices ? 'list' : 'input',
                headerFilterPlaceholder: 'filter…',
                resizable: true,
                headerTooltip: title,
                sorter: numeric ? 'number' : 'string',
                minWidth: floor,
                headerMenu: [{
                    label: 'Hide this column',
                    action: function (e, column) { column.hide(); },
                }],
            };
            if (choices) {
                col.headerFilterParams = { values: choices, clearable: true };
                col.headerFilterFunc = '=';
            }
            if (numeric) { col.hozAlign = 'right'; }
            if (hidden.indexOf(title.toLowerCase()) !== -1) { col.visible = false; }
            if (isColoured(title)) {
                col.formatter = function (cell) {
                    var v = cell.getValue();
                    var colour = VALUE_COLOR[String(v === null ? '' : v).toLowerCase()];
                    var span = document.createElement('span');
                    span.textContent = v === null || v === undefined ? '' : v;
                    if (colour) {
                        span.className = 'rk-grid-tag';
                        span.style.color = colour;
                        span.style.borderColor = colour;
                    }
                    return span;
                };
            }
            return col;
        });

        var tableData = rows.map(function (r) {
            var o = {};
            for (var i = 0; i < r.length; i++) { o['c' + i] = r[i]; }
            return o;
        });

        var selectable = String(this._opt(config, 'selectable') || 'no') === 'yes';
        if (selectable) {
            columns.unshift({
                formatter: 'rowSelection', titleFormatter: 'rowSelection',
                hozAlign: 'center', headerSort: false, width: 42,
                cellClick: function (e, cell) { cell.getRow().toggleSelect(); },
            });
        }

        try {
            this.table = new Tabulator(host, {
                data: tableData,
                columns: columns,
                selectableRows: selectable ? true : false,
                // fitColumns, not fitDataStretch. fitDataStretch sizes to the
                // content and then stretches the last column, which overshoots
                // the panel by a few pixels on narrow tables and leaves a
                // permanent horizontal scrollbar under a two-column grid.
                // fitColumns divides the panel width instead, and minWidth
                // below still forces a scrollbar on genuinely wide tables like
                // Findings, where scrolling is the correct answer.
                layout: 'fitColumns',
                // Virtual DOM. Ten thousand rows rendered eagerly would lock
                // the tab; Tabulator only builds the visible window.
                renderVertical: 'virtual',
                height: '100%',
                placeholder: 'No rows match the filters above.',
                pagination: false,
                movableColumns: true,
            });
        } catch (e) {
            this._message('bad', 'The table could not be drawn', String(e && e.message || e));
            return;
        }

        // The visible row count is the one number that tells a reader whether
        // a filter did anything, and with a virtual renderer they cannot count
        // the rows themselves -- only ~40 exist in the DOM at any time.
        //
        // Driven off dataFiltered's own rows argument rather than
        // getDataCount(): the count is queried before Tabulator has finished
        // applying the filter, so it reports the pre-filter total and the
        // label sits there looking authoritative and wrong.
        function setCount(shown) {
            count.textContent = shown === rows.length
                ? shown.toLocaleString() + ' rows'
                : shown.toLocaleString() + ' of ' + rows.length.toLocaleString() + ' rows shown';
        }
        setCount(rows.length);

        // Redraw once the table has actually been built.
        //
        // fitColumns measures the row holder, and at construction time the
        // virtual renderer has not yet said how tall the rows will be -- so on
        // a table long enough to need a vertical scrollbar Tabulator hands out
        // the full width, the scrollbar then takes about fifteen pixels of it,
        // and the difference becomes a horizontal scrollbar under a table that
        // fits. Redrawing after the layout has settled measures the width that
        // actually exists, and is also the first point at which the column
        // floor can be fitted to it.
        this.table.on('tableBuilt', function () {
            requestAnimationFrame(function () {
                try {
                    self._fitColumnFloor();
                    self.table.redraw(true);
                    var holder = self.el.querySelector('.tabulator-tableholder');
                    self._scrolledVertically = !!holder &&
                        holder.scrollHeight > holder.clientHeight;
                } catch (e) { /* torn down */ }
            });
        });
        this.table.on('dataFiltered', function (filters, filteredRows) {
            setCount(filteredRows ? filteredRows.length : rows.length);
            // Filtering can take the vertical scrollbar away, or bring it back,
            // and that changes the width fitColumns had to divide by fifteen
            // pixels. Tabulator does not re-run the layout for a filter, so the
            // columns keep the width they were given and leave a strip of empty
            // panel beside them -- or, the other way round, spill over the edge.
            // Only redraw when the scrollbar actually changed state: a full
            // redraw on every keystroke of a header filter is not free with ten
            // thousand rows behind it.
            requestAnimationFrame(function () { self._resyncWidth(); });
        });

        // Selection is published as a DOM event rather than handled here.
        //
        // The page that owns the action owns the button: this component is on
        // five dashboards and only one of them can accept a risk. Emitting an
        // event lets that page listen without every other panel growing a
        // control it must not have. Column names travel with it so the
        // listener is not guessing at positions.
        if (selectable) {
            var emit = function () {
                var picked = self.table.getSelectedData().map(function (d) {
                    var o = {};
                    for (var i = 0; i < fields.length; i++) { o[fields[i].name] = d['c' + i]; }
                    return o;
                });
                // Column names travel with EVERY event, including the empty
                // one. A page with two selectable grids has to know which of
                // them just cleared, and an empty row list says nothing about
                // where it came from -- so deselecting left the other grid's
                // buttons armed and its summary on screen.
                self.el.dispatchEvent(new CustomEvent('riskability-grid-selection', {
                    bubbles: true,
                    detail: {
                        rows: picked,
                        columns: fields.map(function (f) { return f.name; }),
                    },
                }));
            };
            this.table.on('rowSelectionChanged', emit);
        }

        // Drilldown, so <drilldown> blocks in Simple XML keep working.
        //
        // This is the main thing a custom table gives up against the native
        // one, and two panels depend on it: Overview links a host into the
        // Hosts dashboard, and the MITRE summary opens attack.mitre.org. Token
        // names mirror Splunk's own table -- row.<Column> for every column of
        // the clicked row, plus click.name / click.value for the cell -- so the
        // existing $row.hostname$ and $row.Technique$ references resolve
        // unchanged.
        if (String(this._opt(config, 'drilldown') || 'enabled') !== 'disabled') {
            this.table.on('cellClick', function (e, cell) {
                var rowData = cell.getRow().getData();
                var payload = {};
                for (var i = 0; i < fields.length; i++) {
                    var v = rowData['c' + i];
                    // The BARE field name is the one that works: Splunk adds
                    // the row. prefix itself, so a payload keyed on
                    // "row.hostname" leaves $row.hostname$ in the URL
                    // unsubstituted. The prefixed copy is kept alongside it
                    // because it costs nothing and the framework's handling of
                    // this is undocumented enough to be worth not relying on.
                    payload[fields[i].name] = v;
                    payload['row.' + fields[i].name] = v;
                }
                payload['click.name'] = cell.getColumn().getDefinition().title;
                payload['click.value'] = cell.getValue();
                payload['name'] = payload['click.name'];
                payload['value'] = payload['click.value'];
                self.drilldown({
                    action: SplunkVisualizationBase.FIELD_VALUE_DRILLDOWN,
                    data: payload,
                }, e);
            });
            host.classList.add('rk-grid-clickable');
        }
    },

    /* Redraw only if the vertical scrollbar has appeared or disappeared since
     * the last layout, because that is the only thing that silently changes the
     * width the columns were fitted to. */
    _resyncWidth: function () {
        if (!this.table) { return; }
        var holder = this.el.querySelector('.tabulator-tableholder');
        if (!holder) { return; }
        var scrolls = holder.scrollHeight > holder.clientHeight;
        if (scrolls === this._scrolledVertically) { return; }
        this._scrolledVertically = scrolls;
        try {
            this._fitColumnFloor();
            this.table.redraw(true);
        } catch (e) { /* torn down */ }
    },

    /* Re-fit the per-column floor to the width the table actually has.
     *
     * minWidth is a column property, not a layout-time calculation, so it has
     * to be recomputed whenever the panel changes width -- a browser resize, a
     * zoom change, Splunk reflowing the dashboard. Left at the width it was
     * built for, a table that fitted at 1440px overflows by a few pixels at
     * 960px and grows the same pointless scrollbar. */
    _fitColumnFloor: function () {
        if (!this.table) { return; }
        var holder = this.el.querySelector('.tabulator-tableholder');
        if (!holder || !holder.clientWidth) { return; }

        var flex = [], fixed = 0;
        this.table.getColumns().forEach(function (c) {
            if (!c.isVisible()) { return; }
            var def = c.getDefinition() || {};
            // A column with a declared width (the selection checkbox) does not
            // take a share of what is left; it takes its width off the top.
            if (def.width) { fixed += parseInt(def.width, 10) || 0; }
            else { flex.push(c); }
        });
        if (!flex.length) { return; }

        var want = columnFloor(holder.clientWidth - fixed, flex.length);
        flex.forEach(function (c) {
            var col = c._getSelf ? c._getSelf() : null;
            if (col && col.minWidth !== want) { col.setMinWidth(want); }
        });
    },

    reflow: function () {
        // A panel initialised while hidden measures 0x0, and Tabulator's
        // virtual renderer then believes no rows are visible.
        if (this.table) {
            try {
                this._fitColumnFloor();
                this.table.redraw(true);
                var holder = this.el.querySelector('.tabulator-tableholder');
                this._scrolledVertically = !!holder &&
                    holder.scrollHeight > holder.clientHeight;
            } catch (e) { /* not built yet */ }
        }
    },

    remove: function () {
        this._clear();
    },
});
