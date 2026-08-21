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
         TooltipModule } from 'tabulator-tables';

import SplunkVisualizationBase from 'api/SplunkVisualizationBase';
import vizUtils from 'api/SplunkVisualizationUtils';

Tabulator.registerModule([
    SortModule, FilterModule, FormatModule, EditModule, ResizeColumnsModule,
    PageModule, DownloadModule, MenuModule, TooltipModule,
]);

var ROW_CAP = 10000;

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
};

/* Columns whose values are worth colouring. Matched case-insensitively against
 * the column title, so it survives the SPL renaming its headers. */
var COLOURED = ['confidence', 'severity', 'kev', 'status', 'authority'];

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

        if (!rows.length) {
            this._message('warn', 'Nothing to display', emptyText);
            return;
        }

        this._clear();

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
                minWidth: 90,
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

        try {
            this.table = new Tabulator(host, {
                data: tableData,
                columns: columns,
                layout: 'fitDataStretch',
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
        this.table.on('dataFiltered', function (filters, filteredRows) {
            setCount(filteredRows ? filteredRows.length : rows.length);
        });

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
                    payload['row.' + fields[i].name] = rowData['c' + i];
                }
                payload['click.name'] = cell.getColumn().getDefinition().title;
                payload['click.value'] = cell.getValue();
                self.drilldown({
                    action: SplunkVisualizationBase.FIELD_VALUE_DRILLDOWN,
                    data: payload,
                }, e);
            });
            host.classList.add('rk-grid-clickable');
        }
    },

    reflow: function () {
        // A panel initialised while hidden measures 0x0, and Tabulator's
        // virtual renderer then believes no rows are visible.
        if (this.table) {
            try { this.table.redraw(true); } catch (e) { /* not built yet */ }
        }
    },

    remove: function () {
        this._clear();
    },
});
