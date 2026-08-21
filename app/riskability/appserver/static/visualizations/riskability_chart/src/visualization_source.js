/*
 * Riskability chart -- ECharts visualisations for the Riskability app.
 *
 * One visualization module rather than one per chart type. The chart types are
 * a closed set with a documented column contract each, not an arbitrary option
 * blob, so this is not a generic "render whatever ECharts JSON you pass" panel
 * -- that would be a platform, and this app is a correlation engine with a
 * handful of views. Sharing one module means ECharts core and zrender are
 * bundled once instead of five times, which matters when the whole thing has
 * to fit in a .spl and cross an air gap.
 *
 * Imports are deliberately granular. Pulling in 'echarts' whole costs ~1MB;
 * core plus the five charts and the components actually used is a fraction of
 * that. Anything added here has to earn its bytes.
 */
import * as echarts from 'echarts/core';
import { TreemapChart, SankeyChart, HeatmapChart, BoxplotChart, BarChart } from 'echarts/charts';
import {
    TooltipComponent,
    GridComponent,
    VisualMapComponent,
    TitleComponent,
    CalendarComponent,
    LegendComponent,
} from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';

import SplunkVisualizationBase from 'api/SplunkVisualizationBase';
import vizUtils from 'api/SplunkVisualizationUtils';

echarts.use([
    TreemapChart, SankeyChart, HeatmapChart, BoxplotChart, BarChart,
    TooltipComponent, GridComponent, VisualMapComponent, TitleComponent,
    CalendarComponent, LegendComponent, CanvasRenderer,
]);

/*
 * One palette, matching riskability_admin.css.
 *
 * ECharts ships a 'dark' theme, but it is a different greyscale and looks
 * bolted onto a Splunk dark dashboard. Semantic colours (good/warn/bad) are
 * identical in both themes because they mean severity, not brightness -- only
 * the surface colours are derived from the page, so there is no second theme
 * file to keep in step.
 */
var DARK = {
    text: '#f2f4f5',
    muted: '#9aa4ae',
    axis: '#33383f',
    tooltipBg: '#1a1d21',
};
var LIGHT = {
    text: '#24292e',
    muted: '#5c6773',
    axis: '#d5d8dc',
    tooltipBg: '#ffffff',
};
var SEMANTIC = {
    good: '#53a051',
    warn: '#f8be34',
    bad: '#dc4e41',
    info: '#708794',
};
// Cool -> hot. Used for every value ramp so a colour means the same thing on
// the matrix as it does on the treemap.
var RAMP = ['#2b3a4a', '#33566b', '#3f7d7a', '#6e9c4f', '#c9a227', '#dc4e41'];

/* The row cap Splunk applies to results handed to a visualization. A result
 * set that lands exactly on it has almost certainly been truncated, and a
 * truncated security chart is a wrong chart, not a smaller one. */
var ROW_CAP = 10000;

function theme() {
    var mode;
    try {
        mode = vizUtils.getCurrentTheme && vizUtils.getCurrentTheme();
    } catch (e) {
        mode = 'dark';
    }
    return mode === 'light' ? LIGHT : DARK;
}

function shorten(s, n) {
    s = String(s === null || s === undefined ? '' : s);
    return s.length > n ? s.slice(0, n - 1) + '\u2026' : s;
}

function escapeHtml(s) {
    return String(s === null || s === undefined ? '' : s).replace(/[&<>"']/g, function (c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
}

/*
 * Splunk hands back every value as a string, including numbers. Charts that
 * silently coerce produce a plausible picture from nonsense, so a value that
 * is not a number is treated as absent rather than as zero -- zero is a real
 * measurement here and must not be manufactured.
 */
function num(v) {
    if (v === null || v === undefined || v === '') { return null; }
    var n = Number(v);
    return isFinite(n) ? n : null;
}

/*
 * Column contracts.
 *
 * Each chart type declares the columns it needs, by position, and the panel's
 * SPL is expected to produce them in that order. Positional rather than
 * by-name because the SPL already renames fields for human-readable headers,
 * and a viz that breaks when someone improves a column label is a viz nobody
 * will maintain.
 */
var CONTRACTS = {
    treemap: ['label', 'value'],
    sankey: ['source', 'target', 'value'],
    heatmap: ['x', 'y', 'value'],
    boxplot: ['category', 'min', 'q1', 'median', 'q3', 'max'],
    bar: ['label', 'value'],
};

function buildTreemap(rows, t, config) {
    var data = [];
    for (var i = 0; i < rows.length; i++) {
        var v = num(rows[i][1]);
        if (v === null || v <= 0) { continue; }
        data.push({ name: String(rows[i][0]), value: v });
    }
    if (!data.length) { return null; }
    var max = data.reduce(function (m, d) { return Math.max(m, d.value); }, 0);
    data.forEach(function (d) {
        var idx = Math.min(RAMP.length - 1, Math.floor((d.value / max) * RAMP.length));
        d.itemStyle = { color: RAMP[idx] };
    });
    return {
        tooltip: {
            backgroundColor: t.tooltipBg, borderColor: t.axis,
            textStyle: { color: t.text },
            formatter: function (p) {
                return escapeHtml(p.name) + '<br/><b>' + p.value + '</b> ' +
                    escapeHtml(config.valueLabel || 'CVEs');
            },
        },
        series: [{
            type: 'treemap',
            roam: false,
            nodeClick: false,
            breadcrumb: { show: false },
            // The long tail is the point of using a treemap over the bar chart
            // it replaces, so small tiles are kept rather than rolled into an
            // "Other" block that hides exactly what we came to see.
            visibleMin: 0,
            label: {
                show: true, color: '#ffffff', fontSize: 11,
                overflow: 'truncate',
                formatter: function (p) { return p.name + '\n' + p.value; },
            },
            itemStyle: { borderColor: t.axis, borderWidth: 1, gapWidth: 1 },
            data: data,
        }],
    };
}

function buildSankey(rows, t, config) {
    var nodeSet = {};
    var links = [];
    for (var i = 0; i < rows.length; i++) {
        var src = String(rows[i][0] || '');
        var dst = String(rows[i][1] || '');
        var v = num(rows[i][2]);
        if (!src || !dst || v === null || v <= 0) { continue; }
        // A node named the same on both sides makes ECharts loop forever.
        if (src === dst) { continue; }
        nodeSet[src] = true;
        nodeSet[dst] = true;
        links.push({ source: src, target: dst, value: v });
    }
    if (!links.length) { return null; }
    var nodes = Object.keys(nodeSet).map(function (n) { return { name: n }; });
    return {
        tooltip: {
            trigger: 'item', backgroundColor: t.tooltipBg, borderColor: t.axis,
            textStyle: { color: t.text },
            formatter: function (p) {
                if (p.dataType === 'edge') {
                    return escapeHtml(p.data.source) + ' &#8594; ' +
                        escapeHtml(p.data.target) + '<br/><b>' + p.data.value +
                        '</b> ' + escapeHtml(config.valueLabel || 'CVEs');
                }
                return '<b>' + escapeHtml(p.name) + '</b>';
            },
        },
        series: [{
            type: 'sankey',
            data: nodes,
            links: links,
            emphasis: { focus: 'adjacency' },
            lineStyle: { color: 'gradient', opacity: 0.35 },
            itemStyle: { borderWidth: 0 },
            // Room for the right-hand labels, which are technique names and
            // run long. Without this they overflow the panel entirely.
            right: 190,
            left: 20,
            label: {
                color: t.text, fontSize: 11,
                formatter: function (p) { return shorten(p.name, 30); },
            },
        }],
    };
}

function buildHeatmap(rows, t, config) {
    var xs = [], ys = [], xi = {}, yi = {}, data = [], max = 0;
    for (var i = 0; i < rows.length; i++) {
        var x = String(rows[i][0] || ''), y = String(rows[i][1] || '');
        var v = num(rows[i][2]);
        if (!x || !y || v === null) { continue; }
        if (!(x in xi)) { xi[x] = xs.length; xs.push(x); }
        if (!(y in yi)) { yi[y] = ys.length; ys.push(y); }
        data.push([xi[x], yi[y], v]);
        if (v > max) { max = v; }
    }
    if (!data.length) { return null; }
    return {
        tooltip: {
            backgroundColor: t.tooltipBg, borderColor: t.axis,
            textStyle: { color: t.text },
            formatter: function (p) {
                return escapeHtml(ys[p.value[1]]) + '<br/>' +
                    escapeHtml(xs[p.value[0]]) + '<br/><b>' + p.value[2] +
                    '</b> ' + escapeHtml(config.valueLabel || 'CVEs');
            },
        },
        grid: { left: 140, right: 20, top: 60, bottom: 90, containLabel: false },
        xAxis: {
            type: 'category', data: xs, splitArea: { show: true },
            axisLabel: {
                color: t.muted, rotate: 40, fontSize: 10, interval: 0,
                formatter: function (v) { return shorten(v, 24); },
            },
            axisLine: { lineStyle: { color: t.axis } },
        },
        yAxis: {
            type: 'category', data: ys, splitArea: { show: true },
            axisLabel: {
                color: t.muted, fontSize: 10, width: 130, overflow: 'truncate',
                formatter: function (v) { return shorten(v, 26); },
            },
            axisLine: { lineStyle: { color: t.axis } },
        },
        visualMap: {
            min: 0, max: max || 1, calculable: true, orient: 'horizontal',
            left: 'center', bottom: 5, textStyle: { color: t.muted },
            inRange: { color: RAMP },
        },
        series: [{
            type: 'heatmap', data: data,
            label: { show: false },
            itemStyle: { borderColor: t.axis, borderWidth: 1 },
            emphasis: { itemStyle: { borderColor: t.text, borderWidth: 1 } },
        }],
    };
}

function buildBoxplot(rows, t, config) {
    var cats = [], data = [];
    for (var i = 0; i < rows.length; i++) {
        var c = String(rows[i][0] || '');
        var lo = num(rows[i][1]), q1 = num(rows[i][2]), med = num(rows[i][3]),
            q3 = num(rows[i][4]), hi = num(rows[i][5]);
        if (!c || lo === null || q1 === null || med === null || q3 === null || hi === null) {
            continue;
        }
        cats.push(c);
        data.push([lo, q1, med, q3, hi]);
    }
    if (!data.length) { return null; }
    return {
        tooltip: {
            trigger: 'item', backgroundColor: t.tooltipBg, borderColor: t.axis,
            textStyle: { color: t.text },
            formatter: function (p) {
                var v = p.value;
                return '<b>' + escapeHtml(p.name) + '</b><br/>' +
                    'max ' + v[5] + '<br/>q3 ' + v[4] + '<br/>median ' + v[3] +
                    '<br/>q1 ' + v[2] + '<br/>min ' + v[1];
            },
        },
        grid: { left: 60, right: 20, top: 20, bottom: 110, containLabel: false },
        xAxis: {
            type: 'category', data: cats,
            axisLabel: {
                color: t.muted, rotate: 35, fontSize: 10, interval: 0,
                formatter: function (v) { return shorten(v, 26); },
            },
            axisLine: { lineStyle: { color: t.axis } },
        },
        yAxis: {
            type: 'value', name: config.valueLabel || '',
            nameTextStyle: { color: t.muted },
            axisLabel: { color: t.muted, fontSize: 10 },
            splitLine: { lineStyle: { color: t.axis } },
        },
        series: [{
            type: 'boxplot', data: data,
            itemStyle: { color: '#2b3a4a', borderColor: SEMANTIC.info },
            emphasis: { itemStyle: { borderColor: t.text } },
        }],
    };
}

function buildBar(rows, t, config) {
    var cats = [], vals = [], max = 0;
    for (var i = 0; i < rows.length; i++) {
        var v = num(rows[i][1]);
        if (v === null) { continue; }
        cats.push(String(rows[i][0]));
        vals.push(v);
        if (v > max) { max = v; }
    }
    if (!cats.length) { return null; }
    return {
        tooltip: {
            trigger: 'axis', backgroundColor: t.tooltipBg, borderColor: t.axis,
            textStyle: { color: t.text },
        },
        grid: { left: 60, right: 20, top: 20, bottom: 100, containLabel: false },
        xAxis: {
            type: 'category', data: cats,
            axisLabel: { color: t.muted, rotate: 40, fontSize: 10, interval: 0 },
            axisLine: { lineStyle: { color: t.axis } },
        },
        yAxis: {
            type: 'value', name: config.valueLabel || '',
            nameTextStyle: { color: t.muted },
            axisLabel: { color: t.muted, fontSize: 10 },
            splitLine: { lineStyle: { color: t.axis } },
        },
        series: [{
            type: 'bar',
            data: vals.map(function (v) {
                var idx = Math.min(RAMP.length - 1, Math.floor((v / (max || 1)) * RAMP.length));
                return { value: v, itemStyle: { color: RAMP[idx] } };
            }),
        }],
    };
}

var BUILDERS = {
    treemap: buildTreemap,
    sankey: buildSankey,
    heatmap: buildHeatmap,
    boxplot: buildBoxplot,
    bar: buildBar,
};

export default SplunkVisualizationBase.extend({

    initialize: function () {
        SplunkVisualizationBase.prototype.initialize.apply(this, arguments);
        this.el.classList.add('riskability-chart');
        this.chart = null;
    },

    getInitialDataParams: function () {
        return {
            outputMode: SplunkVisualizationBase.ROW_MAJOR_OUTPUT_MODE,
            count: ROW_CAP,
        };
    },

    /*
     * Every panel must say what it means when it has nothing to draw.
     *
     * An empty chart on a security dashboard reads as "no risk", and on this
     * app that reading is wrong often enough to be dangerous: most CVEs carry
     * no CWE, so a technique panel can be empty while the host is thoroughly
     * vulnerable. The message is rendered into the panel rather than left to
     * Splunk's grey "No results found", which says nothing about why.
     */
    _message: function (kind, title, detail) {
        this._disposeChart();
        // Built with DOM calls rather than innerHTML. These strings are
        // already escaped on the tooltip paths, but a panel that renders
        // search-derived text is not the place to rely on that being right.
        this._clear();
        var box = document.createElement('div');
        box.className = 'rk-viz-msg rk-viz-' + kind;
        var b = document.createElement('b');
        b.textContent = title;
        var span = document.createElement('span');
        span.textContent = detail;
        box.appendChild(b);
        box.appendChild(span);
        this.el.appendChild(box);
    },

    _clear: function () {
        while (this.el.firstChild) { this.el.removeChild(this.el.firstChild); }
    },

    _disposeChart: function () {
        if (this.chart) {
            // Without this every dashboard navigation leaks a canvas and its
            // resize handler.
            this.chart.dispose();
            this.chart = null;
        }
    },

    updateView: function (data, config) {
        var chartType = this._opt(config, 'chartType') || 'treemap';
        var emptyText = this._opt(config, 'emptyText') ||
            'No rows matched. On this dashboard an empty panel means the ' +
            'mapping found nothing to show, not that there is no risk.';

        if (!data || !data.rows) { return; }

        var builder = BUILDERS[chartType];
        if (!builder) {
            this._message('bad', 'Unknown chart type "' + chartType + '"',
                'Expected one of: ' + Object.keys(BUILDERS).join(', ') + '.');
            return;
        }

        var rows = data.rows;
        if (!rows.length) {
            this._message('warn', 'Nothing to display', emptyText);
            return;
        }

        var need = CONTRACTS[chartType].length;
        if ((data.fields || []).length < need) {
            this._message('bad', 'This panel\'s search does not match the chart',
                chartType + ' needs ' + need + ' columns (' +
                CONTRACTS[chartType].join(', ') + ') but the search returned ' +
                (data.fields || []).length + '.');
            return;
        }

        var option;
        try {
            option = builder(rows, theme(), {
                valueLabel: this._opt(config, 'valueLabel'),
            });
        } catch (e) {
            this._message('bad', 'The chart could not be drawn', String(e && e.message || e));
            return;
        }

        if (!option) {
            this._message('warn', 'Nothing to display', emptyText);
            return;
        }

        this._render(option, rows.length >= ROW_CAP);
    },

    _render: function (option, truncated) {
        this._clear();

        var host = document.createElement('div');
        host.className = 'rk-viz-canvas';

        if (truncated) {
            // Splunk truncates silently. A chart drawn from the first 10,000
            // rows of a larger result set looks exactly as authoritative as a
            // complete one, so say so on the panel rather than in a log.
            var warn = document.createElement('div');
            warn.className = 'rk-viz-truncated';
            warn.textContent =
                'Showing the first ' + ROW_CAP.toLocaleString() + ' rows. The ' +
                'search returned at least this many, so this chart is ' +
                'incomplete — aggregate further in the search.';
            this.el.appendChild(warn);
        }

        this.el.appendChild(host);

        try {
            this.chart = echarts.init(host, null, { renderer: 'canvas' });
        } catch (e) {
            this._message('bad', 'The chart library failed to start', String(e && e.message || e));
            return;
        }
        // notMerge, or a previous series survives a token change and two
        // filters are drawn on top of each other.
        this.chart.setOption(option, { notMerge: true });
    },

    _opt: function (config, name) {
        return config['display.visualizations.custom.riskability.riskability_chart.' + name];
    },

    reflow: function () {
        // Panels can be initialised while hidden (a collapsed row, a tab that
        // is not open yet), where the element measures 0x0 and ECharts draws
        // nothing until told to resize.
        if (this.chart) { this.chart.resize(); }
    },

    remove: function () {
        this._disposeChart();
    },
});
