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
import { TreemapChart, SankeyChart, HeatmapChart, BoxplotChart, BarChart,
         PieChart, LineChart, GraphChart } from 'echarts/charts';
import {
    TooltipComponent,
    GridComponent,
    VisualMapComponent,
    TitleComponent,
    LegendComponent,
} from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';

import SplunkVisualizationBase from 'api/SplunkVisualizationBase';
import vizUtils from 'api/SplunkVisualizationUtils';

echarts.use([
    TreemapChart, SankeyChart, HeatmapChart, BoxplotChart, BarChart,
    PieChart, LineChart, GraphChart,
    TooltipComponent, GridComponent, VisualMapComponent, TitleComponent,
    LegendComponent, CanvasRenderer,
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
/* Which of a click's identifying values map to which contract column.
 * A drilldown that reports "category" is useless to a dashboard; one that
 * reports "technique_name" can set a token. */
var CLICK_FIELDS = {
    treemap: ['label'],
    donut: ['label'],
    bar: ['label'],
    stackedbar: ['category', 'series'],
    stackedcolumn: ['category', 'series'],
    heatmap: ['x', 'y'],
    boxplot: ['category'],
    sankey: ['source', 'target'],
    line: ['x'],
    prioritymatrix: ['x', 'y'],
    chaingraph: ['node', 'node_kind'],
    kevbridge: ['technique', 'reach'],
};

var CONTRACTS = {
    treemap: ['label', 'value'],
    sankey: ['source', 'target', 'value'],
    heatmap: ['x', 'y', 'value'],
    boxplot: ['category', 'min', 'q1', 'median', 'q3', 'max'],
    bar: ['label', 'value'],
    stackedbar: ['category', 'series', 'value'],
    stackedcolumn: ['category', 'series', 'value'],
    line: ['x', 'value'],
    donut: ['label', 'value'],
    // x = how likely the world is to exploit it, y = whether this copy answers
    // the network, value = findings, tier = what to do about it.
    prioritymatrix: ['x', 'y', 'value', 'tier'],
    chaingraph: ['source', 'source_kind', 'target', 'target_kind', 'value'],
    // technique on the long Y axis, reach class on the fixed X axis, value =
    // known-exploited CVEs in that cell. tier colours the cell by reach so one
    // internet-facing finding is drawn exactly as loud as a thousand loopback
    // ones. comment is optional and read only into the tooltip.
    kevbridge: ['technique', 'reach', 'value', 'tier', 'comment'],
};

/* Fixed colours for the values that carry meaning rather than magnitude.
 * Confidence and severity are ordered scales, and an ordered scale drawn in
 * an arbitrary palette invites the reader to compare the wrong things. */
var CATEGORY_COLOR = {
    // critical and high must not share a colour: severity is an ordered scale,
    // and two bands drawn identically read as one band twice the size.
    critical: '#a4302a', high: '#dc4e41',
    medium: '#f8be34', moderate: '#f8be34',
    low: '#708794',
    informational: '#5c6773', unrated: '#5c6773', unknown: '#5c6773',
    open: '#dc4e41', mitigated: '#53a051', removed: '#708794',
    // Reachability. Nothing here is green: green means fixed, and none of these
    // mean fixed. The calmest is a cool teal that reads as "later", not "fine".
    'answers any address': '#a4302a', 'answers one address': '#dc4e41',
    'loopback only': '#f8be34', 'no listening port': '#3f7d7a',
    'not assessed': '#6b5a2a',
    // Container lifecycle. Stopped is grey for parked, never green: a stopped
    // container is one docker start from being a running one.
    '1. running and published': '#a4302a',
    '2. running, not published': '#dc4e41',
    '4. stopped, still vulnerable': '#708794',
};

/* What to do about a cell, as opposed to how big it is.
 *
 * The priority matrix colours by TIER rather than by magnitude, and that
 * inversion is the whole point of it. Colouring by count would paint the
 * known-exploited-and-answering-the-internet cell the palest colour on the
 * panel, because it holds the smallest number. */
var TIER = {
    'act-now':      { fill: '#a4302a', text: '#ffffff' },
    'act-soon':     { fill: '#dc4e41', text: '#ffffff' },
    'plan':         { fill: '#f8be34', text: '#1a1d21' },
    'watch':        { fill: '#3f7d7a', text: '#f2f4f5' },
    'unknown-risk': { fill: '#6b5a2a', text: '#f8be34', dashed: true },
};
function categoryColor(name, fallback) {
    return CATEGORY_COLOR[String(name).toLowerCase()] || fallback;
}

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
        animation: false,
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
        animation: false,
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
        animation: false,
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
            type: 'category', data: xs,
            // No split area on this axis. ECharts draws split areas as
            // alternating translucent bands, and with both axes drawing them
            // the two overlays multiply into a chequerboard of four
            // intensities -- with the top-left cell, where both bands are at
            // their most transparent, showing bare background. On a sparse
            // matrix, where most cells carry no data and nothing is painted
            // over the bands, that corner reads as a hole in the grid.
            splitArea: { show: false },
            axisLabel: {
                color: t.muted, rotate: 40, fontSize: 10, interval: 0,
                formatter: function (v) { return shorten(v, 24); },
            },
            axisLine: { lineStyle: { color: t.axis } },
        },
        yAxis: {
            type: 'category', data: ys,
            // Row striping only, and in this theme's own colours. The default
            // band colours are light greys meant for a light background, which
            // on this theme lift the whole plot area away from the panel it
            // sits in.
            splitArea: {
                show: true,
                areaStyle: { color: [t.tooltipBg, 'rgba(0,0,0,0)'] },
            },
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

/* EPSS bands, on FIRST's own absolute scale rather than stretched across
 * whatever this fleet happens to have.
 *
 * A relative ramp would always produce a full spectrum -- the worst thing
 * present would glow red even if it were a 0.4% chance of exploitation -- and
 * on a security dashboard that manufactures alarm out of arithmetic. These
 * thresholds mean the same thing on every install, so a pale chart is a real
 * statement: nothing here is especially likely to be exploited.
 */
function epssBand(v) {
    if (v === null) { return { color: '#2b3a4a', label: 'unscored' }; }
    if (v >= 0.5) { return { color: '#dc4e41', label: '50%+ chance' }; }
    if (v >= 0.1) { return { color: '#f8be34', label: '10-50%' }; }
    if (v >= 0.01) { return { color: '#6e9c4f', label: '1-10%' }; }
    return { color: '#3f7d7a', label: 'under 1%' };
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
        // Coloured by the WHISKER TOP, not the median: the question a reader
        // brings to this panel is "does anything behind this technique look
        // likely to be exploited", and that is the worst CVE in the group. The
        // box still shows whether the group as a whole is hot or whether it is
        // one outlier.
        var band = epssBand(hi);
        data.push({
            value: [lo, q1, med, q3, hi],
            itemStyle: {
                color: band.color + '33',
                borderColor: band.color,
                borderWidth: 1.5,
            },
        });
    }
    if (!data.length) { return null; }
    return {
        animation: false,
        tooltip: {
            trigger: 'item', backgroundColor: t.tooltipBg, borderColor: t.axis,
            textStyle: { color: t.text },
            formatter: function (p) {
                // p.value carries the category at index 0, so the five numbers
                // start at 1.
                var v = p.value;
                var band = epssBand(v[5]);
                return '<b>' + escapeHtml(p.name) + '</b><br/>' +
                    '<span style="color:' + band.color + '">most likely: ' +
                    band.label + '</span><br/>' +
                    'max ' + v[5] + '<br/>q3 ' + v[4] + '<br/>median ' + v[3] +
                    '<br/>q1 ' + v[2] + '<br/>min ' + v[1];
            },
        },
        // containLabel lets ECharts measure the rotated labels and reserve
        // room for them. With it false, long technique names ran off the
        // bottom of the panel and the axis name was clipped at the top.
        grid: { left: 44, right: 24, top: 34, bottom: 12, containLabel: true },
        xAxis: {
            type: 'category', data: cats,
            axisLabel: {
                color: t.muted, rotate: 40, fontSize: 10, interval: 0,
                // Truncation is a backstop; containLabel handles the space.
                // Full names stay in the tooltip.
                formatter: function (v) { return shorten(v, 34); },
            },
            axisLine: { lineStyle: { color: t.axis } },
        },
        yAxis: {
            type: 'value', name: config.valueLabel || '',
            // nameLocation end + a gap keeps the axis title inside the canvas;
            // at the default it sits on the very top pixel row and clips.
            nameLocation: 'end',
            nameGap: 16,
            nameTextStyle: { color: t.muted, align: 'left' },
            axisLabel: { color: t.muted, fontSize: 10 },
            splitLine: { lineStyle: { color: t.axis } },
        },
        series: [{
            type: 'boxplot', data: data,
            emphasis: { itemStyle: { borderWidth: 2.5 } },
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
        animation: false,
        tooltip: {
            trigger: 'axis', backgroundColor: t.tooltipBg, borderColor: t.axis,
            textStyle: { color: t.text },
        },
        grid: { left: 44, right: 24, top: 34, bottom: 12, containLabel: true },
        xAxis: {
            type: 'category', data: cats,
            axisLabel: {
                color: t.muted, rotate: 40, fontSize: 10, interval: 0,
                formatter: function (v) { return shorten(v, 34); },
            },
            axisLine: { lineStyle: { color: t.axis } },
        },
        yAxis: {
            type: 'value', name: config.valueLabel || '',
            nameLocation: 'end', nameGap: 16,
            nameTextStyle: { color: t.muted, align: 'left' },
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

/* A donut rather than a pie: the hole gives the total somewhere to live, and
 * the eye compares arc length instead of trying to judge wedge area. Kept for
 * small ordered category sets only -- anything with a long tail belongs in a
 * bar or treemap. */
function buildDonut(rows, t, config) {
    var data = [], total = 0;
    for (var i = 0; i < rows.length; i++) {
        var v = num(rows[i][1]);
        if (v === null || v <= 0) { continue; }
        var name = String(rows[i][0]);
        total += v;
        data.push({
            name: name, value: v,
            itemStyle: { color: categoryColor(name, RAMP[i % RAMP.length]) },
        });
    }
    if (!data.length) { return null; }
    return {
        animation: false,
        tooltip: {
            trigger: 'item', backgroundColor: t.tooltipBg, borderColor: t.axis,
            textStyle: { color: t.text },
            formatter: function (p) {
                return escapeHtml(p.name) + '<br/><b>' + p.value + '</b> ' +
                    escapeHtml(config.valueLabel || 'findings') +
                    ' (' + p.percent + '%)';
            },
        },
        legend: { orient: 'vertical', right: 10, top: 'center',
                  textStyle: { color: t.muted, fontSize: 11 } },
        series: [{
            type: 'pie', radius: ['45%', '72%'], center: ['38%', '50%'],
            avoidLabelOverlap: true,
            itemStyle: { borderColor: t.tooltipBg, borderWidth: 2 },
            label: { color: t.text, fontSize: 11,
                     formatter: function (p) { return p.name + '\n' + p.value; } },
            labelLine: { lineStyle: { color: t.axis } },
            data: data,
        }],
    };
}

function buildStackedColumn(rows, t, config) {
    return stacked(rows, t, config, false);
}

function buildStackedBar(rows, t, config) {
    return stacked(rows, t, config, true);
}

function stacked(rows, t, config, horizontal) {
    var cats = [], seriesNames = [], byName = {};
    for (var i = 0; i < rows.length; i++) {
        var c = String(rows[i][0] || ''), sname = String(rows[i][1] || '');
        var v = num(rows[i][2]);
        if (!c || v === null) { continue; }
        if (cats.indexOf(c) === -1) { cats.push(c); }
        if (!(sname in byName)) { byName[sname] = {}; seriesNames.push(sname); }
        byName[sname][c] = (byName[sname][c] || 0) + v;
    }
    if (!cats.length) { return null; }
    var series = seriesNames.map(function (sname, i) {
        return {
            name: sname, type: 'bar', stack: 'total',
            itemStyle: { color: categoryColor(sname, RAMP[i % RAMP.length]) },
            emphasis: { focus: 'series' },
            data: cats.map(function (c) { return byName[sname][c] || 0; }),
        };
    });
    var catAxis = {
        type: 'category', data: cats, inverse: horizontal,
        axisLabel: {
            color: t.muted, fontSize: 10,
            rotate: horizontal ? 0 : 40,
            // Horizontal bars carry the category name flat on the y axis with
            // containLabel making room, so they can afford real words: at 24
            // characters "Restrict File and Directory Permissions" was cut to a
            // stub and the operator had to hover every row to learn which
            // control it was. Vertical labels are rotated 40 degrees where
            // every character costs height, so they keep the short budget.
            formatter: function (v) { return shorten(v, horizontal ? 44 : 24); },
        },
        axisLine: { lineStyle: { color: t.axis } },
    };
    var valAxis = {
        type: 'value', axisLabel: { color: t.muted, fontSize: 10 },
        splitLine: { lineStyle: { color: t.axis } },
    };
    return {
        animation: false,
        tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' },
                   backgroundColor: t.tooltipBg, borderColor: t.axis,
                   textStyle: { color: t.text } },
        // A legend that repeats the axis labels is noise. It only earns its
        // space when a category is actually made of several series.
        legend: {
            show: series.length > 1 && cats.length !== series.length,
            textStyle: { color: t.muted, fontSize: 11 }, top: 0,
        },
        // containLabel in both orientations: horizontal carries long category
        // names on the y axis, vertical carries rotated dates on the x, and
        // both were being clipped by fixed margins.
        grid: { left: 44, right: 24, top: 40, bottom: 12, containLabel: true },
        xAxis: horizontal ? valAxis : catAxis,
        yAxis: horizontal ? catAxis : valAxis,
        series: series,
    };
}

function buildLine(rows, t, config) {
    var xs = [], vals = [];
    for (var i = 0; i < rows.length; i++) {
        var v = num(rows[i][1]);
        if (v === null) { continue; }
        xs.push(String(rows[i][0]));
        vals.push(v);
    }
    if (!xs.length) { return null; }
    return {
        animation: false,
        tooltip: { trigger: 'axis', backgroundColor: t.tooltipBg,
                   borderColor: t.axis, textStyle: { color: t.text } },
        grid: { left: 44, right: 24, top: 34, bottom: 12, containLabel: true },
        xAxis: { type: 'category', data: xs, boundaryGap: false,
                 axisLabel: { color: t.muted, fontSize: 10, rotate: 30 },
                 axisLine: { lineStyle: { color: t.axis } } },
        yAxis: { type: 'value', name: config.valueLabel || '',
                 nameLocation: 'end', nameGap: 16,
                 nameTextStyle: { color: t.muted, align: 'left' },
                 axisLabel: { color: t.muted, fontSize: 10 },
                 splitLine: { lineStyle: { color: t.axis } } },
        series: [{
            type: 'line', data: vals, smooth: false, showSymbol: true,
            symbolSize: 5,
            itemStyle: { color: SEMANTIC.warn },
            lineStyle: { color: SEMANTIC.warn, width: 2 },
            areaStyle: { color: 'rgba(248,190,52,0.12)' },
        }],
    };
}

/* Node/cell keys join two fields, so they need a separator that cannot occur
 * inside a package name, a container name or a CVE id. Unit Separator is the
 * character that exists for exactly this and nothing else. */
var RK_SEP = String.fromCharCode(31);

/* The priority matrix: what to do, not how much there is.
 *
 * Reachability and exploit likelihood are orthogonal -- EPSS and KEV say how
 * likely the world is to exploit something, reachability says whether this
 * copy answers the network -- so the natural shape is a matrix.
 *
 * The decisive property is what it does with 16,417 against 6. Every
 * area-based encoding -- sankey ribbon, treemap tile, pie wedge -- draws six
 * findings as a sub-pixel hairline beside sixteen thousand: a panel built to
 * make six findings visible that renders them invisible. In a matrix area
 * encodes nothing, both numbers are typeset the same size, and the six sits in
 * a maroon cell at the top while the sixteen thousand sits in a cool one at the
 * bottom. Visual weight runs against volume, which is the whole argument.
 *
 * Axes come from fixed lists, so a row is drawn even when it is empty. "No
 * known-exploited CVE answers the network" is worth seeing; a missing row is
 * an ambiguity.
 */
/* Severity order, used only to resolve a collision. Each cell of the matrix
 * should carry exactly one tier -- the SPL derives tier from reach and exploit
 * class, so two rows landing in the same cell with different tiers means the
 * search changed. Keeping the worse one is the only safe way to lose that
 * argument: a cell that should read act-now must never be drawn as watch
 * because a calmer row happened to arrive second. */
var TIER_RANK = { 'act-now': 5, 'act-soon': 4, 'unknown-risk': 3, 'plan': 2, 'watch': 1 };

var REACH_ROWS = ['answers any address', 'answers one address', 'loopback only',
                  'no listening port', 'not assessed'];
var EXPLOIT_COLS = ['KEV', 'EPSS 50%+', 'EPSS 10-50%', 'EPSS 1-10%',
                    'EPSS under 1%', 'unscored'];

function buildPriorityMatrix(rows, t, config) {
    var xs = EXPLOIT_COLS.slice(), ys = REACH_ROWS.slice(), cell = {}, i;
    for (i = 0; i < rows.length; i++) {
        var x = String(rows[i][0] === null ? '' : rows[i][0]);
        var y = String(rows[i][1] === null ? '' : rows[i][1]);
        var v = num(rows[i][2]);
        if (!x || !y || v === null) { continue; }
        if (xs.indexOf(x) === -1) { xs.push(x); }
        if (ys.indexOf(y) === -1) { ys.push(y); }
        var k = x + RK_SEP + y, prev = cell[k];
        var tier = String(rows[i].length > 3 && rows[i][3] ? rows[i][3] : 'unknown-risk');
        if (prev && (TIER_RANK[prev.tier] || 0) > (TIER_RANK[tier] || 0)) { tier = prev.tier; }
        cell[k] = {
            v: (prev ? prev.v : 0) + v,
            tier: tier,
            note: rows[i].length > 4 && rows[i][4] ? String(rows[i][4]) : '',
        };
    }
    // ECharts draws a category y axis bottom-up. Without this the most
    // reachable row lands at the bottom and the picture reads upside down.
    ys = ys.slice().reverse();

    var data = [];
    for (var yi = 0; yi < ys.length; yi++) {
        for (var xi = 0; xi < xs.length; xi++) {
            var c = cell[xs[xi] + RK_SEP + ys[yi]];
            var v2 = c ? c.v : 0, st, lc, fw;
            if (v2 === 0) {
                st = { color: t.tooltipBg, borderColor: t.axis, borderWidth: 1 };
                lc = t.muted;
                fw = 'normal';
            } else {
                // An unrecognised tier falls back to unknown-risk, never to watch.
                var tt = TIER[c.tier] || TIER['unknown-risk'];
                st = {
                    color: tt.fill,
                    borderColor: tt.dashed ? tt.text : t.axis,
                    borderWidth: tt.dashed ? 2 : 1,
                    borderType: tt.dashed ? 'dashed' : 'solid',
                };
                lc = tt.text;
                fw = 'bold';
            }
            data.push({
                value: [xi, yi, v2],
                itemStyle: st,
                label: { color: lc, fontWeight: fw },
                rkNote: c ? c.note : '',
                rkTier: c ? c.tier : '',
            });
        }
    }

    return {
        animation: false,
        tooltip: {
            trigger: 'item',
            backgroundColor: t.tooltipBg,
            borderColor: t.axis,
            textStyle: { color: t.text },
            formatter: function (p) {
                var yy = ys[p.value[1]], xx = xs[p.value[0]];
                if (p.value[2] === 0) {
                    return escapeHtml(yy) + '<br/>' + escapeHtml(xx) +
                        '<br/><b>0</b> open findings here.';
                }
                return '<b>' + Number(p.value[2]).toLocaleString() + '</b> open findings' +
                    '<br/>' + escapeHtml(yy) + '<br/>' + escapeHtml(xx) +
                    (p.data.rkNote ? '<br/><span style="color:' + t.muted + '">' +
                        escapeHtml(p.data.rkNote) + '</span>' : '') +
                    '<br/><span style="color:' + t.muted + '">priority: ' +
                    escapeHtml(p.data.rkTier) + '</span>';
            },
        },
        grid: { left: 178, right: 22, top: 64, bottom: 20, containLabel: false },
        xAxis: {
            type: 'category', position: 'top', data: xs,
            splitArea: { show: false },
            axisTick: { show: false },
            axisLine: { lineStyle: { color: t.axis } },
            axisLabel: { color: t.muted, fontSize: 11, interval: 0 },
            name: 'how likely the world is to exploit it',
            nameLocation: 'middle', nameGap: 36,
            nameTextStyle: { color: t.muted, fontSize: 10 },
        },
        yAxis: {
            type: 'category', data: ys,
            splitArea: { show: true,
                         areaStyle: { color: [t.tooltipBg, 'rgba(0,0,0,0)'] } },
            axisTick: { show: false },
            axisLine: { lineStyle: { color: t.axis } },
            axisLabel: { color: t.muted, fontSize: 11, interval: 0,
                         width: 166, overflow: 'truncate' },
            name: 'whether this copy answers the network',
            nameLocation: 'middle', nameGap: 162, nameRotate: 90,
            nameTextStyle: { color: t.muted, fontSize: 10 },
        },
        series: [{
            type: 'heatmap',
            data: data,
            label: {
                show: true, fontSize: 13,
                formatter: function (p) {
                    return p.value[2] === 0 ? '0' : Number(p.value[2]).toLocaleString();
                },
            },
            itemStyle: { borderColor: t.axis, borderWidth: 1 },
            emphasis: { itemStyle: { borderColor: t.text, borderWidth: 2 } },
        }],
    };
}

/* The KEV to ATT&CK bridge: techniques known to be used against the fleet's
 * known-exploited CVEs, laid against whether this copy answers the network.
 *
 * The Y axis is one row per technique that a KEV finding maps to. The X axis is
 * the five reach classes, worst on the left, drawn even when a column is empty
 * so an empty "answers any address" column is a statement rather than a gap.
 * The cell is coloured by reach, not by count: a single known-exploited finding
 * answering the internet is the loudest thing on the page, and a thousand on a
 * closed port stay quiet, which is the whole point of the reach axis. This is
 * the prioritymatrix inversion applied to a different pair of axes, and it
 * reuses the same TIER palette so the two pages read the same way.
 *
 * A count ramp would be exactly wrong here. It would paint the technique with
 * the most CVEs brightest whether or not any copy is reachable, which is the
 * "the world is scared" signal the app already has twice over in EPSS and KEV.
 * The only thing this page adds is "and it is reachable HERE", so reach is what
 * colours it.
 */
function buildKevBridge(rows, t, config) {
    var xs = REACH_ROWS.slice(), ys = [], cell = {}, i;
    // Map a reach class to the priority tier that colours its column.
    var REACH_TIER = {
        'answers any address': 'act-now',
        'answers one address': 'act-soon',
        'loopback only': 'plan',
        'no listening port': 'watch',
        'not assessed': 'unknown-risk',
    };
    for (i = 0; i < rows.length; i++) {
        var y = String(rows[i][0] === null ? '' : rows[i][0]);
        var x = String(rows[i][1] === null ? '' : rows[i][1]);
        var v = num(rows[i][2]);
        if (!y || !x || v === null) { continue; }
        if (ys.indexOf(y) === -1) { ys.push(y); }
        if (xs.indexOf(x) === -1) { xs.push(x); }
        var tier = String(rows[i].length > 3 && rows[i][3] ? rows[i][3]
                          : (REACH_TIER[x] || 'unknown-risk'));
        var note = rows[i].length > 4 && rows[i][4] ? String(rows[i][4]) : '';
        var k = x + RK_SEP + y, prev = cell[k];
        cell[k] = { v: (prev ? prev.v : 0) + v, tier: tier,
                    note: note || (prev ? prev.note : '') };
    }
    // Sort techniques so the worst reach sits at the top of the panel, which is
    // where the eye starts and where the action list belongs. ECharts draws a
    // category y axis bottom-up, so the worst must be LAST in the array.
    var reachRank = {};
    for (i = 0; i < REACH_ROWS.length; i++) { reachRank[REACH_ROWS[i]] = REACH_ROWS.length - i; }
    function worstReach(techName) {
        var best = 0;
        for (var xi = 0; xi < xs.length; xi++) {
            if (cell[xs[xi] + RK_SEP + techName]) {
                best = Math.max(best, reachRank[xs[xi]] || 0);
            }
        }
        return best;
    }
    ys.sort(function (a, b) { return worstReach(a) - worstReach(b); });

    var data = [];
    for (var yi = 0; yi < ys.length; yi++) {
        for (var xi2 = 0; xi2 < xs.length; xi2++) {
            var c = cell[xs[xi2] + RK_SEP + ys[yi]];
            var v2 = c ? c.v : 0, st, lc, fw;
            if (v2 === 0) {
                st = { color: t.tooltipBg, borderColor: t.axis, borderWidth: 1 };
                lc = t.muted; fw = 'normal';
            } else {
                var tt = TIER[c.tier] || TIER['unknown-risk'];
                st = { color: tt.fill, borderColor: t.axis, borderWidth: 1 };
                lc = tt.text; fw = 'bold';
            }
            data.push({
                value: [xi2, yi, v2],
                itemStyle: st,
                label: { color: lc, fontWeight: fw },
                rkNote: c ? c.note : '',
                rkTier: c ? c.tier : '',
            });
        }
    }
    var rowH = 26, plotH = Math.max(ys.length * rowH, rowH);

    return {
        animation: false,
        tooltip: {
            trigger: 'item',
            backgroundColor: t.tooltipBg, borderColor: t.axis,
            textStyle: { color: t.text },
            // The note is MITRE's own sentence on how the CVE is exploited, and
            // some of those sentences are paragraphs. Unwrapped, the tooltip grew
            // to the width of the longest one and clipped both viewport edges.
            // confine keeps it inside the chart, the css caps the width and lets
            // the text wrap, and the note itself is cut at a sentence-ish length
            // because a tooltip is a glance, not the place to read MITRE's essay.
            confine: true,
            extraCssText: 'max-width: 440px; white-space: normal;',
            formatter: function (p) {
                var yy = ys[p.value[1]], xx = xs[p.value[0]];
                if (p.value[2] === 0) {
                    return escapeHtml(yy) + '<br/>' + escapeHtml(xx) +
                        '<br/><b>0</b> known-exploited CVEs here.';
                }
                return '<b>' + Number(p.value[2]).toLocaleString() +
                    '</b> known-exploited CVEs<br/>' + escapeHtml(yy) +
                    '<br/>' + escapeHtml(xx) +
                    (p.data.rkNote ? '<br/><span style="color:' + t.muted + '">' +
                        escapeHtml(shorten(p.data.rkNote, 240)) + '</span>' : '');
            },
        },
        grid: { left: 344, right: 22, top: 64, bottom: 20, containLabel: false },
        xAxis: {
            type: 'category', position: 'top', data: xs,
            splitArea: { show: false }, axisTick: { show: false },
            axisLine: { lineStyle: { color: t.axis } },
            axisLabel: { color: t.muted, fontSize: 11, interval: 0 },
            name: 'whether this copy answers the network',
            nameLocation: 'middle', nameGap: 36,
            nameTextStyle: { color: t.muted, fontSize: 10 },
        },
        yAxis: {
            type: 'category', data: ys,
            splitArea: { show: true,
                         areaStyle: { color: [t.tooltipBg, 'rgba(0,0,0,0)'] } },
            axisTick: { show: false },
            axisLine: { lineStyle: { color: t.axis } },
            axisLabel: { color: t.muted, fontSize: 11, interval: 0,
                         width: 330, overflow: 'truncate' },
        },
        series: [{
            type: 'heatmap', data: data,
            label: { show: true, fontSize: 12,
                     formatter: function (p) {
                         return p.value[2] === 0 ? '' : Number(p.value[2]).toLocaleString();
                     } },
            itemStyle: { borderColor: t.axis, borderWidth: 1 },
            emphasis: { itemStyle: { borderColor: t.text, borderWidth: 2 } },
        }],
        rkMinHeight: plotH + 84,
    };
}

/* The chain: network edge -> listening process -> container -> package -> CVE.
 *
 * This is the one picture only this collector can draw. It follows a published
 * port through the process holding it, into the container answering it, to the
 * package inside, to the CVE. Laid out as a fixed five-column DAG rather than a
 * force graph, because a picture that rearranges itself between two loads of
 * the same data is a picture nobody trusts.
 *
 * A sankey was the cheaper option and is wrong here. Sankey takes a node's
 * column from its depth in the flow, and these chains have two different
 * depths -- a host process is four hops, a containerised one is five -- so host
 * packages would land in column three and container packages in column four,
 * asserting they are different kinds of thing when the only difference is that
 * one hop exists. A tree is wrong for the opposite reason: it duplicates shared
 * nodes, and convergence -- three exposed services ending at one library -- is
 * exactly what the operator came to see.
 *
 * Node identity is (layer, name), never name alone. A container called nginx
 * and a package called nginx are different things, and merging them would draw
 * a chain that does not exist.
 */
var CHAIN_KIND = {
    'edge':            { layer: 0, color: '#dc4e41' },
    'listener':        { layer: 1, color: '#f8be34' },
    // A port that answers with no process attributed to it. Drawn dashed
    // because it is a hole in what the collector could see, which is a
    // different thing from a hop that is known and harmless.
    'listener-unknown': { layer: 1, color: '#6b5a2a', dashed: true },
    'container':       { layer: 2, color: '#7cc0ec' },
    'package':         { layer: 3, color: '#6e9c4f' },
    'package-unknown': { layer: 3, color: '#6b5a2a', dashed: true },
    'cve':             { layer: 4, color: '#708794' },
    'cve-kev':         { layer: 4, color: '#a4302a' },
};
var CHAIN_LAYERS = ['network edge', 'listening process', 'container', 'package', 'CVE'];

function chainNodeLabel(id) {
    var s = String(id);
    return s.slice(s.indexOf(RK_SEP) + 1);
}

// The chain draws a fixed set of columns and consolidates the nodes in each one
// when a column gets crowded. That shape is not specific to the exposure story
// it was written for, so a panel can supply its own columns as
// "kind:Label,kind:Label" in layer order. The encyclopaedia reuses it for
// package, fixed version and CVE rather than growing a second graph
// visualization that would then have to be kept in step with this one.
function chainSchema(config) {
    var spec = String((config && config.chainKinds) || '').trim();
    if (!spec) { return { kinds: CHAIN_KIND, layers: CHAIN_LAYERS }; }
    var kinds = {}, layers = [];
    var palette = ['#dc4e41', '#f8be34', '#7cc0ec', '#6e9c4f', '#708794'];
    spec.split(',').forEach(function (pair) {
        var bits = String(pair).split(':');
        var kind = (bits[0] || '').trim();
        if (!kind) { return; }
        kinds[kind] = { layer: layers.length, color: palette[layers.length % palette.length] };
        layers.push((bits[1] || kind).trim());
    });
    return layers.length ? { kinds: kinds, layers: layers }
                         : { kinds: CHAIN_KIND, layers: CHAIN_LAYERS };
}

function buildChainGraph(rows, t, config) {
    var nodes = {}, links = [], i, vmax = 0;
    var schema = chainSchema(config);
    var KINDS = schema.kinds;
    var LAYERS = schema.layers;

    function touch(name, kind, v) {
        var k = KINDS[kind] || { layer: LAYERS.length - 1, color: '#6b5a2a', dashed: true };
        var id = k.layer + RK_SEP + name;
        if (!nodes[id]) {
            nodes[id] = { id: id, name: name, layer: k.layer, kind: kind,
                          color: k.color, dashed: !!k.dashed, v: 0 };
        }
        if (v > nodes[id].v) { nodes[id].v = v; }
        return id;
    }

    for (i = 0; i < rows.length; i++) {
        var sName = String(rows[i][0] === null ? '' : rows[i][0]);
        var sKind = String(rows[i][1] === null ? '' : rows[i][1]);
        var tName = String(rows[i][2] === null ? '' : rows[i][2]);
        var tKind = String(rows[i][3] === null ? '' : rows[i][3]);
        var v = num(rows[i][4]);
        if (!sName || !tName) { continue; }
        if (v === null) { v = 0; }
        if (v > vmax) { vmax = v; }
        var sid = touch(sName, sKind, v), tid = touch(tName, tKind, v);
        links.push({ source: sid, target: tid, value: v,
                     targetKind: tKind, sourceKind: sKind });
    }

    // Lay each column out top to bottom, busiest first, then two barycentre
    // passes to pull connected nodes level with each other. Cheap, and it
    // removes most of the crossings that make a DAG unreadable.
    var byLayer = {};
    Object.keys(nodes).forEach(function (id) {
        (byLayer[nodes[id].layer] = byLayer[nodes[id].layer] || []).push(nodes[id]);
    });
    Object.keys(byLayer).forEach(function (L) {
        byLayer[L].sort(function (a, b) { return b.v - a.v; });
        byLayer[L].forEach(function (n, k) { n.y = 100 * (k + 0.5) / byLayer[L].length; });
    });
    for (var pass = 0; pass < 2; pass++) {
        Object.keys(byLayer).sort().forEach(function (L) {
            byLayer[L].forEach(function (n) {
                var ys = [], j;
                for (j = 0; j < links.length; j++) {
                    if (links[j].target === n.id && nodes[links[j].source]) {
                        ys.push(nodes[links[j].source].y);
                    } else if (links[j].source === n.id && nodes[links[j].target]) {
                        ys.push(nodes[links[j].target].y);
                    }
                }
                if (ys.length) {
                    n.y = ys.reduce(function (a, b) { return a + b; }, 0) / ys.length;
                }
            });
            byLayer[L].sort(function (a, b) { return a.y - b.y; });
            byLayer[L].forEach(function (n, k) { n.y = 100 * (k + 0.5) / byLayer[L].length; });
        });
    }

    // Label every node there is vertical room to label.
    //
    // This was a flat twelve per column, which is why the CVE column drew a
    // dozen names and a dozen anonymous dots: a dot you cannot identify is not
    // a smaller piece of information, it is none. The budget comes from the
    // geometry instead -- the plot's height divided by the space a label needs
    // -- so on a panel with room every node is named, and a column dense enough
    // to overrun it degrades in a way that can be reasoned about rather than at
    // a number someone once typed.
    //
    // ECharts' hideOverlap cannot do this job: it drops labels only after they
    // have collided, so in a tight column it discards most of them and keeps an
    // arbitrary few.
    var LABEL_PITCH = 15;
    var CHROME = 62;
    // A CVE that a dozen distributions have each patched produces a column of
    // sixty fix versions, and the panel was sized for a fraction of that. Rather
    // than drop the overflow, ask for the height the data needs: the column is
    // the answer to "which versions fix this", so a truncated one is not a
    // smaller answer, it is a misleading one.
    //
    // Capped, because a pathological CVE should not produce a page of chart. Past
    // the cap the label budget still degrades by value, which is the old
    // behaviour and the only sensible one left.
    var CHAIN_MAX_HEIGHT = 1600;
    var densest = 0;
    Object.keys(byLayer).forEach(function (L) {
        densest = Math.max(densest, byLayer[L].length);
    });
    var wanted = Math.min(CHAIN_MAX_HEIGHT, densest * LABEL_PITCH + CHROME);
    var configured = (config && config.height ? config.height : 480);
    var effective = Math.max(configured, wanted);

    var plotHeight = Math.max(160, effective - CHROME);
    var room = Math.max(4, Math.floor(plotHeight / LABEL_PITCH));
    Object.keys(byLayer).forEach(function (L) {
        byLayer[L].slice().sort(function (a, b) { return b.v - a.v; })
            .forEach(function (n, k) { n.labelled = k < room; });
    });

    var nodeData = Object.keys(nodes).map(function (id) {
        var n = nodes[id];
        // sqrt so AREA tracks the value. A radius-proportional bubble
        // overstates a large one by its square.
        var size = vmax > 0 ? 9 + 23 * Math.sqrt(n.v / vmax) : 11;
        return {
            name: n.id,
            value: [n.layer, n.y],
            symbolSize: size,
            rkKind: n.kind,
            // Every label to the right of its node, including the last
            // column's -- the grid reserves margin for them, so they land in
            // clear space instead of on top of the edges feeding the node.
            label: { show: n.labelled, position: 'right' },
            itemStyle: {
                color: n.color,
                borderColor: n.dashed ? '#f8be34' : t.axis,
                borderWidth: n.dashed ? 2 : 1,
                borderType: n.dashed ? 'dashed' : 'solid',
            },
        };
    });

    var linkData = links.map(function (l) {
        return {
            source: l.source, target: l.target, value: l.value,
            targetKind: l.targetKind,
            lineStyle: { width: vmax > 0 ? 1 + 2.4 * (l.value / vmax) : 1.4 },
        };
    });

    return {
        animation: false,
        // Published for the view, which walks it on hover to light the whole
        // route through a node rather than only its immediate neighbours.
        rkChain: {
            nodes: nodeData.map(function (n) { return n.name; }),
            links: linkData.map(function (l) { return [l.source, l.target]; }),
        },
        tooltip: {
            trigger: 'item',
            confine: true,
            backgroundColor: t.tooltipBg,
            borderColor: t.axis,
            textStyle: { color: t.text, fontSize: 11 },
            padding: [4, 8],
            // Pinned to the bottom edge, tracking the pointer horizontally.
            // A tooltip that follows the pointer freely sits on top of the
            // graph, and on a five-column route it covers two columns and the
            // edges between them -- so hovering a node to find out what it is
            // hides the thing you were trying to read. The bottom strip is the
            // emptiest part of the plot and, more to the point, it is the same
            // place every time.
            position: function (point, params, dom, rect, size) {
                var x = point[0] + 14;
                var maxX = size.viewSize[0] - size.contentSize[0] - 6;
                if (x > maxX) { x = Math.max(6, point[0] - size.contentSize[0] - 14); }
                return [x, size.viewSize[1] - size.contentSize[1] - 6];
            },
            formatter: function (p) {
                if (p.dataType === 'edge') {
                    return escapeHtml(chainNodeLabel(p.data.source)) + ' &#8594; ' +
                        escapeHtml(chainNodeLabel(p.data.target)) + ' &#183; <b>' +
                        p.data.value + '</b> CVEs through this hop';
                }
                return '<b>' + escapeHtml(chainNodeLabel(p.name)) + '</b> &#183; ' +
                    escapeHtml(LAYERS[p.value[0]] || 'unclassified');
            },
        },
        grid: { left: 18, right: 176, top: 46, bottom: 16, containLabel: false },
        // Read and removed by _render before the option reaches ECharts.
        rkMinHeight: effective,
        xAxis: {
            type: 'category', data: LAYERS, position: 'top', boundaryGap: true,
            axisTick: { show: false },
            axisLine: { show: false },
            splitLine: { show: true, lineStyle: { color: t.axis, type: 'dashed' } },
            axisLabel: { color: t.muted, fontSize: 11, interval: 0 },
        },
        yAxis: { type: 'value', min: 0, max: 100, show: false },
        series: [{
            type: 'graph',
            coordinateSystem: 'cartesian2d',
            xAxisIndex: 0, yAxisIndex: 0, roam: false,
            edgeSymbol: ['none', 'arrow'], edgeSymbolSize: 7,
            lineStyle: { color: 'source', opacity: 0.45, curveness: 0.08 },
            // focus: 'none' on purpose. ECharts' 'adjacency' lights one hop in
            // each direction, which on a five-column route answers the wrong
            // question -- "what touches this?" instead of "what is this on the
            // end of?". The view replaces it with the transitive closure.
            emphasis: { focus: 'none', itemStyle: { borderColor: t.text, borderWidth: 2 } },
            label: {
                show: true, color: t.text, fontSize: 10,
                formatter: function (p) { return shorten(chainNodeLabel(p.name), 34); },
            },
            labelLayout: { hideOverlap: true },
            data: nodeData,
            links: linkData,
        }],
    };
}

var BUILDERS = {
    treemap: buildTreemap,
    donut: buildDonut,
    stackedbar: buildStackedBar,
    stackedcolumn: buildStackedColumn,
    line: buildLine,
    sankey: buildSankey,
    heatmap: buildHeatmap,
    boxplot: buildBoxplot,
    bar: buildBar,
    prioritymatrix: buildPriorityMatrix,
    kevbridge: buildKevBridge,
    chaingraph: buildChainGraph,
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
                // Lets a panel relabel the chain's columns. See chainSchema.
                chainKinds: this._opt(config, 'chainKinds'),
                // The panel's pixel height, so a builder can decide what fits
                // rather than guess at a row count. Zero while the panel is
                // still hidden, hence the fallback at the point of use.
                height: this.el.clientHeight || 0,
            });
        } catch (e) {
            this._message('bad', 'The chart could not be drawn', String(e && e.message || e));
            return;
        }

        if (!option) {
            this._message('warn', 'Nothing to display', emptyText);
            return;
        }

        this._config = config;
        this._render(option, rows.length >= ROW_CAP, chartType, data.fields);
    },

    _render: function (option, truncated, chartType, fields) {
        this._clear();

        // Same reasoning as the table: a chart that has been narrowed by a
        // drilldown looks exactly like a chart of a quiet fleet.
        var note = String(this._opt(this._config || {}, 'filterNote') || '').trim();
        if (note) {
            var fb = document.createElement('div');
            fb.className = 'rk-viz-filtered';
            var lab = document.createElement('b');
            lab.textContent = 'Filtered';
            fb.appendChild(lab);
            fb.appendChild(document.createTextNode(' \u00b7 ' + note));
            this.el.appendChild(fb);
        }

        var host = document.createElement('div');
        host.className = 'rk-viz-canvas';

        // A builder may need more room than the panel was given. Only the chain
        // graph does today, and only when a column is denser than the panel can
        // label. Growing the host is preferred over dropping labels: the page
        // scrolls, a missing name does not come back.
        var wantHeight = option && option.rkMinHeight;
        if (option) { delete option.rkMinHeight; }
        if (wantHeight && wantHeight > 0) {
            var px = Math.round(wantHeight) + 'px';
            host.style.height = px;
            // Growing the canvas alone is not enough. Splunk applies the panel's
            // height option to a wrapper above this element, and our own CSS
            // makes the chart height:100% of it, so a taller canvas is simply
            // clipped by an ancestor that was never told about it.
            //
            // Walk up and lift the constraint. Bounded, and it stops at the
            // panel body rather than continuing into the dashboard, because the
            // panel is the thing that should grow. min-height rather than
            // height, so nothing is ever made shorter than Splunk intended.
            var node = this.el;
            for (var up = 0; node && up < 6; up++) {
                node.style.minHeight = px;
                // An inline height set by the framework wins over min-height on
                // the same element, so relax it where one is present.
                if (node.style.height && node.style.height !== 'auto') {
                    node.style.height = 'auto';
                }
                var cls = ' ' + (node.className || '') + ' ';
                if (cls.indexOf('panel-body') > -1 || cls.indexOf('dashboard-cell') > -1) {
                    break;
                }
                node = node.parentElement;
            }
        }

        if (truncated) {
            // Splunk truncates silently. A chart drawn from the first 10,000
            // rows of a larger result set looks exactly as authoritative as a
            // complete one, so say so on the panel rather than in a log.
            var warn = document.createElement('div');
            warn.className = 'rk-viz-truncated';
            warn.textContent =
                'Showing the first ' + ROW_CAP.toLocaleString() + ' rows. The ' +
                'search returned at least this many, so this chart is ' +
                'incomplete - aggregate further in the search.';
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

        // Before the drilldown check: hovering must work on a panel whose
        // drilldown is switched off.
        if (chartType === 'chaingraph') { this._wireChainHover(option); }

        // Clicking a chart reports what was clicked, using the search's own
        // field names. A treemap tile of a package is only useful if the
        // dashboard can then ask for that package.
        var self = this;
        if (String(this._opt(this._config || {}, 'drilldown') || 'enabled') === 'disabled') {
            return;
        }
        var names = (CLICK_FIELDS[chartType] || []);
        this.chart.on('click', function (params) {
            var values = [];
            if ((chartType === 'heatmap' || chartType === 'prioritymatrix') &&
                    params.value) {
                // Heatmap data is [xIndex, yIndex, value], so the labels have
                // to come back out of the axis rather than off the point.
                var opt = self.chart.getOption();
                values = [
                    (opt.xAxis[0].data || [])[params.value[0]],
                    (opt.yAxis[0].data || [])[params.value[1]],
                ];
            } else if (chartType === 'kevbridge' && params.value) {
                // Same cell shape, but this contract leads with the technique,
                // which is the Y axis here, so the pair comes back (y, x).
                var kopt = self.chart.getOption();
                values = [
                    (kopt.yAxis[0].data || [])[params.value[1]],
                    (kopt.xAxis[0].data || [])[params.value[0]],
                ];
            } else if (chartType === 'chaingraph') {
                // A graph node's name carries its layer, so that a container
                // and a package sharing a name stay separate. The dashboard
                // wants the name back without it.
                values = params.dataType === 'edge'
                    ? [chainNodeLabel(params.data.target), params.data.targetKind]
                    : [chainNodeLabel(params.name), params.data && params.data.rkKind];
            } else if (chartType === 'sankey') {
                values = params.dataType === 'edge'
                    ? [params.data.source, params.data.target]
                    : [params.name];
            } else if (names.length > 1) {
                values = [params.name, params.seriesName];
            } else {
                values = [params.name];
            }

            var payload = {};
            names.forEach(function (slot, i) {
                // The chain graph's click values are a node and its kind, which
                // are not columns 1 and 2 of its contract -- reporting them
                // under the source/source_kind headers would name them wrongly.
                var col = (chartType === 'chaingraph' || !(fields && fields[i]))
                    ? slot : fields[i].name;
                if (values[i] === undefined) { return; }
                // Both spellings, for the same reason the grid emits both:
                // Splunk resolves $row.<field>$ from the bare name.
                payload[col] = values[i];
                payload['row.' + col] = values[i];
            });
            payload['click.name'] = chartType === 'chaingraph' ? 'node'
                : ((fields && fields[0]) ? fields[0].name : 'label');
            payload['click.value'] = values[0];
            payload.name = payload['click.name'];
            payload.value = payload['click.value'];

            self.drilldown({
                action: SplunkVisualizationBase.FIELD_VALUE_DRILLDOWN,
                data: payload,
            }, params.event && params.event.event);
        });
    },

    /* Light the whole route through whatever the pointer is on.
     *
     * ECharts' own emphasis.focus for a graph series offers 'adjacency', which
     * lights one hop in each direction. On a five-column route that answers the
     * wrong question: hovering a package tells you which process holds it and
     * which CVEs it carries, but not which port lets the world in, which is the
     * thing the reader came to find out. ('trajectory', which does walk the
     * whole path, exists only for sankey.)
     *
     * So: walk every edge upstream and every edge downstream from the hovered
     * node, and dim everything that is not on one of those paths. Because the
     * lit set is a path rather than a neighbourhood, a node's labels are worth
     * showing even when the layout had no room to label it, so hovering also
     * reveals the names of nodes the label budget skipped.
     *
     * Cost is a breadth-first walk over a graph capped at 160 edges, on
     * mouseover, with animation off. Nothing here needs to be clever.
     */
    _wireChainHover: function (option) {
        var chain = option && option.rkChain;
        var series = option && option.series && option.series[0];
        if (!chain || !series || !series.data) { return; }

        var self = this;
        var baseNodes = series.data, baseLinks = series.links || [];
        var out = {}, inn = {};
        chain.links.forEach(function (l, i) {
            (out[l[0]] = out[l[0]] || []).push(i);
            (inn[l[1]] = inn[l[1]] || []).push(i);
        });

        function merge(a, b) {
            var o = {}, k;
            for (k in a) { if (Object.prototype.hasOwnProperty.call(a, k)) { o[k] = a[k]; } }
            for (k in b) { if (Object.prototype.hasOwnProperty.call(b, k)) { o[k] = b[k]; } }
            return o;
        }

        // Breadth-first in one direction, recording the edges it crosses --
        // those edges ARE the path, so they are what gets lit.
        function spread(seed, edgeMap, farEnd, nodes, edges) {
            var queue = [], seen = {}, i;
            for (i = 0; i < seed.length; i++) {
                if (seen[seed[i]]) { continue; }
                seen[seed[i]] = 1; nodes[seed[i]] = 1; queue.push(seed[i]);
            }
            while (queue.length) {
                var cur = queue.shift();
                var es = edgeMap[cur] || [];
                for (i = 0; i < es.length; i++) {
                    edges[es[i]] = 1;
                    var nxt = farEnd(chain.links[es[i]]);
                    if (!seen[nxt]) { seen[nxt] = 1; nodes[nxt] = 1; queue.push(nxt); }
                }
            }
        }

        var DIM_NODE = 0.12, DIM_EDGE = 0.04;

        function apply(nodes, edges) {
            var nd = baseNodes, ld = baseLinks;
            if (nodes) {
                nd = baseNodes.map(function (n) {
                    var on = !!nodes[n.name];
                    return merge(n, {
                        itemStyle: merge(n.itemStyle, { opacity: on ? 1 : DIM_NODE }),
                        label: merge(n.label, { show: on, opacity: on ? 1 : 0 }),
                    });
                });
                ld = baseLinks.map(function (l, i) {
                    var on = !!edges[i];
                    return merge(l, {
                        lineStyle: merge(l.lineStyle, {
                            opacity: on ? 0.95 : DIM_EDGE,
                            width: on ? ((l.lineStyle && l.lineStyle.width) || 1.4) + 1.2
                                      : (l.lineStyle && l.lineStyle.width) || 1.4,
                        }),
                    });
                });
            }
            try {
                self.chart.setOption({ series: [{ data: nd, links: ld }] });
            } catch (e) { /* torn down mid-hover */ }
        }

        var lit = null;

        function light(seed, key) {
            if (key === lit) { return; }
            lit = key;
            var nodes = {}, edges = {};
            spread(seed, out, function (l) { return l[1]; }, nodes, edges);
            spread(seed, inn, function (l) { return l[0]; }, nodes, edges);
            apply(nodes, edges);
        }

        function restore() {
            if (lit === null) { return; }
            lit = null;
            apply(null, null);
        }

        // Deliberately no mouseout handler.
        //
        // Applying the highlight redraws the series, which disposes the very
        // element the pointer is over; zrender then reports a mouseout that
        // nothing distinguishes from the pointer actually leaving. Restoring on
        // it undoes the highlight a few milliseconds after drawing it, and the
        // panel looks inert -- which is exactly how this behaved until the
        // handler came out.
        //
        // So the route stays lit until the pointer lands on something else or
        // leaves the chart entirely. Both of those are unambiguous, neither can
        // be produced by our own redraw, and a route that stays put while you
        // read it is better than one that vanishes when you look away from the
        // node to follow the line.
        this.chart.on('mouseover', function (ev) {
            if (ev.dataType === 'edge' && ev.data) {
                light([ev.data.source, ev.data.target],
                      'e:' + ev.data.source + '>' + ev.data.target);
            } else if (ev.name) {
                light([ev.name], 'n:' + ev.name);
            }
        });
        this.chart.on('globalout', restore);

        // Releasing over empty canvas needs a live hit test rather than an
        // event: zrender's own mouseout cannot be told apart from the one our
        // redraw causes, but asking "is anything under the pointer right now"
        // has no such ambiguity. Guarded because findHover is not part of the
        // published API, and the panel is still usable without it - the route
        // simply stays lit until the pointer leaves.
        try {
            var zr = this.chart.getZr();
            if (zr && zr.handler && typeof zr.handler.findHover === 'function') {
                zr.on('mousemove', function (e) {
                    var h = zr.handler.findHover(e.offsetX, e.offsetY);
                    if (!h || !h.target) { restore(); }
                });
            }
        } catch (e) { /* older zrender: globalout still restores */ }
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
