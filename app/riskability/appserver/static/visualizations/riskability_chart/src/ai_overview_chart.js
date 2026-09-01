/*
 * The sea, and what rises out of it.
 *
 * A second, standalone bundle for the AI prioritization page. The page is
 * plain JavaScript in a div rather than a Simple XML dashboard, so it cannot
 * use the Splunk visualisation module next door: that one is an AMD module
 * Splunk instantiates for a panel with a search behind it, and this page
 * deliberately runs no searches at all. Same ECharts, same tree-shaken import
 * discipline, different delivery.
 *
 * WHY THIS CHART AND NOT A SCATTER
 *
 * The obvious chart is priority score against exploit likelihood. It was tried
 * against real verdicts and it draws five flat stripes, because the model
 * returns round numbers: 21 verdicts came back carrying five distinct scores,
 * nine of them 85. A scatter would present that as a picture of risk when it is
 * really a picture of the model's resolution.
 *
 * So the chart says the thing the feature is FOR instead. The whole open
 * catalogue is drawn as a filled profile across exploit-likelihood bands: the
 * sea, thousands of CVEs wide, deliberately dull and unlabelled because that is
 * what it is. The handful that have been analysed and rank highly rise out of it
 * as labelled stems, positioned by the same exploit likelihood so a stem in the
 * shallow left of the sea is visibly a judgement call and one on the right is
 * visibly urgent. A waterline marks the cut.
 *
 * One look answers: how much is there, how little matters, and why that little.
 * The rationale rides in the tooltip, because "describe why" is the third verb
 * in this feature's purpose and a chart that drops it has kept the arithmetic
 * and thrown away the point.
 *
 * The table stays. This sits above it and drives it: clicking a stem filters
 * the table to that CVE rather than replacing it.
 */

import * as echarts from 'echarts/core';
import { BarChart, CustomChart, ScatterChart } from 'echarts/charts';
import {
    GridComponent,
    TooltipComponent,
    MarkLineComponent,
    GraphicComponent,
} from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';

// Registration is not optional and the two failure modes differ: a missing
// SERIES type throws, a missing COMPONENT fails silently and simply omits part
// of the chart. GraphicComponent has done exactly that in this app before, so
// it is listed even though only the empty state uses it.
echarts.use([
    BarChart, CustomChart, ScatterChart,
    GridComponent, TooltipComponent, MarkLineComponent, GraphicComponent,
    CanvasRenderer,
]);

// Exploit-likelihood bands, low to high. EPSS spans four orders of magnitude
// and almost everything sits in the bottom one, so linear axes waste the plot
// on empty space. Bands are also what the verdict cache signature uses, which
// keeps the picture and the invalidation rule talking about the same thing.
var BANDS = [
    { key: '0', label: '<1%' },
    { key: '1', label: '1-5%' },
    { key: '2', label: '5-20%' },
    { key: '3', label: '20-50%' },
    { key: '4', label: '>50%' },
];

// Beyond this many stems the picture stops being readable and the count
// carries more meaning than the strokes would.
var MAX_STEMS = 30;

var TIER_COLOUR = {
    P0: '#e05c5c',
    P1: '#e0a33c',
    P2: '#5b9bd5',
    P3: '#6b8ea3',
    P4: '#6b7681',
};

function epssBand(value) {
    var n = Number(value);
    if (!isFinite(n)) n = 0;
    if (n < 0.01) return 0;
    if (n < 0.05) return 1;
    if (n < 0.20) return 2;
    if (n < 0.50) return 3;
    return 4;
}

function escapeHtml(text) {
    // The tooltip is the one place model-authored text becomes markup. Every
    // other surface on this page uses textContent; ECharts tooltips take an
    // HTML string, so the escaping has to happen here instead of being
    // inherited. Advisory titles come from an imported feed and are written
    // outside this organisation, so this is not a formality.
    return String(text === undefined || text === null ? '' : text)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

/**
 * Draw the sea and its stems.
 *
 * @param {HTMLElement} el      container
 * @param {Object} payload
 *   payload.seaBands  {Object}  band key -> count of ALL open CVEs in that band
 *   payload.results   {Array}   analysed verdicts (cve_id, priority_tier,
 *                               priority_score, epss, package, vendor,
 *                               rationale, kev)
 *   payload.liftTiers {Array}   tiers considered "lifted", default P0 and P1
 * @param {Function} onPick     called with a cve_id when a stem is clicked
 * @returns {Object} the ECharts instance, so the caller can resize/dispose
 */
function render(el, payload, onPick) {
    var results = (payload && payload.results) || [];
    var seaBands = (payload && payload.seaBands) || {};
    var lift = (payload && payload.liftTiers) || ['P0', 'P1'];

    var sea = BANDS.map(function (b) { return Number(seaBands[b.key] || 0); });
    var seaTotal = sea.reduce(function (a, b) { return a + b; }, 0);

    // Only the lifted rows get a stem, and only the strongest MAX_STEMS of
    // them. This was learned the hard way: the first version drew every lifted
    // CVE and, on a fleet where the model put 837 of 1020 above the waterline,
    // produced a solid wall of colour that hid both the sea and the point.
    //
    // The overflow count is not a rendering detail, it is the most important
    // number on the page. A pipeline whose job is to lift the important few
    // out of a sea, and which lifts four fifths of everything, has not
    // prioritised anything, and the chart should say so in the one place
    // somebody is looking rather than leave it to be inferred from a table.
    var allLifted = results.filter(function (r) {
        return lift.indexOf(r.priority_tier) >= 0;
    }).sort(function (x, y) {
        // Score first, then exploit likelihood, then KEV. The tie-break is not
        // cosmetic: the model's scores are coarse (one real fleet had 139
        // verdicts sharing the single value 95), so without it "the strongest
        // thirty" is an arbitrary thirty of a hundred and thirty-nine, and the
        // chart quietly picks favourites by insertion order.
        var byScore = Number(y.priority_score || 0) - Number(x.priority_score || 0);
        if (byScore) return byScore;
        var byEpss = Number(y.epss || 0) - Number(x.epss || 0);
        if (byEpss) return byEpss;
        return (y.kev === 'true' ? 1 : 0) - (x.kev === 'true' ? 1 : 0);
    });
    var lifted = allLifted.slice(0, MAX_STEMS);
    var overflow = allLifted.length - lifted.length;

    // Spread stems within their band so labels do not stack. Ordering by score
    // inside a band keeps the tallest nearest the band centre, which reads as
    // a peak rather than a picket fence.
    var byBand = {};
    lifted.forEach(function (r) {
        var b = epssBand(r.epss);
        (byBand[b] = byBand[b] || []).push(r);
    });
    var stems = [];
    Object.keys(byBand).forEach(function (b) {
        var group = byBand[b].sort(function (x, y) {
            return Number(y.priority_score || 0) - Number(x.priority_score || 0);
        });
        var span = 0.62;
        group.forEach(function (r, i) {
            var offset = group.length === 1
                ? 0
                : (-span / 2) + (span * i / (group.length - 1));
            stems.push({
                value: [Number(b) + offset, Number(r.priority_score || 0)],
                row: r,
            });
        });
    });

    // Log scale, because the sea spans orders of magnitude: a real fleet had
    // 4049 CVEs in the bottom band and 32 in the top, and a linear scale drew
    // the first bar and four invisible ones. The sea is a backdrop, so it is
    // compressed into the bottom fifth of the plot whatever its size.
    var logMax = Math.log10(Math.max.apply(null, sea.concat([10])));
    function seaHeight(count) {
        if (!count) return 0;
        return (Math.log10(count) / logMax) * 20;
    }

    var option = {
        animation: false,
        backgroundColor: 'transparent',
        grid: { left: 54, right: 22, top: 46, bottom: 46 },
        xAxis: {
            type: 'value',
            min: -0.6,
            max: BANDS.length - 0.4,
            interval: 1,
            name: 'exploit likelihood (EPSS)',
            nameLocation: 'middle',
            nameGap: 28,
            nameTextStyle: { color: '#8d99a6', fontSize: 11 },
            axisLabel: {
                color: '#8d99a6',
                formatter: function (v) {
                    var b = BANDS[Math.round(v)];
                    return b ? b.label : '';
                },
            },
            axisLine: { lineStyle: { color: '#3a4650' } },
            splitLine: { show: false },
        },
        yAxis: {
            type: 'value',
            min: 0,
            max: 100,
            axisLabel: { color: '#8d99a6' },
            // onZero false, and this is not a style preference. ECharts draws
            // an axis line at the other axis's ZERO by default, and this x
            // axis starts at -0.6 so that the first band is not clipped. The
            // y axis line therefore floated in the middle of the plot, at the
            // centre of the "<1%" band, reading exactly like a full height
            // stem with no head on it. Spotted only by looking at a render.
            axisLine: { onZero: false, lineStyle: { color: '#3a4650' } },
            splitLine: { lineStyle: { color: '#232c34' } },
        },
        tooltip: {
            trigger: 'item',
            confine: true,
            backgroundColor: '#1b2229',
            borderColor: '#3a4650',
            textStyle: { color: '#d6dee6', fontSize: 12 },
            extraCssText: 'max-width:380px;white-space:normal;',
        },
        series: [],
    };

    // THE SEA. A bar per band, scaled into the bottom quarter of the plot so
    // it reads as a horizon rather than competing with the stems. It carries
    // no labels on purpose: its job is to be large and undifferentiated.
    option.series.push({
        type: 'bar',
        name: 'sea',
        barWidth: '86%',
        silent: false,
        z: 1,
        itemStyle: { color: '#20303c' },
        data: sea.map(function (count, i) {
            return { value: [i, seaHeight(count)], count: count };
        }),
        tooltip: {
            formatter: function (p) {
                var band = BANDS[Math.round(p.value[0])];
                return '<b>' + escapeHtml(band ? band.label : '') + ' exploit likelihood</b><br/>'
                    + escapeHtml(p.data.count) + ' open CVEs in the fleet<br/>'
                    + '<span style="color:#8d99a6">not analysed individually; '
                    + 'the deterministic rules already decided the extremes</span>';
            },
        },
    });

    // THE WATERLINE. Drawn on the stem series so it sits above the sea.
    // 65 is where P1 begins in the expansion search's thresholds; anything
    // below it is not work for tonight.
    var stemSeries = {
        type: 'custom',
        name: 'lifted',
        z: 3,
        renderItem: function (params, api) {
            var x = api.value(0);
            var y = api.value(1);
            var top = api.coord([x, y]);
            var base = api.coord([x, 0]);
            var row = stems[params.dataIndex].row;
            var colour = TIER_COLOUR[row.priority_tier] || '#5b9bd5';
            return {
                type: 'group',
                children: [
                    {
                        type: 'line',
                        shape: { x1: top[0], y1: top[1], x2: base[0], y2: base[1] },
                        style: { stroke: colour, lineWidth: 1, opacity: 0.45 },
                    },
                    {
                        type: 'circle',
                        shape: { cx: top[0], cy: top[1], r: row.kev === 'true' ? 6 : 4 },
                        style: {
                            fill: colour,
                            stroke: row.kev === 'true' ? '#ffffff' : colour,
                            lineWidth: row.kev === 'true' ? 1.5 : 0,
                        },
                    },
                ],
            };
        },
        encode: { x: 0, y: 1 },
        data: stems,
        markLine: {
            silent: true,
            symbol: 'none',
            label: {
                formatter: 'waterline',
                color: '#6b7681',
                fontSize: 10,
                position: 'insideEndTop',
            },
            lineStyle: { color: '#3a4650', type: 'dashed', width: 1 },
            data: [{ yAxis: 65 }],
        },
        tooltip: {
            formatter: function (p) {
                var r = stems[p.dataIndex].row;
                var who = [r.vendor, r.package].filter(Boolean).join(' ');
                return '<b>' + escapeHtml(r.cve_id) + '</b> '
                    + '<span style="color:' + (TIER_COLOUR[r.priority_tier] || '#5b9bd5')
                    + '">' + escapeHtml(r.priority_tier) + '</span>'
                    + (r.kev === 'true' ? ' <span style="color:#e05c5c">KEV</span>' : '')
                    + '<br/>' + (who ? escapeHtml(who) + '<br/>' : '')
                    + '<span style="color:#8d99a6">' + escapeHtml(r.rationale || '') + '</span>';
            },
        },
    };
    option.series.push(stemSeries);

    var chart = echarts.init(el, null, { renderer: 'canvas' });

    if (!seaTotal && !stems.length) {
        // Empty state as graphic text rather than an empty grid, so a page with
        // no analysis yet says so instead of showing an axis and nothing else.
        option.graphic = [{
            type: 'text', left: 'center', top: 'middle',
            style: {
                text: 'No analysis yet. The sea fills when the queue search runs.',
                fill: '#6b7681', fontSize: 13,
            },
        }];
    }

    // The caption. Deliberately plain arithmetic rather than a judgement: the
    // operator is told how many were analysed, how many were lifted and what
    // share that is, and draws their own conclusion about whether a pipeline
    // that lifts most of what it sees is helping.
    var analysed = results.length;
    var pct = analysed ? Math.round((allLifted.length / analysed) * 100) : 0;
    // The percentage is of what was ANALYSED, never of the sea, and the wording
    // has to make that impossible to misread. An earlier version put the fleet
    // total and the percentage in the same breath, which invites "82% of my
    // CVEs are urgent" when the true statement is "82% of the ambiguous middle
    // that reached the model". The deterministic rules already removed both
    // extremes before the model saw anything, so the model was never choosing
    // from the sea at all: it was ranking what was left after the easy calls
    // were made, and a share of that is a different claim entirely.
    var caption = seaTotal.toLocaleString() + ' open CVEs in the fleet. '
        + 'The deterministic rules settled all but '
        + analysed.toLocaleString() + ', and of those '
        + allLifted.length.toLocaleString() + ' came back above the waterline ('
        + pct + '% of the ones asked about)'
        + (overflow > 0 ? ', strongest ' + lifted.length + ' drawn' : '');
    // The second line is a caveat, not decoration. These are CVE-level
    // verdicts: the fleet's worst case for each vulnerability, before the
    // expansion search steps each finding DOWN for the host it is actually on.
    // A reader who takes the percentage as "82% of my findings are urgent"
    // has read it wrong, and the chart should not let them.
    var caveat = 'fleet worst case per CVE, before the per-host adjustment';
    option.graphic = (option.graphic || []).concat([
        {
            type: 'text', left: 10, top: 4,
            style: { text: caption, fill: pct >= 50 ? '#e0a33c' : '#8d99a6', fontSize: 11 },
        },
        {
            type: 'text', left: 10, top: 20,
            style: { text: caveat, fill: '#6b7681', fontSize: 10 },
        },
    ]);

    chart.setOption(option);

    if (typeof onPick === 'function') {
        chart.on('click', function (params) {
            if (params.seriesName !== 'lifted') return;
            var row = stems[params.dataIndex] && stems[params.dataIndex].row;
            if (row && row.cve_id) onPick(row.cve_id);
        });
    }
    return chart;
}

export default { render: render, BANDS: BANDS, epssBand: epssBand };
