# Third-party code bundled into visualization.js

AppInspect and Splunkbase vetting both expect vendored JavaScript to be
identifiable: which library, which version, which licence, and where it came
from. `visualization.js` is a webpack bundle, so nothing below is separately
readable inside the package - this file is the manifest for it.

| Library | Version | Licence | Source |
|---|---|---|---|
| Apache ECharts | 5.5.1 | Apache-2.0 | https://github.com/apache/echarts |
| zrender (bundled by ECharts) | per echarts 5.5.1 | Apache-2.0 | https://github.com/ecomfe/zrender |

ECharts is Apache-2.0 and embeds portions under BSD licences; the upstream
notices are reproduced verbatim in `ECHARTS-LICENSE.txt` rather than summarised,
and webpack preserves the licence banners of bundled modules in
`visualization.js.LICENSE.txt`.

Nothing is fetched at runtime. The bundle is built from the pinned versions in
`package.json` / `package-lock.json` and ships inside the app, which is a
requirement rather than a preference: this app runs on air-gapped search heads.

To rebuild:

    cd appserver/static/visualizations/riskability_chart
    npm ci
    npx webpack --mode production

`node_modules/` is a build-time dependency only and is deliberately excluded
from both the repository and the package.
