// Webpack 5, not the scaffold's webpack 1.
//
// The template pins ^1.12.6 (2015), which predates ES modules, package
// "exports" and tree shaking. Modern ECharts is ESM-first: webpack 1 either
// fails to parse it or silently resolves dist/echarts.js and bundles the whole
// ~1MB library with no dead-code elimination. Since this ships inside the .spl
// to an air-gapped search head, paying a megabyte for five chart types is not
// acceptable -- tree shaking is the entire reason for the upgrade.
//
// libraryTarget stays 'amd': Splunk Web loads visualizations through RequireJS
// and the vizapi modules must remain external, resolved by Splunk at runtime.
const path = require('path');

module.exports = {
    entry: './src/visualization_source.js',
    output: {
        path: __dirname,
        filename: 'visualization.js',
        // export: 'default' matters. Without it webpack hands AMD the ES
        // module namespace object -- { default: Ctor, __esModule: true } --
        // and Splunk fails with "this.options.vizConstructor is not a
        // constructor", because it expects the module value to BE the class.
        library: { type: 'amd', export: 'default' },
    },
    // 'api/...', NOT the scaffold's 'vizapi/...'.
    //
    // Splunk resolves these AMD ids itself at runtime; they must not be
    // bundled. The viztemplate scaffold names them 'vizapi/...', which this
    // Splunk does not serve -- the request 404s, the browser refuses the HTML
    // error page as a script, and every chart panel stays blank with nothing
    // in splunkd's logs. Splunk's own Monitoring Console visualisations use
    // 'api/SplunkVisualizationBase', which is the id that actually resolves.
    externals: [
        'api/SplunkVisualizationBase',
        'api/SplunkVisualizationUtils',
    ],
    optimization: {
        // Keep the Apache-2.0 banner in the emitted bundle rather than moving
        // it to a .LICENSE.txt sidecar, so the built file carries its own
        // attribution wherever it ends up.
        minimize: true,
    },
    performance: { hints: false },
};
