// Same recipe as riskability_chart: webpack 5, AMD output, vizapi external.
//
// library.export = 'default' is required -- without it AMD receives the ES
// module namespace object and Splunk fails with "vizConstructor is not a
// constructor".
const path = require('path');

module.exports = {
    entry: './src/visualization_source.js',
    output: {
        path: __dirname,
        filename: 'visualization.js',
        library: { type: 'amd', export: 'default' },
    },
    externals: [
        'api/SplunkVisualizationBase',
        'api/SplunkVisualizationUtils',
    ],
    optimization: { minimize: true },
    performance: { hints: false },
};
