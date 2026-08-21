# Third-party code bundled into visualization.js

`visualization.js` is a webpack bundle, so nothing below is separately readable
inside the package. This file is the manifest for it.

| Library | Version | Licence | Source |
|---|---|---|---|
| Tabulator | 6.3.0 | MIT | https://github.com/olifolkerd/tabulator |

`visualization.css` is Tabulator's `tabulator_midnight` theme concatenated with
`overrides.css` from this directory, which pulls it onto the Riskability
palette. Both halves are plain CSS and readable in the shipped file.

Only the Tabulator modules this table uses are registered — sort, filter,
format, edit (which supplies the header-filter inputs), column resize, page,
download, menu and tooltip — rather than `TabulatorFull`, which would bundle
every feature including ones with heavier dependencies.

Nothing is fetched at runtime; this app runs on air-gapped search heads.

To rebuild:

    cd appserver/static/visualizations/riskability_grid
    npm ci
    npx webpack --mode production
    cat node_modules/tabulator-tables/dist/css/tabulator_midnight.min.css \
        overrides.css > visualization.css

`node_modules/` is a build-time dependency only and ships in neither the
repository nor the package.
