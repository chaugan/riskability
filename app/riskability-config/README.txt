Riskability Configuration
=========================

Administrative configuration for Riskability. Install this app on the search
head, from the same release as the riskability app itself.

It is deliberately a separate app, readable only by the admin and sc_admin
roles (see metadata/default.meta): the dashboards analysts use every day sit
in the main riskability app and carry nothing that changes how the app works.
Everything that does lives here:

  * Feed administration  — bundle upload, import, index names, direct fetch
  * AI analysis          — the GPU CVE prioritization pipeline: endpoint,
                           secret, hardware profile, dispatch

The pages call REST endpoints registered by the riskability app, which guard
themselves by capability (admin_all_objects for the feed, riskability_ai_admin
for AI) — the app-level restriction here is ergonomics; the capability is the
control.

See docs/AI-MOD.md in the source repository for the full AI pipeline
documentation.
