TA-riskability-ai
=================

Index definitions and search-time parsing for the Riskability AI analysis
pipeline. Deploy to INDEXERS ONLY (or a single instance), from the same
release as the riskability app.

Creates three indexes:

  riskability_ai_candidates   the queue the GPU box reads (7 day retention)
  riskability_ai_prioritized  prioritization results written back over HEC
                              (1 year)
  riskability_ai_alerts       P0/P1 events for downstream alerting (1 year)

Nothing writes to these indexes until an administrator switches AI analysis
on in the Riskability Configuration app, and the indexes are cheap while
empty. See docs/AI-MOD.md in the source repository for the pipeline
architecture and the HEC contract the GPU box must follow.
