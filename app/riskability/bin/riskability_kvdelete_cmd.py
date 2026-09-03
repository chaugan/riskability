#!/usr/bin/env python
"""``riskabilitykvdelete`` - delete KV Store documents by key, and nothing else.

Usage in SPL::

    ... | fields _key | riskabilitykvdelete collection=riskability_aiverdicts

Why this exists. The one honest way to remove a document from a KV Store
collection inside a search was outputlookup, which does not delete: it
REWRITES the whole collection through a lookup, and a lookup carries only the
fields its transforms stanza lists. Any field a handler had added to a
document and not to that list was stripped on every run. The on-demand AI
explanations went that way, hourly, for as long as the verdict garbage
collector existed, and it looked exactly like a restart losing them.

A delete by key cannot lose a field it has never heard of, which is the
property a housekeeping job over somebody else's documents needs. This
command deletes each _key it is handed and reports the count. It writes
nothing, and a row without a _key is skipped rather than guessed at.

Streaming command: it runs where the rows are and needs the search's own
session, which splunklib hands it as self.service. Deleting is admin-tier on
every collection this app ships, so a search run by a role without write
access simply deletes nothing and says so in its output.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from splunklib.searchcommands import Configuration, StreamingCommand, Option, dispatch  # noqa: E402

BATCH = 500


@Configuration(required_fields=["_key"])
class RiskabilityKvDeleteCommand(StreamingCommand):
    collection = Option(require=True, doc="The KV Store collection to delete from.")

    def stream(self, records):
        keys = []
        skipped = 0
        for record in records:
            key = str(record.get("_key") or "").strip()
            if key:
                keys.append(key)
            else:
                skipped += 1
        deleted = 0
        failed = ""
        try:
            data = self.service.kvstore[str(self.collection)].data
            for i in range(0, len(keys), BATCH):
                chunk = keys[i:i + BATCH]
                data.delete(query=json.dumps({"_key": {"$in": chunk}}))
                deleted += len(chunk)
        except Exception as exc:
            failed = str(exc)[:200]
        yield {"collection": str(self.collection), "requested": len(keys),
               "deleted": deleted, "skipped_no_key": skipped, "error": failed}


dispatch(RiskabilityKvDeleteCommand, sys.argv, sys.stdin, sys.stdout, __name__)
