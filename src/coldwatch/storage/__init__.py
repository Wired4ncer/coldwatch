"""Persistence: SQLite schema, keyed HMACs at rest, the transient outbox.

Nothing here yet.

⚠️ There is no event-history table and there must not be one. A stored "item N fired at
14:32:07" row is a timing side channel that reverses the HMAC anonymity when matched against
public chain data. See CONTRIBUTING.md invariant I3 and docs/architecture.md §3.
"""
