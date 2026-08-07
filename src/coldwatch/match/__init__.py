"""The matching loop: ZMQ ingest, HMAC comparison, gap detection, reconciliation.

Nothing here yet — this is issue #4.

⚠️ Whatever lands here must not assume it has seen every transaction. The ZMQ stream drops
messages silently under load (measured: ~832 lost across 3 sequence gaps in 40 minutes, no
error raised). The stream is a latency optimisation; correctness comes from periodic
reconciliation against the UTXO set. See CONTRIBUTING.md invariant I4.
"""
