"""The matching loop: ZMQ ingest, HMAC comparison, gap detection, reconciliation.

⚠️ Nothing here may assume it has seen every transaction. The ZMQ stream drops messages
silently under load (measured: ~832 lost across 3 sequence gaps in 40 minutes, no error
raised). The stream is a latency optimisation; correctness comes from periodic reconciliation
against the UTXO set. See CONTRIBUTING.md invariant I4.

What is here so far: sequence tracking, transaction parsing, keyed hashing, and the
compare-and-update loop — all of it exercised offline against the fixtures. Two live SUB
sockets and the reconciler that repairs what they miss are still to come (issue #4); until
the reconciler exists, `SequenceTracker.needs_reconciliation` is a flag nobody clears.
"""

from __future__ import annotations

from .block import Block, MalformedBlock, parse_block
from .keys import (
    Subkeys,
    canonical_outpoint,
    derive_subkeys,
    hkdf,
    outpoint_hmac,
    spk_hmac,
    txid_from_display,
    txid_to_display,
)
from .matcher import InMemoryWatchIndex, Match, Matcher, WatchIndex
from .sequence import Anomaly, AnomalyKind, SequenceTracker, TopicState, parse_seq_part
from .stream import (
    TOPIC_BLOCK,
    TOPIC_TX,
    SeenTransactions,
    StreamIngest,
    StreamMessage,
)
from .tx import MalformedTransaction, OutPoint, Transaction, TxOutput, parse_tx, read_tx

__all__ = [
    "TOPIC_BLOCK",
    "TOPIC_TX",
    "Anomaly",
    "AnomalyKind",
    "Block",
    "InMemoryWatchIndex",
    "MalformedBlock",
    "MalformedTransaction",
    "Match",
    "Matcher",
    "OutPoint",
    "SeenTransactions",
    "SequenceTracker",
    "StreamIngest",
    "StreamMessage",
    "Subkeys",
    "TopicState",
    "Transaction",
    "TxOutput",
    "WatchIndex",
    "canonical_outpoint",
    "derive_subkeys",
    "hkdf",
    "outpoint_hmac",
    "parse_block",
    "parse_seq_part",
    "parse_tx",
    "read_tx",
    "spk_hmac",
    "txid_from_display",
    "txid_to_display",
]
