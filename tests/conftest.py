"""Shared fixtures: the recorded streams, and a key to hash with.

No node, no network, no credentials — see CONTRIBUTING.md §2. The recorded streams are
synthetic and reproducible from a seed; CI regenerates them and fails if a byte changed,
which is how "someone captured real data" gets caught rather than reviewed for.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coldwatch.match import StreamMessage, derive_subkeys

FIXTURES = Path(__file__).parent / "fixtures"


def load_stream(name: str) -> list[StreamMessage]:
    """Read a JSONL fixture as the ingest would receive it off the wire."""
    messages = []
    for line in (FIXTURES / name).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        record = json.loads(line)
        messages.append(
            StreamMessage(
                topic=record["topic"],
                body=bytes.fromhex(record["hex"]),
                seq=int(record["seq"]),
            )
        )
    return messages


@pytest.fixture
def contiguous_stream() -> list[StreamMessage]:
    """120 transactions, no drops. The baseline: a correct detector reports zero gaps."""
    return load_stream("stream-sample.jsonl")


@pytest.fixture
def gapped_stream() -> list[StreamMessage]:
    """The same stream with three deliberate drops — 599, 26 and 207 messages missing.

    Nothing in any payload indicates a drop. The counter is the only evidence there is.
    """
    return load_stream("with-gap.jsonl")


@pytest.fixture
def k_match() -> bytes:
    """A match subkey from a fixed test master. Not a credential shape — 32 bytes of 'k'."""
    return derive_subkeys(b"k" * 32).match
