"""Everything that talks to bitcoind: the RPC client and the scan supervisor.

Kept apart from `coldwatch.match` on purpose. The matching loop consumes a stream and compares
hashes; this package makes blocking calls to a node that will only do one thing at a time. They
have different failure modes, and reconciliation is about to depend on both — a dependency that
is much easier to reason about in one direction than in a cycle.

⚠️ The node is **pruned**. `getblock` below the prune height fails, so nothing here may assume
arbitrary historical retrieval. See docs/architecture.md §4.
"""

from __future__ import annotations

from .rpc import BitcoinRpc, RpcError, RpcTransportError
from .supervisor import ScanFailed, ScanQueueFull, ScanSupervisor, ScanUtxo

__all__ = [
    "BitcoinRpc",
    "RpcError",
    "RpcTransportError",
    "ScanFailed",
    "ScanQueueFull",
    "ScanSupervisor",
    "ScanUtxo",
]
