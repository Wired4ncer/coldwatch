"""Kept for the channels lane: the cipher moved to `coldwatch.crypto` when the storage layer
needed it too. Import from there in new code."""

from coldwatch.crypto.chacha20 import chacha20_xor

__all__ = ["chacha20_xor"]
