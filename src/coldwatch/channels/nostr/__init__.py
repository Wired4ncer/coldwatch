"""NIP-17 gift-wrapped DM delivery (issue #3).

Split into one file per concern rather than one large module, the way `coldwatch.match` is --
`bech32.py` and `chacha20.py` are stdlib-only encodings/ciphers with their own vector tests;
`nip44.py` and `nip01.py` are the two places this needs `coincurve` for real elliptic-curve
work; `giftwrap.py` composes those into the rumor/seal/wrap layers NIP-59 defines; `channel.py`
is the `Channel` protocol implementation that ties it to relay transport.
"""

from coldwatch.channels.nostr.channel import MissingConfig, NostrChannel

__all__ = ["MissingConfig", "NostrChannel"]
