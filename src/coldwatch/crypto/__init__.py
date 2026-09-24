"""The two stdlib-only primitives this project hand-rolls, and the AEAD built from them.

Everything here has published test vectors (RFC 8439), and that is the whole reason it is
hand-rolled rather than a dependency -- the policy decided in issue #3: a third-party package is
admissible only for work that is impossible or dangerous in Python *and* has no vectors to
check a transcription against. Arithmetic on public counters and nonces is neither.

`chacha20` and `poly1305` are the primitives; `aead` composes them into the RFC 8439 AEAD that
`coldwatch.storage` uses for every ciphertext column (`spk_ct`, `label_ct`, `dest_ct`).
"""

from coldwatch.crypto.aead import AuthenticationFailed, open_, seal
from coldwatch.crypto.chacha20 import chacha20_xor
from coldwatch.crypto.poly1305 import poly1305_mac

__all__ = ["AuthenticationFailed", "chacha20_xor", "open_", "poly1305_mac", "seal"]
