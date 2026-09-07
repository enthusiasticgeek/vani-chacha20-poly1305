# chacha20_poly1305

ChaCha20 (RFC 8439 section 2.3/2.4), Poly1305 (RFC 8439 section 2.5),
and the ChaCha20-Poly1305 AEAD construction (RFC 8439 section 2.8) —
pure vāṇी, hardware-agnostic and heap-free.

Extracted from [Dhruva OS](https://github.com/enthusiasticgeek/dhruvaos)'s
Pi 1 kernel — the only crypto primitive in that project's roadmap that
existed on Pi 1 with **no** Pi 4/5-side counterpart to extract from
(`vani-crypto-hash`, `vani-curve25519`, and `vani-pki` all started as
Pi 4/5 code moved outward instead).

## Two layers

**Streaming primitives** (no length cap at all):

```
fn chacha20_block(key: ref [u8; 32], counter: u32, nonce: ref [u8; 12]) -> [u8; 64]
fn chacha20_xor_chunk(key: ref [u8; 32], nonce: ref [u8; 12], counter: u32, chunk: ref [u8; 64], chunk_len: i64) -> [u8; 64]

struct Poly1305Ctx { ... }
fn poly1305_init(key: ref [u8; 32]) -> Poly1305Ctx
fn poly1305_update(ctx: ref Poly1305Ctx, chunk: ref [u8; 256], chunk_len: i64) -> Poly1305Ctx
fn poly1305_finalize(ctx: ref Poly1305Ctx) -> [u8; 16]
```

ChaCha20 blocks are independent under its own CTR-mode construction
(RFC 8439 section 2.4), so a caller can process a message of any
length just by looping `chacha20_xor_chunk` and incrementing the
block counter — no accumulating state needed. Poly1305's polynomial
evaluation genuinely does need accumulating state across the whole
message, so `Poly1305Ctx` mirrors
[`vani-crypto-hash`](https://github.com/enthusiasticgeek/vani-crypto-hash)'s
own `Sha256Ctx`/`Sha512Ctx` streaming design (the same carry-buffer-
for-a-partial-block technique).

**One-shot convenience layer**, capped at 512 bytes of plaintext/
ciphertext and 64 bytes of AAD — the same practical ceiling
[`vani-curve25519`](https://github.com/enthusiasticgeek/vani-curve25519)'s
Ed25519 `msg` parameter settled on, for the same reason: there is no
`[expr; N]` array-repeat literal in vāṇी yet (see
`vani-compiler/docs/DHRUVAOS_ERGONOMICS_TODO.md`), so a larger fixed
cap means a larger hand-typed zero-literal. Built directly on the
streaming primitives above, not a separate implementation:

```
fn chacha20_encrypt(key: ref [u8; 32], nonce: ref [u8; 12], initial_counter: u32, data: ref [u8; 512], data_len: i64) -> [u8; 512]
fn poly1305_mac(key: ref [u8; 32], msg: ref [u8; 512], msg_len: i64) -> [u8; 16]
fn poly1305_verify_constant_time(a: ref [u8; 16], b: ref [u8; 16]) -> i64

struct AeadEncryptResult { ciphertext: [u8; 512], tag: [u8; 16] }
struct AeadDecryptResult { ok: i64, plaintext: [u8; 512] }
fn chacha20_poly1305_encrypt(key: ref [u8; 32], nonce: ref [u8; 12], aad: ref [u8; 64], aad_len: i64, plaintext: ref [u8; 512], plaintext_len: i64) -> AeadEncryptResult
fn chacha20_poly1305_decrypt(key: ref [u8; 32], nonce: ref [u8; 12], aad: ref [u8; 64], aad_len: i64, ciphertext: ref [u8; 512], ciphertext_len: i64, tag_in: ref [u8; 16]) -> AeadDecryptResult
```

A consumer with a longer real message (DhruvaOS's own Pi 1 TLS
records, currently up to 2048 bytes) is expected to call the
streaming primitives directly against its own buffer in a chunked
loop — the same adapter shape `vani-crypto-hash`'s own `sha256_hash`
heap adapter in DhruvaOS's `kernel_main.vani` already uses. This
package's `chacha20_poly1305_encrypt`/`poly1305_mac` are themselves
already written that way (capped, not a separate one-shot
implementation), so they double as a working template.

`chacha20_poly1305_decrypt` returns `ok: 0` (plaintext left as
zeros) on a tag mismatch — reject, don't guess; never act on
`plaintext` from a call that returned `ok: 0`.

## Verification

Every KAT was independently re-verified against the real
`cryptography` Python library's `ChaCha20`/`Poly1305`/
`ChaCha20Poly1305` primitives before being ported here: RFC 8439
section 2.3.2's ChaCha20 block vector, section 2.5.2's Poly1305
vector (plus an empty-message edge case and an altered-message-
produces-a-different-tag check), and a DhruvaOS-original AEAD
vector (encrypt, decrypt round trip, and a tampered-ciphertext-must-
fail check). `test/host_test.vani` runs all three self-tests under
the host harness.
