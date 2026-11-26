# hybrid-sig v1: specification

A hybrid signature: one Ed25519 signature and one ML-DSA-65 signature over the same bytes. Both must verify.
This is a demonstration format of this repository. It is **not** the IETF composite-signature format and does
not claim to interoperate with it.

## Algorithms

- **Ed25519** (RFC 8032, pure). Acceptance policy, stricter than the RFC requires, applied to both the public
  key `A` and the signature point `R`: the 32 bytes must be the canonical encoding of the point they decode to,
  and the point must be in the prime-order subgroup and not the identity. (Every non-canonical encoding happens
  to decode to a point the second condition already excludes; both conditions are checked anyway.) The scalar `S` must be below the
  group order. Verification uses the library's strict equation.
- **ML-DSA-65** (FIPS 204), the pure (not pre-hash) external interface, with the FIPS context string set to the
  ASCII bytes `hybrid-sig-v1`. Signing is hedged: fresh randomness for every signature. If the random
  generator fails, signing fails; there is no silent fall-back to deterministic signing.

Both come from third-party libraries. No cryptographic primitive is implemented here.

## Keys

- Secret key: two independent 32-byte seeds from the operating system's random generator, one per algorithm.
  Neither is derived from the other. Do not use either component key in any other protocol.
- Public key encoding (1988 bytes): `"HSP1"` (4) ‖ Ed25519 public key (32) ‖ ML-DSA-65 public key (1952).
- Key id: SHA-256 of the whole public key encoding.

## What is signed

    T = "hybrid-sig-v1" ‖ 0x00 ‖ key_id (32) ‖ len(context) (1 byte) ‖ context (0..255 bytes) ‖ message

- `context` is the **application** context ("invoice", "release"): exact bytes, no text normalisation. It lives
  inside `T`. It is not the FIPS 204 context string, which is fixed as above.
- The fields before `message` have fixed or length-prefixed sizes, so for one key id, different (context,
  message) pairs give different `T`. Separating keys relies on their ids differing (SHA-256 collision
  resistance).
- Ed25519 signs `T`. ML-DSA-65 signs `T`.

## Signature encoding (3377 bytes)

    "HSS1" (4) ‖ Ed25519 signature (64) ‖ ML-DSA-65 signature (3309)

## Verification

The **verifier** supplies the public key it trusts and the context it expects. Neither is taken from the
signature, and a key delivered alongside a signature proves nothing.

1. The public key and signature have exactly the lengths and magic values above; anything else is refused.
2. The Ed25519 points pass the policy above.
3. Rebuild `T` from the verifier's own public key, context and the message.
4. Both signatures verify. There is no mode that accepts one of them.

## Security: what this gives, and under which assumptions

- **Existential unforgeability (EUF-CMA) if either component has it.** Assuming the two keys were generated
  independently, `T` is unambiguous (above), and at least one of Ed25519 and ML-DSA-65 remains EUF-CMA secure,
  an attacker who has seen signatures cannot produce a valid hybrid signature on a **new** `T`.
- **Strong unforgeability is not promised.** If either component's secret key is compromised, its holder can
  make a second, different signature for an already signed `T` by replacing that half.
- **Binding to the key.** `T` includes the SHA-256 of the complete public key, so (assuming SHA-256 is
  collision resistant) a component signature made for one hybrid key is not valid under another hybrid key that
  shares one of its halves. This does not authenticate any key: whoever can replace the verifier's trusted key
  can sign with their own.
- **Only weak non-separability.** Each half is an ordinary signature over `T`. A plain Ed25519 verifier given
  `T` as its message accepts the Ed25519 half. The fixed prefix makes that visible; it cannot prevent it.
  Applications must verify hybrid keys only with a hybrid verifier.
- **Context separates applications only if the verifier chooses it.** An application that takes the context
  from the sender gets no separation.

## Out of scope

No certificates, expiry, revocation, rotation or trusted time. No encryption or key exchange. No side-channel
analysis of this code, and no audit. This is a signing component, not a secure system.
