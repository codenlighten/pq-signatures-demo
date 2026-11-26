# pq-signatures-demo: hybrid Ed25519 + ML-DSA-65 signatures, checked against NIST's vectors

A small Rust signing component that signs every message twice, with Ed25519 and with the post-quantum algorithm ML-DSA-65 (FIPS 204), and accepts it only if **both** signatures verify. Both algorithms come from **third-party libraries**; nothing cryptographic is implemented here. **It is a demonstration and has not been audited.**

The work shown is the part around the libraries, where hybrid schemes tend to go wrong: making sure a half cannot be dropped, moved to another key or reused elsewhere, pinning down which inputs are accepted, and saying precisely what the combination does and does not guarantee.

## Run it

Tested with Rust 1.98.1 only (the test-only `ml-dsa` crate itself asks for 1.87 or newer). The command line needs Unix; the library does not.

```bash
cargo test --locked
cargo run --release -- keygen --secret my.key --public my.pub
cargo run --release -- sign   --secret my.key --context release --in README.md --out readme.sig
cargo run --release -- verify --public my.pub --context release --in README.md --signature readme.sig
```

`verify` exits 0 if both signatures verify, 1 if not, and 2 for a usage or file error. The secret key file is created readable by its owner only, is refused if others can read it, and nothing is ever overwritten.

## The construction

The full specification is [SPEC.md](SPEC.md). In short, both algorithms sign

    "hybrid-sig-v1" ‖ 0x00 ‖ SHA-256(complete public key) ‖ context length ‖ context ‖ message

| | Bytes |
|---|---|
| Public key (`"HSP1"`, Ed25519, ML-DSA-65) | 1988 |
| Secret key (`"HSK1"`, two independent 32-byte seeds) | 68 |
| Signature (`"HSS1"`, Ed25519, ML-DSA-65) | 3377 |

Ed25519 points (the public key and `R`) must be canonically encoded, in the prime-order subgroup and not the identity: stricter than the library's "strict" mode, which accepts points that merely have a small-order component. ML-DSA signing is randomised; if the system's random generator fails, nothing is signed.

## Limits: what it gives, and what it does not

- A forger needs both algorithms: assuming independent keys and that **at least one** of them remains existentially unforgeable, signatures on new messages cannot be forged.
- **Strong unforgeability is not promised.** Whoever holds one of the two component keys can produce a second valid signature for a message that was already signed. A test does exactly that.
- A half made for one hybrid key does not verify under another that shares a component (assuming SHA-256 is collision resistant).
- **Each half is an ordinary signature** over the bytes above. A plain Ed25519 verifier given those bytes accepts the Ed25519 half. A test asserts this, so the limit cannot change unnoticed.
- It does **not** authenticate keys. Whoever can replace the verifier's trusted public key can sign with their own.
- A context separates applications only if the **verifier** chooses it.
- No certificates, expiry, revocation, rotation, trusted time, encryption or key exchange. This is a signing component, not a secure system, and it is not the IETF composite-signature format.

## Evidence

### NIST test vectors, two libraries

The component signs with [`fips204`](https://crates.io/crates/fips204). A second, independently written library, RustCrypto's [`ml-dsa`](https://crates.io/crates/ml-dsa), is used **only in tests** as a second opinion. Both are run against NIST's ACVP vectors for ML-DSA-65 ([provenance and NIST's notice](third_party/nist-acvp/NOTICE.md)):

| NIST vectors (external, pure interface) | Cases | `fips204` | `ml-dsa` |
|---|---|---|---|
| Key generation from seed | 25 | all match | all match (public keys) |
| Signing, deterministic and randomised, byte for byte | 30 | all match | all match |
| Verification, both accepting and rejecting cases | 15 | all verdicts match | all verdicts match |

The two libraries also derive the same public keys from 100 further seeds and accept each other's signatures. Not covered: NIST's pre-hash and internal-interface groups, and ML-DSA-44 and 87, none of which this component uses.

### Attacks

[`tests/attacks.rs`](tests/attacks.rs) alters, moves or drops part of a signature in each way it can think of and checks the specific error: either half dropped, zeroed or taken from another signature; a half moved to a key that shares it; context and message boundary shifted; every byte of a signature and of a public key changed; a second form of the Ed25519 scalar; small-order and mixed-order points; wrong lengths and magic.

### Tests

39 tests pass; `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` are clean. Developed on a Linux (WSL 2) machine; CI runs the same steps from a clean checkout.

### Deliberate breaks

27 changes were made one at a time to the code, the tests run and the code restored (39 of 39 pass afterwards). **25 were caught. Two survive, and cannot be caught**, because they do not change behaviour:

| Surviving change | Why no test can see it |
|---|---|
| The explicit "canonical encoding" rule removed from the point check | Every non-canonical Ed25519 encoding decodes to a point the other two rules already refuse. A test enumerates all 40 such encodings and shows this. The rule stays as a second line of defence. |
| Ed25519 "strict" verification replaced by the lenient one | The point rules run first and refuse what strict mode would refuse (small-order points); both modes require a canonical scalar. |

The 25 caught: either half not checked; either point unchecked; small-order components or the identity allowed; the key id, context length or domain prefix not signed; a long context truncated; the key id ignoring one half; longer inputs or wrong magic accepted; a random-generator failure ignored (two places); deterministic signing; one seed used for both algorithms; an empty FIPS context; a readable secret key file; the permission check removed; existing files overwritten; a half-finished key generation left behind; size limits not enforced; a long context reported as a bad signature; a failed verification exiting 0.

## Timings

One run of the example program (`examples/timings.rs`, 2,000 calls per row, 1 KiB messages, release build), pinned to one CPU of an Intel i7-8750H (a 2018 laptop) under WSL 2 on Windows, Rust 1.98.1, load average about 1 to 1.5, on 2026-11-25. CPU frequency and temperature could not be read from inside WSL. A second run's medians agreed within 2%.

| Scheme | Operation | Median µs | 5th to 95th percentile |
|---|---|---|---|
| Ed25519 | key generation | 72 | 72 to 108 |
| Ed25519 | sign | 93 | 92 to 133 |
| Ed25519 | verify | 135 | 135 to 238 |
| ML-DSA-65 (`fips204`) | key generation | 1079 | 1026 to 1760 |
| ML-DSA-65 (`fips204`) | sign | 2403 | 1047 to 7276 |
| ML-DSA-65 (`fips204`) | verify | 717 | 698 to 1382 |
| hybrid | key generation | 1627 | 1533 to 2361 |
| hybrid | sign | 2421 | 1121 to 7371 |
| hybrid | verify | 1065 | 1010 to 1748 |

ML-DSA signing time varies severalfold by design (it retries until a candidate signature is safe to publish), so its median says more than any single call. These numbers describe these libraries, this build and this machine; they are not a comparison of the algorithms.

## What running it found

- **My test for a second point encoding proved there was nothing to find.** It searched for a valid prime-order Ed25519 point with two encodings and found none, which is why one safety rule above is redundant.
- **Nothing checked that the two key seeds differ.** Using one seed for both algorithms would have passed every test; a test now rejects it.
- **A test failed once in dozens of runs.** The cause was the machine: its Linux subsystem finished starting mid-run and emptied `/tmp`, deleting a test's folder. Tests now use Cargo's own scratch directory.

## Independent review

An independent AI review (a different model) looked at the specification before any code was written, and again at the finished code. It found no way to bypass verification.

| Finding | Fix |
|---|---|
| Design: security claims stated more strongly than they hold (unforgeability, key binding) and an underspecified rule for acceptable points | Assumptions stated; exact point policy specified and enforced |
| Key generation could leave a secret key behind without its public key | Public key written first; partial results removed; test |
| The secret file's permissions were checked by name, then the file read separately | Opened once; permissions checked on the same handle that is read |
| A huge input file was read entirely before being rejected | Reads are bounded (message limit 64 MiB); test |
| The memory-wiping claim was not established | A compile-time check for the types claimed, and the claim narrowed |
| The "second signature" test signed with both keys, so it did not show the one-key case it described | Rewritten to use only one component key |
| Two sentences claimed more than the code does | Narrowed |
| An over-long context was reported as a bad signature | Usage error; test |

## Library choice

As checked on 2026-11-25 in the [RustSec advisory database](https://github.com/rustsec/advisory-db): `fips204` had no advisory on file, `ml-dsa` had one (a timing side channel in signing, fixed before the release used here), and `libcrux-ml-dsa` had four dated 2026, two of them in verification, all fixed in later releases. An empty advisory list is not an audit.

- `fips204` states that, within one signing attempt, it does not branch on secret data, and makes no constant-time claim for verification. I have not verified that.
- RustCrypto's `ml-dsa` states it has never been independently audited; here it is only a test oracle.

CI runs `cargo audit` against the dependency tree on every push.

## Dependencies

`fips204`, `ed25519-dalek`, `curve25519-dalek`, `sha2`, `getrandom` and `zeroize` at run time; `ml-dsa`, `serde_json` and `hex` for tests. All are public crates; none of their code is copied here.

## Licence

MIT, see `LICENSE`. `third_party/nist-acvp/mldsa65.json` is NIST's data under NIST's notice, not under this licence.
