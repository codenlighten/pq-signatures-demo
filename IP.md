# IP records

| Date | Covers | Type | Record hash | Signer | Tag |
|---|---|---|---|---|---|
| 2026-11-26 | Commit `d9338bc`: composition of third-party Ed25519 and ML-DSA-65 libraries into a hybrid signing component, specification, source, tests and documentation. No authorship claimed in the algorithms, the libraries, NIST's test vectors and the generated lockfile. | software, hash-only | [`44e96670ec41a7019bfd7c26e3b683ffd5e5d768282234afc9dee774ccb0d925`](https://iptrust.org/v/44e96670ec41a7019bfd7c26e3b683ffd5e5d768282234afc9dee774ccb0d925) | Gregory J. Ward | `ip-2026-11-26` |

A record is evidence that the committed content existed by the time of its anchor and that the signer made
the statement; it does not create or register any right. Anchoring completes some hours after submission.
Files under `third_party/`, where present, are not part of the record.

## Verifying

Verification needs the evidence package for the record, which the author holds and which is not committed
here. With it in `.iptrust/`:

```
git worktree add /tmp/at-tag-pq-signatures-demo ip-2026-11-26
cp -r .iptrust /tmp/at-tag-pq-signatures-demo/
(cd /tmp/at-tag-pq-signatures-demo && iptrust2 verify 44e96670ec41a7019bfd7c26e3b683ffd5e5d768282234afc9dee774ccb0d925 --fetch-headers)
git worktree remove --force /tmp/at-tag-pq-signatures-demo
```

Expect `verdict: valid` and `content: matched` once both chains have anchored.
