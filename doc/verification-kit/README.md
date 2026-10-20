# Subcento verification kit — v1.3.2

Everything the README claims, reproducible **offline**, on your machine, with our
production signatures. One runtime dependency: PyNaCl.

## Contents

| File | Role |
|---|---|
| `subcento_engine.py` | The engine (sha256 `7d5446aae593f5de…`, byte-identical to the production host) |
| `ofac_blocklist.json` | The local OFAC list the engine ships with (public US Treasury data) |
| `fixtures/*.json` | 5 verdicts signed by the production Ed25519 key |
| `verify_fixtures.py` | Offline verifier — refuses any key not announced out-of-band |
| `gen_fixtures.py` + `kit_inputs.json` | Regenerates the fixtures byte-for-byte with your own signing key |
| `test_jev_v2.py` | Doctrine battery: an unmeasured semantic layer is never a silent `SAFE` |
| `test_calldata_binding.py` | 27 calldata-binding edge cases (normalization, injection, vectors) |
| `test_verify_fixtures.py` | Attack battery: foreign-key re-signing must be rejected |
| `sha256sums.txt` | Fingerprints of everything in this directory |

## 1 — Verify the fixtures

A signature file cannot vouch for its own key. The expected key therefore comes
from the live service, out-of-band — never from the files being verified:

```bash
python3 -m pip install -r requirements.txt
KEY=$(curl -s https://subcento.alterfield.com/health \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["verify_key"])')
python3 verify_fixtures.py --expected-verify-key "$KEY"
```

Expected: 5 × `ok`.

| Fixture | Verdict | What it proves |
|---|---|---|
| `block_sanctioned` | BLOCK, measured | OFAC hit short-circuits before any external call |
| `caution_transfer` | CAUTION, measured | plain transfer path, capped by deterministic layer |
| `jev_semantic_blind` | CAUTION, not-measured | a Jev layer that never answers cannot yield `SAFE` (v1.3.2 doctrine) |
| `nonce_bound` | CAUTION, binding=`nonce-bound` | verdicts bind real 32-byte nonces, client-checkable |
| `not_measured_blind` | BLOCK, not-measured | total blindness fails closed, and `checks_failed` names **every** missing layer (`goplus`, `jev_semantic`) |

## 2 — Run the batteries

```bash
python3 test_jev_v2.py               # → "DECRET 1 — JEV V2 : VALIDÉ"
python3 test_calldata_binding.py     # → 27 checks OK
python3 test_verify_fixtures.py      # → "É4 — RESIGNATURE ETRANGERE REJETEE : BATTERIE VERTE"
```

`test_verify_fixtures.py` first demonstrates that the naive verifier (trusting the
key embedded in the file) accepts a verdict re-signed with an attacker key, then
shows this kit's verifier rejecting the same forgery.

## 3 — Reproduce the fixtures yourself

Timestamps and `latency_ms` are replayed from the production run (inside the
signed payload, hence frozen). `gen_fixtures.py` recomputes each verdict through
this engine and re-signs the canonical payload:

```bash
python3 -c 'import nacl.signing; open("/tmp/test_signing.key","wb").write(nacl.signing.SigningKey.generate().encode())'
SUBCENTO_KEY_PATH=/tmp/test_signing.key SUBCENTO_OUTDIR=/tmp/fx_repro python3 gen_fixtures.py
```

Everything identical except the `signature` and informational `verify_key`
fields — check with e.g.
`diff <(jq 'del(.signature,.verify_key)' -s /tmp/fx_repro/nonce_bound.json) <(jq 'del(.signature,.verify_key)' -s fixtures/nonce_bound.json)`.
Your key, same truth.

## Key provenance

Production `verify_key`: `99d59000e66922a9…` (full value at `/health`). The private
half was generated once on the production host, lives at 600 perms, and has never
left it.

MIT · subcento@pm.me
