# Subcento

**Verify before you sign. Not after.**

Pre-flight transaction verification for AI agents — one `POST /check` in front of
every signature. Pay **0.002 USDC on Base** with [x402](https://x402.org), get back a
**signed verdict** (`SAFE | CAUTION | BLOCK`) with per-layer evidence. No API keys,
no signup, no humans in the loop. A machine pays a machine for the one thing an
agent should never sign without: an independent second opinion.

**Live endpoint:** https://subcento.alterfield.com ·
[Listing on x402scan](https://www.x402scan.com/server/58adf777-807c-4f31-b6d9-9eba8c186b6e) ·
[Machine contract](https://subcento.alterfield.com/openapi.json) ·
[llms.txt](https://subcento.alterfield.com/llms.txt)

## What runs before your signature

| # | Layer | Question it answers |
|---|-------|---------------------|
| 1 | **GoPlus** | Is this address a known drainer / risky contract? |
| 2 | **OFAC blocklist** | Is this address sanctioned by the US Treasury? (local copy, refreshed weekly) |
| 3 | **Jev semantic analysis** | What does the *calldata actually do* — and does it match your agent's *declared intent*? ([official TypeSafe AI System One API](https://typesafe.ai), version pinned) |
| 4 | **Deterministic checks** | Unlimited approvals, honeypot patterns, value sanity — pure code, no model |

Every verdict is **Ed25519-signed**. Don't trust the service? Don't trust us —
**verify the signature with the key from `/health`** and see exactly what you paid for.

## Fail-closed by design

If a trust layer is unreachable, you get `BLOCK` — never a generous `SAFE`.
Subcento fails in the direction of your funds, not the direction of its uptime.

## Quickstart

Discovery is free. Payment is x402 — your agent handles the 402 natively:

```bash
curl -X POST https://subcento.alterfield.com/check \
  -H 'content-type: application/json' \
  -d '{"to":"0x…target","calldata":"0x…","value":0,"intent":"swap ETH for USDC"}'
# → HTTP 402 + Payment-Required (x402 v2): 0.002 USDC, Base mainnet, 60s timeout
```

With the official x402 client, the payment is transparent — same call, paid retry:

```python
# pip install x402
# See client_example.py for the decision-loop pattern (SAFE→sign, CAUTION→escalate, BLOCK→refuse)
```

### Verify a verdict — in 8 lines

```python
import hashlib, json
from nacl.signing import VerifyKey
from nacl.encoding import HexEncoder

v = verdict  # the JSON you got back from /check
payload = {k: v[k] for k in ("verdict", "to", "function", "reasons", "timestamp")}
canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
digest = hashlib.sha256(canonical.encode()).digest()
VerifyKey(v["verify_key"], HexEncoder).verify(digest, bytes.fromhex(v["signature"]))
# raises on any tampering; passing = this exact verdict left Subcento untouched
```

## Architecture (the honest one)

- **Edge paywall, not app paywall.** Payment gating lives in Caddy via
  `caddy-x402avm` (`deploy/Caddyfile`) — the backend never sees unpaid traffic,
  and the Python app has zero payment code to audit.
- **`<100 ms` cached, sub-second cold.** The Jev fan-out (drainer / risk / intent)
  is one 3-in-1 call, not three.
- **Signature key never leaves the machine it was born on.** Generated once, on the
  production host, 600 perms. Split custody by design.
- Run everything yourself: `pip install -r requirements.txt && gunicorn subcento_api:app`,
  bring your own [TypeSafe](https://console.typesafe.ai) key. MIT — fork the checker,
  keep the verdicts honest.

## Why an agent should care

One 0.002 USDC call is the cheapest insurance in agentic commerce: it is smaller
than a single wasted signature and larger than nothing when the approval you sign
drains your wallet. The lane is littered with pre-sign guards that went dormant —
this one ships signed evidence, sanctioned-address screening, and semantic intent
analysis, and answers to machines.

## Status

Live on Base mainnet · indexed on [x402scan](https://x402scan.com) · discovery: `/`, `/health`, `/openapi.json`, `/llms.txt` (all free).

## License

MIT — see [LICENSE](LICENSE). Contact: subcento@pm.me
