"""
Subcento API — Endpoint /check prêt pour x402.

Le reverse-proxy Caddy (avec plugin x402) intercepte les requêtes HTTP 402.
Cette API Flask sert la logique métier derrière le paywall.
"""

from flask import Flask, request, jsonify
from subcento_engine import check_transaction, VERIFY_KEY_HEX

app = Flask(__name__)


@app.route("/")
def index():
    """Page de découverte M2M (servie sans paiement via x402)."""
    return jsonify({
        "name": "Subcento — Pre-flight Transaction Verifier for AI Agents",
        "version": "1.2.0",
        "description": (
            "Verifies an on-chain transaction before an AI agent signs it. "
            "Returns SAFE | CAUTION | BLOCK with signed evidence in <100ms. "
            "v1.2: nonce-bound or shape-bound verdicts, evaluation_status, signed limits."
        ),
        "pricing_model": "x402",
        "cost_per_request_usdc": "0.002",
        "endpoints": [
            {
                "path": "/check",
                "method": "POST",
                "description": "Pre-flight transaction verification",
                "body": {
                    "to": "string (target address)",
                    "calldata": "string (hex calldata, '0x' for native transfer)",
                    "value": "int (wei, optional, default 0)",
                    "chain_id": "int (optional, default 8453 = Base)",
                    "intent": "string (optional — declared agent intent; enables 3-in-1 intent-match diagnostic)",
                    "nonce": "string (optional — ERC-3009 bytes32 you intend to spend; verdict becomes nonce-bound)",
                },
            }
        ],
        "verify_key": VERIFY_KEY_HEX,
    })


@app.route("/check", methods=["POST"])
def check():
    """
    Endpoint payant (x402: 0.002 USDC).
    Le facilitator x402 valide le paiement avant que la requête n'atteigne cette route.
    """
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    to = data.get("to")
    calldata = data.get("calldata", "0x")
    value = int(data.get("value", 0) or 0)  # tolère les clients qui envoient une string
    chain_id = int(data.get("chain_id", 8453))
    intent = data.get("intent")  # optionnel : intention déclarée (diagnostic 3-en-1)
    nonce = data.get("nonce")  # optionnel : bytes32 ERC-3009 => verdict nonce-bound

    if not to:
        return jsonify({"error": "'to' address required"}), 400

    try:
        verdict = check_transaction(to, calldata, value, chain_id,
                                    declared_intent=intent, nonce=nonce)
        return jsonify(verdict)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health")
def health():
    return jsonify({"status": "ok", "verify_key": VERIFY_KEY_HEX})


CHECK_SCHEMA = {
    "type": "object",
    "required": ["to"],
    "properties": {
        "to": {"type": "string", "description": "Target address (0x + 40 hex)", "pattern": "^0x[0-9a-fA-F]{40}$"},
        "calldata": {"type": "string", "description": "Hex calldata; '0x' for a native transfer", "default": "0x"},
        "value": {"type": "integer", "description": "Wei sent (optional, default 0)", "minimum": 0},
        "chain_id": {"type": "integer", "description": "Chain id (optional, default 8453 = Base)", "default": 8453},
        "intent": {"type": "string", "description": "Declared agent intent — enables the Jev 3-in-1 intent-match diagnostic"},
        "nonce": {"type": "string", "description": "Optional ERC-3009 bytes32 nonce (0x + 64 hex) the caller intends to spend; when present the signed verdict is nonce-bound and opens against exactly one settlement", "pattern": "^0x[0-9a-fA-F]{64}$"},
    },
}

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["SAFE", "CAUTION", "BLOCK"]},
        "reasons": {"type": "array", "items": {"type": "string"}},
        "latency_ms": {"type": "number"},
        "value": {"type": "integer", "description": "Signed: wei in the payment shape"},
        "chain_id": {"type": "integer", "description": "Signed: chain the verdict is valid on (anti cross-chain replay)"},
        "timestamp": {"type": "integer", "description": "Signed issue time, unix seconds. Ordering rule: a verdict counts as pre-flight only when strictly before the settlement block timestamp; equal does not count."},
        "binding": {"type": "object", "description": "Signed. {kind: 'nonce-bound', nonce: '0x…64'} when the caller supplied the ERC-3009 nonce — verdict then opens against exactly one settlement, never a second identical payment. {kind: 'shape-bound'} otherwise — never upgradeable to a per-payment claim.", "properties": {"kind": {"type": "string", "enum": ["nonce-bound", "shape-bound"]}, "nonce": {"type": "string"}}},
        "evaluation_status": {"type": "string", "enum": ["measured", "not-measured"], "description": "not-measured means a required trust layer could not run (see checks_failed); a BLOCK with not-measured is gate conservatism, not evidence of danger, and must not count as a negative signal about the agent"},
        "checks_failed": {"type": "array", "items": {"type": "string"}, "description": "Layers that could not run (goplus, ofac_blocklist, jev_semantic)"},
        "limits": {"type": "array", "items": {"type": "string"}, "description": "Signed: what this verdict does and does not show"},
        "layers": {"type": "object", "description": "Per-layer evidence (GoPlus risk, OFAC, Jev semantics, deterministic checks) — unsigned advisory detail"},
        "signature": {"type": "string", "description": "Ed25519 signature over the canonical digest of the signed payload (verdict, to, function, value, reasons, timestamp, chain_id, binding, evaluation_status, checks_failed, limits)"},
        "verify_key": {"type": "string", "description": "Hex Ed25519 verify key (also at /health)"},
    },
}

import struct as _struct


def _build_favicon() -> bytes:
    """ICO 16x16x32 — carré vert Subcento, généré sans dépendance."""
    w = h = 16
    px = b"".join(b"\xa0\xe5\x00\xff" * w for _ in range(h))  # BGRA #00E5A0
    andmask = b"\x00" * (h * 4)
    bmp = _struct.pack("<IiiHHIIiiII", 40, w, h * 2, 1, 32, 0, len(px), 0, 0, 0, 0) + px + andmask
    ico = _struct.pack("<HHH", 0, 1, 1) + _struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, len(bmp), 22)
    return ico + bmp


FAVICON = _build_favicon()


@app.route("/favicon.ico")
def favicon():
    return FAVICON, 200, {"Content-Type": "image/x-icon", "Cache-Control": "public, max-age=86400"}


OPENAPI = {
    "openapi": "3.1.0",
    "info": {
        "title": "Subcento — Pre-flight Transaction Verifier for AI Agents",
        "version": "1.2.0",
        "contact": {
            "name": "Subcento — operated by Alterfield",
            "url": "https://subcento.alterfield.com",
            "email": "subcento@pm.me",
        },
        "description": (
            "Verifies an on-chain transaction BEFORE an AI agent signs it. Four layers: "
            "GoPlus address risk, OFAC blocklist, Jev (TypeSafe AI) semantic calldata analysis, "
            "deterministic checks. Ed25519-signed verdict. Fail-closed: unreachable trust layers => BLOCK, never a false SAFE. "
            "v1.2: every verdict carries a binding (nonce-bound opens against exactly one settlement, shape-bound never upgrades), "
            "an evaluation_status (measured | not-measured, so a blind BLOCK is never read as evidence of danger), and signed limits."
        ),
        "x-guidance": (
            "Call POST /check before signing any Base/EVM transaction. Unpaid calls return HTTP 402 with a "
            "Payment-Required (x402 v2) header: pay exactly 0.002 USDC on Base mainnet (eip155:8453, scheme exact, "
            "maxTimeout 60s) via facilitator https://facilitator.goplausible.xyz, then retry the identical request "
            "with the X-PAYMENT header. Include 'intent' to get the 3-in-1 semantic diagnostic "
            "(drainer probability, risk level, intent-match). Treat BLOCK as final; CAUTION deserves a human or a smaller probe. "
            "Free routes: /, /health, /llms.txt, /openapi.json, /favicon.ico — never pay for discovery. "
            "To make a verdict citable as a pre-settlement precondition, send the ERC-3009 nonce you intend to spend "
            "in the request: the signed verdict then binds to it and opens against exactly one settlement. "
            "A BLOCK whose evaluation_status is not-measured means the verifier was blind, not that you are guilty."
        ),
    },
    "extensions": {
        "bazaar": {
            "schema": {
                "type": "object",
                "properties": {
                    "input": CHECK_SCHEMA,
                    "output": VERDICT_SCHEMA,
                },
            }
        }
    },
    "paths": {
        "/": {
            "get": {"summary": "Machine-readable discovery card", "security": [],
                    "responses": {"200": {"description": "Discovery JSON"}}},
        },
        "/health": {
            "get": {"summary": "Liveness + verify_key", "security": [],
                    "responses": {"200": {"description": "ok"}}},
        },
        "/llms.txt": {
            "get": {"summary": "Plain-text guide for LLM crawlers", "security": [],
                    "responses": {"200": {"description": "text/plain"}}},
        },
        "/check": {
            "post": {
                "summary": "Pre-flight transaction verification (paid)",
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": CHECK_SCHEMA}},
                },
                "responses": {
                    "200": {"description": "Signed verdict", "content": {"application/json": {"schema": VERDICT_SCHEMA}}},
                    "400": {"description": "Bad request (after payment)"},
                    "402": {"description": "Payment Required"},
                },
                "x-payment-info": {
                    "price": {"mode": "fixed", "currency": "USD", "amount": "0.002"},
                    "protocols": [{"x402": {}}],
                },
            }
        },
    },
}


@app.route("/openapi.json")
def openapi():
    return jsonify(OPENAPI)


LLMS_TXT = """# Subcento

> Pre-flight transaction verification for AI agents. Pay with x402 (0.002 USDC on
> Base mainnet), get a signed verdict — SAFE | CAUTION | BLOCK — with evidence in
> <100ms (cached) / <700ms (cold). Fail-closed: if trust layers are unreachable you
> get BLOCK, never a false SAFE.

## Why an agent should call this before signing
Four layers: address risk (GoPlus), OFAC blocklist, semantic intent analysis of the
calldata (Jev / TypeSafe AI), Ed25519-signed verdict verifiable with `verify_key`.

## Endpoints

### POST /check (x402 paywall — returns HTTP 402 + Payment-Required if unpaid)
Body: `{"to": "0x…", "calldata": "0x…", "value": 0, "chain_id": 8453, "intent": "optional declared intent"}`
x402 terms: scheme exact, network eip155:8453, asset USDC, amount 2000 (= $0.002),
facilitator https://facilitator.goplausible.xyz, maxTimeout 60s.

### GET / — free machine-readable discovery card
### GET /health — free liveness + verify_key

## Docs
- Root: https://subcento.alterfield.com/ (full OpenAPI-ish discovery JSON)

## Notes
- Verdicts include `latency_ms`, `reasons[]`, `signature`, `verify_key`.
- `intent` mismatch alone ⇒ CAUTION (anti false-positive), drainer probability > 0.7 ⇒ BLOCK.
- v1.2: send the ERC-3009 `nonce` you intend to spend and the signed verdict is `nonce-bound`
  (opens against exactly one settlement; a shape-bound verdict never upgrades).
- `evaluation_status: not-measured` on a BLOCK means a trust layer could not run — gate
  conservatism, not evidence. Never cite it as a negative signal about the agent.
- Signature covers: verdict, to, function, value, reasons, timestamp, chain_id, binding,
  evaluation_status, checks_failed, limits. Everything else in the response is advisory detail.
"""


@app.route("/llms.txt")
def llms():
    return LLMS_TXT, 200, {"Content-Type": "text/plain; charset=utf-8"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
