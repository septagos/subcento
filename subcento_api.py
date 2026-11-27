"""
Subcento API: Endpoint /check prêt pour x402.

Le reverse-proxy Caddy (avec plugin x402) intercepte les requêtes HTTP 402.
Cette API Flask sert la logique métier derrière le paywall.
"""

import os

from flask import Flask, request, jsonify
from subcento_engine import check_transaction, check_market, VERIFY_KEY_HEX

app = Flask(__name__)


@app.route("/")
def index():
    """Page de découverte M2M (servie sans paiement via x402)."""
    return jsonify({
        "name": "Subcento: Pre-flight Transaction Verifier for AI Agents",
        "version": "1.5.2",
        "description": (
            "Verifies an on-chain transaction before an AI agent signs it. "
            "Returns SAFE | CAUTION | BLOCK with signed evidence. /regime stays "
            "under 150 ms; /check runs ~0.3 s warm, ~1 s cold (live trust-layer calls). "
            "v1.2: nonce-bound or shape-bound verdicts, evaluation_status, signed limits. "
            "v1.3: POST /regime, signed market-stress verdict (seismograph + Jev regime). "
            "v1.3.1: contract hardening: only /check and /regime are ever billed; unknown paths return an unpaid 404 JSON; the x402 resume guide at /x402v2.txt is free. v1.4: full free discovery surface for agents and registries: /robots.txt, /sitemap.xml, /.well-known/agent-card.json, /.well-known/x402. v1.5: POST /audit: signed Evidence Pack (0.05 USDC), offline-verifiable; the billed-route contract now covers /check, /regime and /audit. v1.5.1: price integrity: the unpaid 404 handler announced /audit at 0.5 USDC instead of 0.05; every served surface now states the same price. v1.5.2: payment guide (/x402v2.txt, /.well-known/x402) now announces all three billed routes; history clearly separated from contract."
        ),
        "pricing_model": "x402",
        "cost_per_request_usdc": {"POST /check": "0.002", "POST /regime": "0.0001", "POST /audit": "0.05"},
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
                    "intent": "string (optional: declared agent intent; enables 3-in-1 intent-match diagnostic)",
                    "nonce": "string (optional: ERC-3009 bytes32 you intend to spend; verdict becomes nonce-bound)",
                },
            },
            {
                "path": "/regime",
                "method": "POST",
                "description": "Signed market-stress verdict: cross-asset seismograph score + Jev regime label",
                "body": {
                    "live_jev": "bool (optional, default false: true refreshes the Jev classification now, ~300ms)",
                },
            },
            {
                "path": "/audit",
                "method": "POST",
                "description": "Signed Evidence Pack: merchant identity, kit SHA-256 integrity, on-chain proofs, market snapshot, deployment state, verifiable offline",
                "body": {},
            }
        ],
        "discovery_files": ["/robots.txt", "/sitemap.xml", "/.well-known/agent-card.json", "/.well-known/x402", "/llms.txt", "/openapi.json", "/x402v2.txt"],
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
    except ValueError as e:
        # Entrée invalide (ex. calldata non-hex) : faute du client, pas du serveur
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "1.5.2", "verify_key": VERIFY_KEY_HEX})


@app.route("/regime", methods=["POST"])
def regime():
    """
    Endpoint payant (x402: 0.0001 USDC): lecture signée du marché.
    Score sismique déterministe (30 min de fraîcheur max) + classification
    de régime par Jev (TypeSafe). Fail-soft: sans Jev, evaluation_status
    = not-measured, jamais un faux SAFE.
    """
    data = request.get_json(force=True, silent=True) or {}
    live = bool(data.get("live_jev", False))
    try:
        return jsonify(check_market(live_jev=live))
    except FileNotFoundError:
        return jsonify({"error": "market snapshot unavailable (seismo cycle pending)"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500


CHECK_SCHEMA = {
    "type": "object",
    "required": ["to"],
    "properties": {
        "to": {"type": "string", "description": "Target address (0x + 40 hex)", "pattern": "^0x[0-9a-fA-F]{40}$"},
        "calldata": {"type": "string", "description": "Hex calldata; '0x' for a native transfer", "default": "0x"},
        "value": {"type": "integer", "description": "Wei sent (optional, default 0)", "minimum": 0},
        "chain_id": {"type": "integer", "description": "Chain id (optional, default 8453 = Base)", "default": 8453},
        "intent": {"type": "string", "description": "Declared agent intent, enables the Jev 3-in-1 intent-match diagnostic"},
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
        "binding": {"type": "object", "description": "Signed. {kind: 'nonce-bound', nonce: '0x…64'} when the caller supplied the ERC-3009 nonce; verdict then opens against exactly one settlement, never a second identical payment. {kind: 'shape-bound'} otherwise: never upgradeable to a per-payment claim.", "properties": {"kind": {"type": "string", "enum": ["nonce-bound", "shape-bound"]}, "nonce": {"type": "string"}}},
        "evaluation_status": {"type": "string", "enum": ["measured", "not-measured"], "description": "not-measured means a required trust layer could not run (see checks_failed); a BLOCK with not-measured is gate conservatism, not evidence of danger, and must not count as a negative signal about the agent"},
        "checks_failed": {"type": "array", "items": {"type": "string"}, "description": "Layers that could not run (goplus, ofac_blocklist, jev_semantic)"},
        "limits": {"type": "array", "items": {"type": "string"}, "description": "Signed: what this verdict does and does not show"},
        "layers": {"type": "object", "description": "Per-layer evidence (GoPlus risk, OFAC, Jev semantics, deterministic checks), unsigned advisory detail"},
        "signature": {"type": "string", "description": "Ed25519 signature over the canonical digest of the signed payload (verdict, to, function, value, reasons, timestamp, chain_id, binding, evaluation_status, checks_failed, limits)"},
        "verify_key": {"type": "string", "description": "Hex Ed25519 verify key (also at /health)"},
    },
}

import struct as _struct

REGIME_SCHEMA = {
    "type": "object",
    "properties": {
        "live_jev": {"type": "boolean", "description": "Refresh the Jev regime classification at request time (~300ms, default false)", "default": False},
    },
}

REGIME_VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "market_verdict": {"type": "string", "enum": ["SAFE", "CAUTION", "BLOCK"]},
        "score_global": {"type": "number", "description": "Deterministic cross-asset stress score 0-100"},
        "zone": {"type": "string", "description": "calme | tendu | alarme"},
        "components": {"type": "object", "description": "Per-engine scores (fx, crypto, btc_disp, equities, rates, vix, fng)"},
        "btc_exchange_spread_pct": {"type": ["number", "null"], "description": "Max BTC price divergence across exchanges"},
        "jev_regime": {"type": ["string", "null"], "enum": ["calm", "volatile", "stress", "crisis", None]},
        "escalade_48h": {"type": ["number", "null"], "description": "Jev noul: probability stress escalates within 48h"},
        "snapshot_ts": {"type": "string", "description": "UTC capture time of the underlying seismograph snapshot"},
        "age_seconds": {"type": "integer", "description": "Freshness of the snapshot at verdict time (<1800 guaranteed)"},
        "evaluation_status": {"type": "string", "enum": ["measured", "not-measured"]},
        "timestamp": {"type": "integer"},
        "signature": {"type": "string", "description": "Ed25519 over the canonical regime digest"},
        "verify_key": {"type": "string"},
        "latency_ms": {"type": "number"},
        "limits": {"type": "array", "items": {"type": "string"}},
    },
}


def _build_favicon() -> bytes:
    """ICO 16x16x32: carré vert Subcento, généré sans dépendance."""
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



# --- v1.4.0 : surface de découverte M2M gratuite (aucun impact Caddy, aucune route payante touchée) ---

ROBOTS_TXT = (
    "User-agent: *\nAllow: /\n\n"
    "# Everything needed to discover, evaluate and pay Subcento is free.\n"
    "# Paid endpoints: POST /check, POST /regime, POST /audit (x402 v2, Base mainnet).\n"
    "Sitemap: https://subcento.alterfield.com/sitemap.xml\n"
)

SITEMAP_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    "  <url><loc>https://subcento.alterfield.com/</loc></url>\n"
    "  <url><loc>https://subcento.alterfield.com/llms.txt</loc></url>\n"
    "  <url><loc>https://subcento.alterfield.com/openapi.json</loc></url>\n"
    "  <url><loc>https://subcento.alterfield.com/x402v2.txt</loc></url>\n"
    "</urlset>\n"
)

AGENT_CARD = {
    "name": "Subcento",
    "description": (
        "Pre-flight on-chain transaction verification for AI agents. x402-paid micro-USDC "
        "on Base mainnet; Ed25519-signed verdicts (SAFE | CAUTION | BLOCK) with per-layer "
        "evidence (GoPlus risk, OFAC blocklist, Jev semantic intent, deterministic checks). "
        "Fail-closed: unreachable trust layers yield BLOCK, never a false SAFE. "
        "Also POST /regime: signed market-stress verdict (seismograph score + Jev regime)."
    ),
    "version": "1.5.2",
    "url": "https://subcento.alterfield.com",
    "provider": {
        "organization": "Alterfield",
        "url": "https://subcento.alterfield.com",
        "email": "subcento@pm.me",
    },
    "transport": {"protocol": "HTTP+JSON", "payment": "x402 v2 per endpoint (see x402 blocks below)"},
    "capabilities": {"signed_verdicts": True, "fail_closed": True, "streaming": False},
    "documentation": {
        "discovery_root": "GET / (machine-readable contract)",
        "openapi": "GET /openapi.json",
        "llms": "GET /llms.txt",
        "payment_resume_guide": "GET /x402v2.txt (free, referenced by every 402 challenge)",
        "trust_key": "GET /health (Ed25519 verify key)",
    },
    "skills": [
        {
            "id": "preflight_check",
            "name": "Pre-flight transaction verification",
            "summary": "Verify an EVM/Base transaction BEFORE signing; returns a signed verdict with reasons, limits and binding (nonce-bound when you send the ERC-3009 nonce).",
            "endpoint": {"path": "/check", "method": "POST", "content_type": "application/json"},
            "input_fields": ["to (required)", "calldata", "value", "chain_id (default 8453)", "intent", "nonce"],
            "output": "signed verdict JSON: verdict, reasons[], binding, evaluation_status, checks_failed[], limits[], signature, verify_key",
            "latency": "~0.3 s warm, ~1 s cold (live per-request trust-layer calls)",
            "x402": {
                "network": "eip155:8453", "scheme": "exact",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "amount_minor": "2000", "minor_units_decimals": 6,
                "facilitator": "https://facilitator.goplausible.xyz", "max_timeout_s": 60,
            },
        },
        {
            "id": "market_regime",
            "name": "Signed market-stress verdict",
            "summary": "Deterministic cross-asset seismograph score (0-100) + Jev regime label (calm|volatile|stress|crisis) + 48h escalation probability, Ed25519-signed, snapshot < 30 min old.",
            "endpoint": {"path": "/regime", "method": "POST", "content_type": "application/json"},
            "input_fields": ["live_jev (bool, optional, default false)"],
            "output": "signed regime verdict JSON",
            "latency": "<150 ms",
            "x402": {
                "network": "eip155:8453", "scheme": "exact",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "amount_minor": "100", "minor_units_decimals": 6,
                "facilitator": "https://facilitator.goplausible.xyz", "max_timeout_s": 60,
            },
        },
        {
            "id": "evidence_audit",
            "name": "Signed Evidence Pack",
            "summary": "Offline-verifiable dossier: merchant identity, kit SHA-256 integrity, on-chain merchant proofs, engine market snapshot, real deployment state, Ed25519 signature. Unmeasured fields stay NON_MESURE, never invented.",
            "endpoint": {"path": "/audit", "method": "POST", "content_type": "application/json"},
            "input_fields": [],
            "output": "signed evidence pack JSON (sections with status MESURE | PARTIEL | NON_MESURE)",
            "latency": "~0.2 s",
            "x402": {
                "network": "eip155:8453", "scheme": "exact",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "amount_minor": "50000", "minor_units_decimals": 6,
                "facilitator": "https://facilitator.goplausible.xyz", "max_timeout_s": 60,
            },
        },
    ],
    "free_routes": ["/", "/health", "/openapi.json", "/llms.txt", "/x402v2.txt",
                    "/robots.txt", "/sitemap.xml", "/favicon.ico",
                    "/.well-known/agent-card.json", "/.well-known/x402"],
    "contract": (
        "Only POST /check (0.002 USDC), POST /regime (0.0001 USDC) and POST /audit (0.05 USDC) are ever billed. "
        "Any other path returns an unpaid 404 JSON describing the contract: you cannot pay for a ghost. "
        "Never pay for discovery: everything above is free."
    ),
}


@app.route("/robots.txt")
def robots():
    return ROBOTS_TXT, 200, {"Content-Type": "text/plain; charset=utf-8",
                             "Cache-Control": "public, max-age=3600"}


@app.route("/sitemap.xml")
def sitemap():
    return SITEMAP_XML, 200, {"Content-Type": "application/xml; charset=utf-8"}


@app.route("/.well-known/agent-card.json")
def agent_card():
    """Carte d'agent pour registres agentic-web (BrickBlue et al.)."""
    return jsonify(AGENT_CARD)


@app.route("/.well-known/agent.json")
def agent_json():
    """Alias legacy recherché par les crawlers Open402: même carte."""
    return jsonify(AGENT_CARD)


@app.route("/.well-known/x402")
def wellknown_x402():
    """Alias well-known du guide de reprise de paiement (route déjà libre)."""
    return x402_guide()


OPENAPI = {
    "openapi": "3.1.0",
    "info": {
        "title": "Subcento: Pre-flight Transaction Verifier for AI Agents",
        "version": "1.5.2",
        "contact": {
            "name": "Subcento, operated by Alterfield",
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
            "Free routes: /, /health, /llms.txt, /openapi.json, /favicon.ico, /x402v2.txt, /robots.txt, /sitemap.xml, /.well-known/agent-card.json, /.well-known/x402: never pay for discovery. "
            "Only /check, /regime and /audit are ever billed: any other path returns an unpaid 404 JSON. "
            "Full payment-resume steps: GET /x402v2.txt (free). "
            "To make a verdict citable as a pre-settlement precondition, send the ERC-3009 nonce you intend to spend "
            "in the request: the signed verdict then binds to it and opens against exactly one settlement. "
            "A BLOCK whose evaluation_status is not-measured means the verifier was blind, not that you are guilty. "
            "For market context, POST /regime (0.0001 USDC) returns a signed market-stress verdict: deterministic "
            "cross-asset seismograph score + Jev regime label (calm|volatile|stress|crisis) + 48h escalation noul. "
            "Default body {} is fine; {\"live_jev\": true} refreshes the Jev classification at request time."
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
        "/x402v2.txt": {
            "get": {"summary": "Free step-by-step payment-resume guide (referenced by every 402 challenge)",
                    "security": [], "responses": {"200": {"description": "text/plain"}}},
        },
        "/favicon.ico": {
            "get": {"summary": "Icon", "security": [], "responses": {"200": {"description": "image/x-icon"}}},
        },
        "/robots.txt": {
            "get": {"summary": "Crawler policy (free)", "security": [], "responses": {"200": {"description": "text/plain"}}},
        },
        "/sitemap.xml": {
            "get": {"summary": "Sitemap of free docs (free)", "security": [], "responses": {"200": {"description": "application/xml"}}},
        },
        "/.well-known/agent-card.json": {
            "get": {"summary": "Agentic-web discovery card (free)", "security": [], "responses": {"200": {"description": "application/json"}}},
        },
        "/.well-known/agent.json": {
            "get": {"summary": "Alias of agent-card.json (free)", "security": [], "responses": {"200": {"description": "application/json"}}},
        },
        "/.well-known/x402": {
            "get": {"summary": "Payment-resume guide at well-known path (free)", "security": [], "responses": {"200": {"description": "text/plain"}}},
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
        "/regime": {
            "post": {
                "summary": "Signed market-stress verdict (paid, 0.0001 USDC)",
                "requestBody": {
                    "required": False,
                    "content": {"application/json": {"schema": REGIME_SCHEMA}},
                },
                "responses": {
                    "200": {"description": "Signed regime verdict", "content": {"application/json": {"schema": REGIME_VERDICT_SCHEMA}}},
                    "402": {"description": "Payment Required"},
                    "503": {"description": "Snapshot unavailable"},
                },
                "x-payment-info": {
                    "price": {"mode": "fixed", "currency": "USD", "amount": "0.0001"},
                    "protocols": [{"x402": {}}],
                },
            }
        },
        "/audit": {
            "post": {
                "summary": "Signed Evidence Pack (paid, 0.05 USDC)",
                "requestBody": {"required": False, "content": {"application/json": {"schema": {"type": "object"}}}},
                "responses": {
                    "200": {"description": "Signed evidence pack (sections status MESURE | PARTIEL | NON_MESURE)"},
                    "402": {"description": "Payment Required"},
                },
                "x-payment-info": {
                    "price": {"mode": "fixed", "currency": "USD", "amount": "0.05"},
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
> Base mainnet), get a signed verdict (SAFE | CAUTION | BLOCK) with evidence in
> /regime under 150 ms; /check ~0.3 s warm / ~1 s cold (GoPlus + Jev run live per
> request; only GoPlus is cached). Fail-closed: if trust layers are unreachable you
> get BLOCK, never a false SAFE.

## Why an agent should call this before signing
Four layers: address risk (GoPlus), OFAC blocklist, semantic intent analysis of the
calldata (Jev / TypeSafe AI), Ed25519-signed verdict verifiable with `verify_key`.

## Endpoints

### POST /check (x402 paywall: returns HTTP 402 + Payment-Required if unpaid)
Body: `{"to": "0x…", "calldata": "0x…", "value": 0, "chain_id": 8453, "intent": "optional declared intent"}`
x402 terms: scheme exact, network eip155:8453, asset USDC, amount 2000 (= $0.002),
facilitator https://facilitator.goplausible.xyz, maxTimeout 60s.

### GET /: free machine-readable discovery card
### GET /health: free liveness + verify_key

### POST /regime (x402 paywall: 0.0001 USDC)
Body: `{}` or `{"live_jev": true}` to refresh the Jev classification now.
Returns a signed market-stress verdict: deterministic cross-asset seismograph
score (0-100, SAFE <45 ≤ CAUTION <75 ≤ BLOCK), Jev regime label
(calm|volatile|stress|crisis) and 48h escalation noul, snapshot freshness
(`age_seconds`, always <1800). x402 terms: network eip155:8453, amount 100
(micro-USDC = $0.0001), same facilitator. This is aggregate market stress:
not a price prediction, not advice.

## Payment guide
### GET /x402v2.txt (free)
Step-by-step: decode the `Payment-Required` challenge, sign the ERC-3009
USDC authorization, retry with `X-PAYMENT`, keep `X-PAYMENT-RESPONSE` as receipt.

## Discovery files (all free)
### GET /robots.txt · GET /sitemap.xml
### GET /.well-known/agent-card.json (agentic-web registry card) · GET /.well-known/x402 (guide alias)

## Contract
Only POST /check and POST /regime are ever billed. Every other path returns an
unpaid 404 JSON listing the paid routes: you cannot pay for a ghost.

## Docs
- Root: https://subcento.alterfield.com/ (full OpenAPI-ish discovery JSON)

## Notes
- Verdicts include `latency_ms`, `reasons[]`, `signature`, `verify_key`.
- `intent` mismatch alone ⇒ CAUTION (anti false-positive), drainer probability > 0.7 ⇒ BLOCK.
- v1.2: send the ERC-3009 `nonce` you intend to spend and the signed verdict is `nonce-bound`
  (opens against exactly one settlement; a shape-bound verdict never upgrades).
- `evaluation_status: not-measured` on a BLOCK means a trust layer could not run: gate
  conservatism, not evidence. Never cite it as a negative signal about the agent.
- Signature covers: verdict, to, function, value, reasons, timestamp, chain_id, binding,
  evaluation_status, checks_failed, limits. Everything else in the response is advisory detail.
"""


@app.route("/llms.txt")
def llms():
    return LLMS_TXT, 200, {"Content-Type": "text/plain; charset=utf-8"}



X402_GUIDE_PATH = os.environ.get("SUBCENTO_X402_GUIDE", "/srv/subcento/x402v2.txt")


@app.errorhandler(404)
def not_found(e):
    """Un unknown path is never billable: explicit unpaid 404 with the paid-route contract."""
    return jsonify({
        "error": "route does not exist, nothing was billed",
        "paid_routes": [{"path": "/check", "method": "POST", "price_usdc": "0.002"},
                        {"path": "/regime", "method": "POST", "price_usdc": "0.0001"},
                        {"path": "/audit", "method": "POST", "price_usdc": "0.05"}],
        "free_discovery": ["/", "/health", "/openapi.json", "/llms.txt", "/x402v2.txt",
                           "/robots.txt", "/sitemap.xml", "/.well-known/agent-card.json",
                           "/.well-known/x402"],
    }), 404


@app.route("/x402v2.txt")
def x402_guide():
    """Free plain-text payment-resume guide referenced by every 402 challenge."""
    try:
        with open(X402_GUIDE_PATH) as f:
            return f.read(), 200, {"Content-Type": "text/plain; charset=utf-8"}
    except FileNotFoundError:
        return "guide temporarily unavailable, see /llms.txt", 503


# --- v1.5.0 : POST /audit: Evidence Pack (x402 billed by Caddy; deploy/Caddyfile.audit.snippet) ---
from audit_api import register_audit_routes as _reg_audit
_reg_audit(app)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
