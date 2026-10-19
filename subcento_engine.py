"""
Subcento Engine — Pré-vérification ultra-rapide de transactions pour agents IA.

Pipeline :
  1. Décode le calldata (4-byte selector → fonction connue + paramètres)
  2. Heuristiques déterministes (approvals illimités, transferts suspects, GoPlus)
  3. Couche sémantique Jev (interprète l'intention du calldata)
  4. Verdict final : SAFE | CAUTION | BLOCK, signé Ed25519

Latence cible : <100 ms (verdicts mis en cache).
"""

import os
import json
import time
import hashlib
import datetime as dt
from typing import Any, Optional
import requests

# --- Configuration ---
# API OFFICIELLE TypeSafe (depuis 2026-10-17) — schéma identique à l'ancien,
# TokenRa dégradé en fallback secondaire (revendeur, pas de SLA/SOC2).
TYPESAFE_API_URL = "https://api.typesafe.ai/v1/systemone"
TYPESAFE_API_KEY = os.environ.get("TYPESAFE_API_KEY", "")
JEV_MODEL = os.environ.get("JEV_MODEL", "jev-1.14.0")  # version épinglée, jamais l'alias
# Fallback secondaire (déprécié) :
JEV_FALLBACK_URL = os.environ.get("JEV_FALLBACK_URL", "https://tokenra.io/v1/decisions")
TOKENRA_API_KEY = os.environ.get("TOKENRA_API_KEY", "")  # vide = fallback désactivé
GOPLUS_API = "https://api.gopluslabs.io/api/v1"

# --- Blocklist OFAC locale (hors-ligne, déterministe, ~0 ms) ---
_OFAC_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ofac_blocklist.json")
_OFAC_SET: set | None = None
_OFAC_ERROR: str | None = None
# tickers pertinents pour les chaînes EVM visées (Base/Ethereum/BSC/Arbitrum...)
_OFAC_EVM_TICKERS = ("eth", "usdt", "usdc", "arb", "bnb", "bsc")


def ofac_sanctioned(address: str) -> bool:
    global _OFAC_SET, _OFAC_ERROR
    if _OFAC_SET is None:
        try:
            with open(_OFAC_PATH) as f:
                data = json.load(f)
            _OFAC_SET = {
                a.lower()
                for ticker in _OFAC_EVM_TICKERS
                for a in data.get("addresses", {}).get(ticker, [])
            }
            _OFAC_ERROR = None
        except Exception as e:
            # Fail-closed strict : une blocklist injouable n'est pas une blocklist vide,
            # c'est une couche de sécurité absente -> _OFAC_ERROR force le BLOCK.
            _OFAC_SET = set()
            _OFAC_ERROR = str(e)
    return address.lower() in _OFAC_SET

# Clé de signature Ed25519 (générée au démarrage si absente)
import nacl.signing
import nacl.encoding

_SIGNING_KEY_PATH = os.environ.get("SUBCENTO_KEY_PATH", "./subcento_signing.key")

def _load_signing_key() -> nacl.signing.SigningKey:
    if os.path.exists(_SIGNING_KEY_PATH):
        with open(_SIGNING_KEY_PATH, "rb") as f:
            return nacl.signing.SigningKey(f.read())
    key = nacl.signing.SigningKey.generate()
    with open(_SIGNING_KEY_PATH, "wb") as f:
        f.write(bytes(key))
    return key

SIGNING_KEY = _load_signing_key()
VERIFY_KEY_HEX = SIGNING_KEY.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()


# ---------------------------------------------------------------------------
# 1. DÉCODEUR DE CALLDATA
# ---------------------------------------------------------------------------

# Signatures connues (4-byte selector → nom + types de paramètres)
# On utilise les selecteurs les plus courants pour les agents
KNOWN_SELECTORS: dict[str, dict] = {
    "0x095ea7b3": {"name": "approve", "inputs": ["address", "uint256"]},
    "0xa9059cbb": {"name": "transfer", "inputs": ["address", "uint256"]},
    "0x23b872dd": {"name": "transferFrom", "inputs": ["address", "address", "uint256"]},
    "0x7ff36ab5": {"name": "swapExactETHForTokens", "inputs": ["uint256", "address[]", "address", "uint256"]},
    "0x38ed1739": {"name": "swapExactTokensForTokens", "inputs": ["uint256", "uint256", "address[]", "address", "uint256"]},
    "0x4e71d92d": {"name": "claim", "inputs": []},
    "0x6a627842": {"name": "mint", "inputs": ["address", "uint256"]},
    "0x42966c68": {"name": "burn", "inputs": ["uint256"]},
    "0x1cff79cd": {"name": "skim", "inputs": ["address"]},
    "0xd0e30db0": {"name": "deposit", "inputs": []},
    "0x2e1a7d4d": {"name": "withdraw", "inputs": ["uint256"]},
    "0x00000000": {"name": "native_transfer", "inputs": []},  # value != 0, data empty
}

MAX_UINT256 = (2 ** 256) - 1


def decode_calldata(calldata: str) -> dict:
    """Décode le calldata brut en fonction + paramètres lisibles."""
    if not calldata or calldata == "0x":
        return {"function": "native_transfer", "params": {}, "raw": calldata}

    selector = calldata[:10].lower()
    meta = KNOWN_SELECTORS.get(selector, {"name": f"unknown_{selector}", "inputs": []})

    params: dict[str, Any] = {}
    if meta["inputs"]:
        raw_params = calldata[10:]
        offset = 0
        for i, ptype in enumerate(meta["inputs"]):
            if offset + 64 > len(raw_params):
                break
            chunk = raw_params[offset:offset + 64]
            if ptype == "address":
                params[f"arg{i}_{ptype}"] = "0x" + chunk[-40:]
            elif ptype == "uint256":
                params[f"arg{i}_{ptype}"] = int(chunk, 16)
            else:
                params[f"arg{i}_{ptype}"] = "0x" + chunk
            offset += 64

    return {"function": meta["name"], "params": params, "raw": calldata}


# ---------------------------------------------------------------------------
# 2. HEURISTIQUES DÉTERMINISTES
# ---------------------------------------------------------------------------

_GOPLUS_CACHE: dict[str, tuple[float, dict]] = {}
_GOPLUS_TTL = 300  # secondes — les labels drainer/sanction bougent peu

# Champs réels de l'API address_security considérés comme malveillants (valeur "1")
_GOPLUS_MALICIOUS_FIELDS = (
    "cybercrime", "money_laundering", "darkweb_transactions",
    "phishing_activities", "stealing_attack", "honeypot_related_address",
)
_GOPLUS_ALL_FIELDS = _GOPLUS_MALICIOUS_FIELDS + (
    "blackmail_activities", "blacklist_doubt", "sanctioned", "reinit",
    "gas_abuse", "fake_kyc", "fake_standard_interface", "mixer", "fake_token",
)


def check_goplus_malicious(address: str, chain_id: int = 8453) -> dict:
    """
    Vérifie une adresse via GoPlus address_security (tier gratuit).
    Parse les CHAMPS RÉELS de la réponse (l'API ne renvoie pas is_drainer/*).
    Cache le résultat 5 min ; {"unavailable": True} si le réseau/API échoue.
    """
    key = f"{chain_id}:{address.lower()}"
    now = time.time()
    cached = _GOPLUS_CACHE.get(key)
    if cached and cached[0] > now:
        return cached[1]
    result: dict = {}
    try:
        r = requests.get(
            f"{GOPLUS_API}/address_security/{address}",
            params={"chain_id": chain_id},
            # Fail-closed strict : un timeout trop serré crée de faux BLOCK sur
            # adresses saines. 2,5s = pire cas cold-path, amorti par le cache 5 min.
            timeout=2.5,
        )
        body = r.json() if r.status_code == 200 else {}
        if body.get("code") == 1:
            data = body.get("result") or {}
            if data:
                result = {
                    "is_drainer": any(data.get(f) == "1" for f in _GOPLUS_MALICIOUS_FIELDS),
                    "is_blackmail": data.get("blackmail_activities") == "1"
                                    or data.get("blacklist_doubt") == "1",
                    "is_sanctioned": data.get("sanctioned") == "1",
                    "is_contract": data.get("contract_address") == "1",
                    "flags": [f for f in _GOPLUS_ALL_FIELDS if data.get(f) == "1"],
                }
        else:
            result = {"unavailable": True}
    except Exception:
        result = {"unavailable": True}
    # Fail-strict : un échec réseau se cache 30 s seulement (pas 5 min de BLOCK
    # automatique sur une adresse juste), un succès 5 min.
    ttl = 30 if result.get("unavailable") else _GOPLUS_TTL
    _GOPLUS_CACHE[key] = (now + ttl, result)
    return result


def heuristic_checks(decoded: dict, to: str, value: int) -> list[str]:
    """Retourne une liste de risk flags déterministes."""
    flags = []

    fn = decoded["function"]
    params = decoded["params"]

    # --- Approvals illimités ---
    if fn == "approve":
        amount = params.get("arg1_uint256", 0)
        if amount == MAX_UINT256 or amount >= 10 ** 30:
            flags.append("unlimited_erc20_approval")
        spender = params.get("arg0_address", "")
        if spender and spender.lower() != to.lower():
            flags.append("approval_to_third_party")

    # --- TransferFrom (drainer typique) ---
    elif fn == "transferFrom":
        flags.append("transferFrom_called")

    # --- Claim sur contrat inconnu ---
    elif fn == "claim":
        flags.append("claim_on_unknown_contract")

    # --- Mint sur contrat inconnu ---
    elif fn == "mint":
        flags.append("mint_on_unknown_contract")

    # --- Transfert natif vers contrat ---
    elif fn == "native_transfer" and value > 0:
        flags.append("native_transfer")

    return flags


# ---------------------------------------------------------------------------
# 3. COUCHE SÉMANTIQUE JEV
# ---------------------------------------------------------------------------

def _jev_post(url: str, key: str, payload: dict, timeout: float = 2.5) -> dict:
    resp = requests.post(
        url,
        json=payload,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()


def jev_semantic_check(decoded: dict, to: str, value: int, flags: list[str],
                       declared_intent: str | None = None) -> dict | None:
    """
    Couche sémantique Jev (TypeSafe AI officiel — depuis 2026-10-17).
    Diagnostic 3-en-1 en un seul pass (coût latence quasi constant, doc officielle) :
      1. is_drainer_or_scam (noul)   -> probabilité drainer 0-1
      2. risk_level (choice)         -> low/medium/high + confiance calibrée
      3. intent_match (choice)       -> l'intention DÉCLARÉE par l'agent correspond-elle
         au calldata décodé ? (si pas d'intention déclarée : test de cohérence
         fonction↔calldata, détection de décodage halluciné)
    Primaire : api.typesafe.ai/v1/systemone (version épinglée JEV_MODEL).
    Fallback secondaire : tokenra.io (revendeur) si TOKENRA_API_KEY configurée.
    """
    if not TYPESAFE_API_KEY and not TOKENRA_API_KEY:
        return None  # aucune clé configurée : pas d'appel réseau mort

    intent_line = (
        f"Declared agent intent: {declared_intent}\n" if declared_intent else ""
    )
    state = (
        f"An AI agent is about to submit an on-chain transaction.\n"
        f"Target contract: {to}\n"
        f"Function: {decoded['function']}\n"
        f"Parameters: {json.dumps(decoded['params'])}\n"
        f"Value sent (wei): {value}\n"
        f"Pre-computed risk flags: {flags}\n"
        f"{intent_line}"
    )

    third_q = {
        "intent_match": {
            "type": "choice",
            "criteria": {
                "match": "The declared intent is fully consistent with the decoded calldata",
                "mismatch": "The declared intent does NOT match what this calldata actually does",
                "unclear": "Cannot determine consistency from the given information",
            },
        }
    } if declared_intent else {
        "consistency": {
            "type": "choice",
            "criteria": {
                "coherent": "The decoded function name matches what the calldata bytes actually do",
                "incoherent": "The decoded function does NOT correspond to the calldata content",
                "unclear": "Cannot determine",
            },
        }
    }

    questions = {
        "is_drainer_or_scam": {
            "type": "noul",
            "instructions": (
                "Does this transaction pattern match a known wallet drainer or scam? "
                "Red flags: unlimited approvals, transferFrom to unknown addresses, "
                "claim/mint on unaudited contracts, native transfers to unknown contracts."
            ),
        },
        "risk_level": {
            "type": "choice",
            "criteria": {
                "low": "Standard DeFi interaction (swap, deposit, verified contract)",
                "medium": "Ambiguous — needs human review or extra checks",
                "high": "Likely drainer or malicious — should be blocked",
            },
        },
        **third_q,
    }

    attempts = []
    if TYPESAFE_API_KEY:
        attempts.append((TYPESAFE_API_URL, TYPESAFE_API_KEY, JEV_MODEL, "typesafe"))
    if TOKENRA_API_KEY:
        attempts.append((JEV_FALLBACK_URL, TOKENRA_API_KEY, "jev-latest", "tokenra-fallback"))

    for url, key, model, via in attempts:
        payload = {"model": model, "state": state, "questions": questions}
        try:
            body = _jev_post(url, key, payload)
            answers = body["answers"]
            result = {
                "drainer_prob": answers["is_drainer_or_scam"]["noul"],
                "risk_level": answers["risk_level"]["choice"],
                "risk_confidence": answers["risk_level"]["confidence"],
                "model": body.get("model", model),
                "via": via,
            }
            if declared_intent:
                im = answers.get("intent_match", {})
                result["intent_match"] = im.get("choice")
                result["intent_confidence"] = im.get("confidence")
            else:
                cs = answers.get("consistency", {})
                result["consistency"] = cs.get("choice")
            return result
        except Exception as e:
            print(f"[Jev:{via}] error: {e}")
    return None


# ---------------------------------------------------------------------------
# 4. VERDICT FINAL + SIGNATURE
# ---------------------------------------------------------------------------

# Limites déclarées embarquées dans le payload signé (convention "limits" des
# vectors de conformance, discussion publique erc-8004#99) : ce qu'un verdict dit
# et ne dit pas.
VERDICT_LIMITS = [
    "shows: transaction-shape risk (recipient, allowance, calldata heuristics) evaluated before execution",
    "does not show: that any work followed the payment",
    "does not show: counterparty honesty or producer intent",
]


def _normalize_nonce(nonce: str | None) -> str | None:
    """Valide un nonce ERC-3009 bytes32 (0x + 64 hex). None si absent/invalide."""
    if not nonce:
        return None
    n = nonce.strip().lower()
    if len(n) != 66 or not n.startswith("0x"):
        return None
    body = n[2:]
    if not all(c in "0123456789abcdef" for c in body):
        return None
    if body == "0" * 64:
        return None  # nonce nul : non usage
    return n


def build_verdict(
    decoded: dict,
    to: str,
    value: int,
    flags: list[str],
    goplus: dict,
    jev: dict | None,
    ofac_hits: tuple = (),
    degraded: tuple = (),
    checks_failed: tuple = (),
    nonce: str | None = None,
    chain_id: int = 8453,
) -> dict:
    """
    Agrège toutes les couches en un verdict final.
    Règles de priorité :
      - GoPlus drainer/sanction → BLOCK (déterministe)
      - Jev high risk + drainer_prob > 0.7 → BLOCK
      - unlimited approval + contrat inconnu → CAUTION
      - Sinon → SAFE
    v1.2 : binding (nonce-bound vs shape-bound), evaluation_status mesuré
    ou non (règle NOT_MEASURED de la discussion erc-8004#99), limites embarquées.
    Le gate reste fail-closed strict : une couche injoignable donne BLOCK,
    mais le verdict dit désormais POURQUOI (dangereux vs aveugle).
    """
    reasons = []
    block = False
    caution = False

    # --- Couche 0 : blocklist OFAC locale (BLOCK absolu, hors-ligne) ---
    if ofac_hits:
        block = True
        reasons.append("ofac_sanctioned_address")

    # --- Couche 1 : GoPlus (déterministe, priorité max) ---
    if goplus.get("is_drainer"):
        block = True
        reasons.append("goplus_drainer_match")
    if goplus.get("is_blackmail"):
        block = True
        reasons.append("goplus_blacklist_match")
    if goplus.get("is_sanctioned"):
        block = True
        reasons.append("goplus_sanctioned")
    if goplus.get("unavailable"):
        # Mode FAIL-CLOSED strict (règle depuis 2026-10-17) :
        # couche de confiance injoignable => aucun SAFE possible, BLOCK.
        block = True
        reasons.append("goplus_unavailable_fail_closed")
    if degraded:
        block = True
        reasons.extend(degraded)

    # --- Couche 2 : Heuristiques ---
    if "unlimited_erc20_approval" in flags:
        caution = True
        reasons.append("unlimited_erc20_approval")
    if "transferFrom_called" in flags:
        caution = True
        reasons.append("transferFrom_called")
    if "claim_on_unknown_contract" in flags:
        caution = True
        reasons.append("claim_on_unknown_contract")

    # --- Couche 3 : Jev (sémantique) ---
    if jev:
        if jev["drainer_prob"] > 0.7:
            block = True
            reasons.append(f"jev_drainer_prob_high({jev['drainer_prob']:.2f})")
        elif jev["drainer_prob"] > 0.4:
            caution = True
            reasons.append(f"jev_drainer_prob_medium({jev['drainer_prob']:.2f})")
        if jev["risk_level"] == "high":
            block = True
            reasons.append("jev_risk_high")
        elif jev["risk_level"] == "medium":
            caution = True
            reasons.append("jev_risk_medium")
        # Diagnostic 3-en-1 (depuis 2026-10-17) : intention vs calldata
        if jev.get("intent_match") == "mismatch":
            caution = True
            reasons.append("jev_intent_mismatch")
        elif jev.get("consistency") == "incoherent":
            caution = True
            reasons.append("jev_decode_incoherent")

    if block:
        verdict = "BLOCK"
    elif caution:
        verdict = "CAUTION"
    else:
        verdict = "SAFE"

    # v1.2 — binding : un verdict avec nonce ERC-3009 valide est "nonce-bound"
    # (ouvrable contre exactement un règlement), sinon "shape-bound" (jamais
    # promu, convention SHAPE_BOUND de la discussion erc-8004#99).
    nonce_norm = _normalize_nonce(nonce)
    if nonce_norm:
        binding = {"kind": "nonce-bound", "nonce": nonce_norm}
    else:
        binding = {"kind": "shape-bound"}

    # v1.2 — evaluation_status : "not-measured" si une couche de confiance
    # requise (GoPlus, blocklist OFAC) n'a pas pu s'exécuter. Le gate BLOCK,
    # mais le verdict distingue "dangereux" de "on n'a pas pu voir".
    required_failed = [c for c in checks_failed if c in ("goplus", "ofac_blocklist")]
    evaluation_status = "not-measured" if required_failed else "measured"

    # --- Signature Ed25519 du verdict (payload canonique v1.2) ---
    verdict_payload = {
        "verdict": verdict,
        "to": to,
        "function": decoded["function"],
        "value": int(value),
        "reasons": reasons,
        "timestamp": int(time.time()),
        "chain_id": int(chain_id),
        "binding": binding,
        "evaluation_status": evaluation_status,
        "checks_failed": sorted(checks_failed),
        "limits": VERDICT_LIMITS,
    }
    canonical = json.dumps(verdict_payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).digest()
    signature = SIGNING_KEY.sign(digest).signature
    sig_hex = signature.hex()

    return {
        **verdict_payload,
        "confidence": jev.get("risk_confidence") if jev else None,
        "goplus": goplus,
        "jev": jev,
        "signature": sig_hex,
        "verify_key": VERIFY_KEY_HEX,
    }


# ---------------------------------------------------------------------------
# 5. ENTRY POINT
# ---------------------------------------------------------------------------

def check_transaction(
    to: str,
    calldata: str,
    value: int = 0,
    chain_id: int = 8453,
    declared_intent: str | None = None,
    nonce: str | None = None,
) -> dict:
    """
    Vérifie une transaction avant signature.
    Retourne le verdict signé.
    v1.2 : `nonce` (bytes32 ERC-3009, optionnel) rend le verdict nonce-bound,
    ouvrable contre exactement un règlement futur (fil erc-8004#99).
    """
    t0 = time.time()

    # 1. Décodage
    decoded = decode_calldata(calldata)

    # 2. Heuristiques
    flags = heuristic_checks(decoded, to, value)

    # 2b. Blocklist OFAC locale : cible + paramètres adresse (ex. spender d'un approve)
    candidates = [to] + [p for p in decoded["params"].values()
                         if isinstance(p, str) and p.startswith("0x") and len(p) == 42]
    ofac_hits = tuple(a for a in candidates if ofac_sanctioned(a))
    if ofac_hits:
        # BLOCK déterministe : aucun appel réseau nécessaire
        verdict = build_verdict(decoded, to, value, flags, {}, None, ofac_hits,
                                 nonce=nonce, chain_id=chain_id)
        verdict["ofac_hits"] = list(ofac_hits)
        verdict["latency_ms"] = round((time.time() - t0) * 1000, 1)
        return verdict

    # 3. GoPlus — TOUJOURS (fail-closed strict : pas de SAFE sans couche de
    # confiance consultée ; l'OFAC hit a déjà court-circuité au-dessus)
    goplus = check_goplus_malicious(to, chain_id)

    # 4. Jev (si pas déjà un flag bloquant déterministe)
    jev = None
    jev_attempted = bool(TYPESAFE_API_KEY or TOKENRA_API_KEY)
    if not goplus.get("is_drainer") and not goplus.get("is_blackmail") and not goplus.get("is_sanctioned"):
        jev = jev_semantic_check(decoded, to, value, flags, declared_intent)

    # 4b. v1.2 — quelles couches n'ont pas pu s'exécuter (règle NOT_MEASURED)
    failed = []
    if goplus.get("unavailable"):
        failed.append("goplus")
    if _OFAC_ERROR:
        failed.append("ofac_blocklist")
    if jev_attempted and jev is None and not failed:
        # tentative réelle + aucune donnée = échec réseau des endpoints sémantiques
        failed.append("jev_semantic")

    # 5. Verdict final
    degraded = ("ofac_blocklist_unavailable_fail_closed",) if _OFAC_ERROR else ()
    verdict = build_verdict(decoded, to, value, flags, goplus, jev, degraded=degraded,
                             checks_failed=tuple(failed), nonce=nonce, chain_id=chain_id)
    verdict["latency_ms"] = round((time.time() - t0) * 1000, 1)

    return verdict


# ---------------------------------------------------------------------------
# 5. /regime — marché lu par Jev + score sismique déterministe (v1.3, 19/10/26)
# ---------------------------------------------------------------------------
# Le capteur armée (seismo, cycle 30 min) écrit etat.json sur ce VPS.
# /regime vend une lecture SIGNÉE de ce snapshot : score déterministe (arithmo
# jamais deleguee a l'LLM) + étiquette de regime Jev (shadow-mode -> produit).
# live_jev=true rafraîchit la classification Jev à la demande (~150-400ms,
# ~0.000015 $) ; par défaut on ressert l'étiquette du dernier cycle -> $0.

SEISMO_ETAT_PATH = os.environ.get("SEISMO_ETAT", "/var/lib/svarog/seismo/etat.json")

REGIME_LIMITS = [
    "shows: aggregate market stress at snapshot time (cross-asset seismograph + Jev regime label)",
    "does not show: a price prediction for any specific asset",
    "does not show: that any work followed the payment",
]


def jev_market_check(state: str) -> Optional[dict]:
    """Classification Jev du régime de marché + COURBE d'escalade multi-horizons
    (1h/4h/12h/48h). Vend la term structure, pas un champ unique.
    Chaîne primaire typesafe puis fallback tokenra."""
    questions = {
        "regime": {"type": "choice", "criteria": {
            "calm": "Normal trading, low contagion risk between tech equities and crypto",
            "volatile": "Elevated moves, contagion possible but orderly",
            "stress": "Active tech-to-crypto contagion, infrastructure/liquidity strain",
            "crisis": "Dislocation, forced selling, stablecoin or exchange stress"}},
        "escalade_1h": {"type": "noul", "instructions": "Probability market stress increases within 1 hour"},
        "escalade_4h": {"type": "noul", "instructions": "Probability market stress increases within 4 hours"},
        "escalade_12h": {"type": "noul", "instructions": "Probability market stress increases within 12 hours"},
        "escalade_48h": {"type": "noul", "instructions": "Probability market stress increases within 48 hours"},
    }
    attempts = []
    if TYPESAFE_API_KEY:
        attempts.append((TYPESAFE_API_URL, TYPESAFE_API_KEY, JEV_MODEL, "typesafe"))
    if TOKENRA_API_KEY:
        attempts.append((JEV_FALLBACK_URL, TOKENRA_API_KEY, "jev-latest", "tokenra-fallback"))
    for url, key, model, via in attempts:
        payload = {"model": model, "state": state, "questions": questions}
        try:
            body = _jev_post(url, key, payload, timeout=4.0)
            a = body["answers"]
            return {
                "regime": a["regime"]["choice"],
                "confidence": a["regime"]["confidence"],
                "escalade_1h": round(a["escalade_1h"]["noul"], 3),
                "escalade_4h": round(a["escalade_4h"]["noul"], 3),
                "escalade_12h": round(a["escalade_12h"]["noul"], 3),
                "escalade_48h": round(a["escalade_48h"]["noul"], 3),
                "model": body.get("model", model),
                "via": via,
            }
        except Exception as e:
            print(f"[Jev-regime:{via}] error: {e}")
    return None


def check_market(live_jev: bool = False) -> dict:
    t0 = time.time()
    with open(SEISMO_ETAT_PATH) as f:
        snap = json.load(f)

    score = snap.get("score") or {}
    g = score.get("global")
    if g is None:
        raise ValueError("snapshot seismo sans score")
    verdict = "BLOCK" if g >= 75 else ("CAUTION" if g >= 45 else "SAFE")

    jev_stored = snap.get("jev") or {}
    if live_jev:
        jev = jev_market_check(json.dumps(snap, sort_keys=True)[:4000]) or (jev_stored or None)
        jev_live_ok = jev is not None
    else:
        jev = jev_stored or None
        jev_live_ok = False

    snap_dt = dt.datetime.fromisoformat(snap["ts"].replace("Z", "+00:00"))
    age = int(dt.datetime.now(dt.timezone.utc).timestamp() - snap_dt.timestamp())

    checks_failed = [] if jev else ["jev_semantic"]
    # courbe d'escalade — accepte les deux orthographes stockées (escal48h legacy, escalade_*)
    curve = {
        "h1": (jev or {}).get("escalade_1h"),
        "h4": (jev or {}).get("escalade_4h"),
        "h12": (jev or {}).get("escalade_12h"),
        "h48": (jev or {}).get("escalade_48h", (jev or {}).get("escal48h")),
    }
    payload = {
        "market_verdict": verdict,
        "score_global": g,
        "zone": score.get("zone"),
        "components": score.get("components"),
        "btc_exchange_spread_pct": (snap.get("btc_spread") or {}).get("disp"),
        "fng": (snap.get("fng") or {}).get("value"),
        "jev_regime": (jev or {}).get("regime"),
        "jev_confidence": (jev or {}).get("confidence", (jev or {}).get("conf")),
        "escalade_curve": curve,
        "escalade_48h": curve["h48"],
        "jev_model": (jev or {}).get("model"),
        "jev_refreshed": jev_live_ok if live_jev else False,
        "snapshot_ts": snap["ts"],
        "age_seconds": age,
        "timestamp": int(time.time()),
        "source": "subcento-seismo-v1",
        "evaluation_status": "measured" if jev else "not-measured",
        "checks_failed": checks_failed,
        "limits": REGIME_LIMITS,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).digest()
    sig_hex = SIGNING_KEY.sign(digest).signature.hex()

    payload["signature"] = sig_hex
    payload["verify_key"] = VERIFY_KEY_HEX
    payload["latency_ms"] = round((time.time() - t0) * 1000, 1)
    return payload


if __name__ == "__main__":
    # Test rapide
    test_cases = [
        # Approve illimité (drainer typique)
        {"to": "0xDeAdBeefDeAdBeefDeAdBeefDeAdBeefDeAdBeef",
         "calldata": "0x095ea7b3" + "0" * 24 + "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" + "f" * 64},
        # Transfer natif
        {"to": "0x1234567890123456789012345678901234567890",
         "calldata": "0x", "value": 10 ** 17},
        # Swap standard
        {"to": "0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24",
         "calldata": "0x7ff36ab5" + "0" * 64 + "0" * 64 + "0" * 64 + "0" * 64},
    ]
    for tc in test_cases:
        v = check_transaction(**tc)
        print(f"\n[{v['verdict']}] {v['function']} → {v['reasons']} ({v['latency_ms']}ms)")
