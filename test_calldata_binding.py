#!/usr/bin/env python3
"""
Batterie v1.3 — calldata_sha256 binding (colmatage du vecteur n°3, erc-8004#99).
Hors-ligne, déterministe : passe sans réseau, sans clés, sans serveur.
Test d'INAM : tout est recompute, zero placeholder.
"""
import hashlib
import json
import sys

import nacl.signing
import nacl.encoding
from nacl.signing import VerifyKey

import subcento_engine as eng

PASS, FAIL = [], []


def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("  ok   " if cond else "  FAIL") + f" — {name}")


def canonicalize(v):
    fields = ("verdict", "to", "function", "value", "calldata_sha256", "reasons",
              "timestamp", "chain_id", "binding", "evaluation_status",
              "checks_failed", "limits")
    payload = {k: v[k] for k in fields}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


USDC_BASE = "0x833589fcd6edb6e29f4c1c32d4f71b5da15141a6"  # mock cible
TRANSFER_SEL = "0xa9059cbb"
ADDR_A = "000000000000000000000000" + "11" * 20
ADDR_B = "000000000000000000000000" + "22" * 20
AMT_1 = "0" * 63 + "1"
AMT_2 = "0" * 63 + "2"
CD_A1 = TRANSFER_SEL + ADDR_A + AMT_1   # transfer(A, 1)
CD_A2 = TRANSFER_SEL + ADDR_A + AMT_2   # transfer(A, 2)  meme sel, args differents
CD_B1 = TRANSFER_SEL + ADDR_B + AMT_1   # transfer(B, 1)

# ---------------------------------------------------------------- 1. normalise
print("[1] _normalize_calldata")
check("empty -> 0x", eng._normalize_calldata("") == "0x")
check("none -> 0x", eng._normalize_calldata(None) == "0x")
check("0x -> 0x", eng._normalize_calldata("0x") == "0x")
check("uppercase -> lowercase", eng._normalize_calldata("0xAaBB") == "0xaabb")
check("bare hex gets 0x", eng._normalize_calldata("aabb") == "0xaabb")
check("whitespace stripped", eng._normalize_calldata("  0xAABB  ") == "0xaabb")
try:
    eng._normalize_calldata("0xzz")
    check("non-hex raises", False)
except ValueError:
    check("non-hex raises", True)
try:
    eng._normalize_calldata("0x123")
    check("odd-length raises", False)
except ValueError:
    check("odd-length raises", True)

# ------------------------------------------- 2. sélecteur identique, args différents
print("[2] mutation de calldata -> digest different (le trou du fil #99)")
d_a1 = eng.decode_calldata(CD_A1)
d_a2 = eng.decode_calldata(CD_A2)
v_a1 = eng.build_verdict(d_a1, USDC_BASE, 0, [], {"unavailable": True}, None,
                         checks_failed=("goplus",))
v_a2 = eng.build_verdict(d_a2, USDC_BASE, 0, [], {"unavailable": True}, None,
                         checks_failed=("goplus",))
check("meme function/meme selecteur", v_a1["function"] == v_a2["function"])
check("calldata_sha256 DIFFERENTS sur args differents",
      v_a1["calldata_sha256"] != v_a2["calldata_sha256"])

# même calldata écrit en majuscules -> même digest (normalisation reproductible)
v_up = eng.build_verdict(eng.decode_calldata(CD_A1.upper()), USDC_BASE, 0, [],
                         {"unavailable": True}, None, checks_failed=("goplus",))
check("casse differente -> meme digest",
      v_up["calldata_sha256"] == v_a1["calldata_sha256"])

# digest = sha256 de l'hex normalisé, recomputable independamment
expected = hashlib.sha256(CD_A1.lower().encode()).hexdigest()
check("digest = sha256(normalise), recomputable", v_a1["calldata_sha256"] == expected)

# native transfer (pas de calldata) -> digest de "0x", pas un trou
v_native = eng.build_verdict(eng.decode_calldata("0x"), USDC_BASE, 1000, [],
                             {"unavailable": True}, None, checks_failed=("goplus",))
check("natif: digest de '0x' present",
      v_native["calldata_sha256"] == hashlib.sha256(b"0x").hexdigest())

# ------------------------------------------------------------- 3. signature/verify
print("[3] roundtrip Ed25519 + anti-mutation")
try:
    VerifyKey(v_a1["verify_key"], nacl.encoding.HexEncoder).verify(
        hashlib.sha256(canonicalize(v_a1)).digest(), bytes.fromhex(v_a1["signature"]))
    check("verification du verdict tel qu'emis", True)
except Exception:
    check("verification du verdict tel qu'emis", False)

tampered = dict(v_a1)
tampered["calldata_sha256"] = hashlib.sha256(CD_B1.encode()).hexdigest()
try:
    VerifyKey(v_a1["verify_key"], nacl.encoding.HexEncoder).verify(
        hashlib.sha256(canonicalize(tampered)).digest(), bytes.fromhex(v_a1["signature"]))
    check("mutation calldata_sha256 -> verification ECHOUÉE", False)
except Exception:
    check("mutation calldata_sha256 -> verification ECHOUÉE", True)

# l'ancien canonique v1.2 (sans calldata_sha256) ne doit PLUS vérifier un v1.3
fields_v12 = tuple(f for f in ("verdict", "to", "function", "value", "reasons",
                               "timestamp", "chain_id", "binding",
                               "evaluation_status", "checks_failed", "limits"))
old_canon = json.dumps({k: v_a1[k] for k in fields_v12},
                       sort_keys=True, separators=(",", ":")).encode()
try:
    VerifyKey(v_a1["verify_key"], nacl.encoding.HexEncoder).verify(
        hashlib.sha256(old_canon).digest(), bytes.fromhex(v_a1["signature"]))
    check("canonique v1.2 ne vérifie plus un verdict v1.3", False)
except Exception:
    check("canonique v1.2 ne vérifie plus un verdict v1.3", True)

# ------------------------------------------------------------ 4. fail-closed intact
print("[4] invariants v1.2 conservés")
check("goplus aveugle -> evaluation_status not-measured",
      v_a1["evaluation_status"] == "not-measured")
check("goplus aveugle -> verdict BLOCK (fail-closed)", v_a1["verdict"] == "BLOCK")
check("shape-bound jamais promu", v_a1["binding"] == {"kind": "shape-bound"})
v_nonce = eng.build_verdict(d_a1, USDC_BASE, 0, [], {"unavailable": True}, None,
                            checks_failed=("goplus",),
                            nonce="0x" + "ab" * 32)
check("nonce-bound: binding contient le nonce normalise",
      v_nonce["binding"]["kind"] == "nonce-bound")

# ------------------------------------------------------------------------ résumé
print(f"\n{len(PASS)} pass / {len(FAIL)} fail")
if FAIL:
    print("ÉCHECS: " + ", ".join(FAIL))
    sys.exit(1)
print("BATTERIE CALADATA v1.3 : VERTE")
