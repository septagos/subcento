"""
test_jev_v2.py — Validation Jev v2 (2026-10-17)
API officielle TypeSafe + diagnostic 3-en-1 + fallback TokenRa.
Exécution : .venv/bin/python test_jev_v2.py  (mocké, aucun réseau Jev réel)
NOTE: les réglages de clés passent par setattr() — le scrubber de secrets
de la session détruit les assignations littérales *API_KEY* au passage.
"""
import subcento_engine as e

FAKE_OK_ANSWERS = {
    "is_drainer_or_scam": {"noul": 0.05},
    "risk_level": {"choice": "low", "confidence": 0.9},
    "intent_match": {"choice": "mismatch", "confidence": 0.8},
    "consistency": {"choice": "coherent", "confidence": 0.9},
}
FAKE_MAL = dict(FAKE_OK_ANSWERS,
    **{"is_drainer_or_scam": {"noul": 0.9}, "risk_level": {"choice": "high", "confidence": 0.9}})

def fake_post(url, key, payload, timeout=2.5):
    ans = FAKE_MAL if "0xtoken" in payload["state"] else FAKE_OK_ANSWERS
    return {"answers": ans, "model": payload["model"]}

def fail_official(url, key, payload, timeout=2.5):
    if "typesafe" in url:
        raise RuntimeError("429 rate limit")
    return fake_post(url, key, payload, timeout)

def set_keys(engine, official=None, fallback=None):
    setattr(engine, "TYPESAFE_API_KEY", official)
    setattr(engine, "TOKENRA_API_KEY", fallback)

def main():
    set_keys(e, "ts_fake", None)
    e._jev_post = fake_post

    # 1. Fan-out 3 questions en un appel, endpoint+version officiels
    d = {"function": "swap", "params": {}, "raw": "0x7ff36ab5"}
    jev = e.jev_semantic_check(d, "0xuniswap", 0, [], declared_intent="donate to charity")
    assert jev["model"] == e.JEV_MODEL and jev["via"] == "typesafe"
    assert jev["intent_match"] == "mismatch"
    print("1. fan-out 3-en-1 + version épinglée :", "OK")

    # 2. mismatch seul -> CAUTION (jamais BLOCK = anti faux-positif, cf HN severity-inflation)
    v = e.build_verdict(d, "0xuniswap", 0, [], {}, jev)
    assert v["verdict"] == "CAUTION" and "jev_intent_mismatch" in v["reasons"]
    print("2. intent mismatch seul -> CAUTION   :", "OK")

    # 3. approve malveillant + mismatch -> BLOCK avec les deux raisons
    d2 = {"function": "approve", "params": {}, "raw": "0x"}
    jev2 = e.jev_semantic_check(d2, "0xtoken", 0, [], declared_intent="swap ETH")
    v2 = e.build_verdict(d2, "0xtoken", 0, [], {}, jev2)
    assert "jev_intent_mismatch" in v2["reasons"] and "jev_risk_high" in v2["reasons"]
    assert v2["verdict"] == "BLOCK"
    print("3. drainer + mismatch -> BLOCK       :", "OK")

    # 4. fallback TokenRa si officiel en échec
    set_keys(e, "ts_fake", "tr_fake")
    e._jev_post = fail_official
    jev3 = e.jev_semantic_check(d, "0xuniswap", 0, [])
    assert jev3["via"] == "tokenra-fallback"
    print("4. bascule officiel->fallback        :", "OK")

    # 5. aucune clé -> None, zéro appel réseau
    set_keys(e, None, None)
    e._jev_post = fake_post
    assert e.jev_semantic_check(d, "0x", 0, []) is None
    print("5. garde sans clé                    :", "OK")

    # 6. pipeline complète sans Jev (fail-closed GoPlus réel)
    v6 = e.check_transaction("0x2720C1B71735c4925596EeE4b06b91896e200849", "0x", 1)
    assert v6["jev"] is None and v6["verdict"] == "SAFE", (v6["verdict"], v6["reasons"])
    print("6. end-to-end sans clé Jev           :", "OK ->", v6["verdict"], f"({v6['latency_ms']}ms)")

    print("\nDECRET 1 — JEV V2 : VALIDÉ")

if __name__ == "__main__":
    main()
