#!/usr/bin/env python3
"""Regeneration DETERMINISTE des 5 fixtures du kit-verdict (fil erc-8004#99).

Lancer avec la cle de production via SUBCENTO_KEY_PATH (jamais le defaut
relatif). Les couches reseau (GoPlus / Jev) sont STUBBEES sur les releves
d'origine (fixtures du 20/10, kit_inputs.json) : les scenarios restent
figes. Seules corrections volontaires :
  - nonce_bound : nonce bytes32 VALIDE (0xde*32) -> binding nonce-bound ;
  - not_measured_blind : checks_failed nomme les DEUX couches aveugles
    (regle NOT_MEASURED, patch v1.3.2+ du 20/10).
Format fichier identique a l'original normalise : json pretty (indent=2,
sort_keys) + newline final. Ed25519 etant deterministe, les payloads
inchanges ressortent octet-pour-octet identiques si la cle est celle
d'origine (gate de fidelite).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import subcento_engine as e  # noqa: E402

KITSRC = os.environ.get("SUBCENTO_KIT_JSON", os.path.join(HERE, "kit_inputs.json"))
OUTDIR = os.environ.get("SUBCENTO_OUTDIR", os.path.join(HERE, "fixtures_out"))


class FrozenClock:
    """time.time() au compteur : appel 1 = t0, appel 2 = timestamp signe
    (identiques), appel 3+ = t0+latence d'origine. monotonic() explose si
    appele => toute derive de sequence de clock est detectee, pas silencieuse."""

    def __init__(self, ts: int, lat_ms: float):
        self.n = 0
        self.ts = ts
        self.adv = lat_ms / 1000.0

    def time(self):
        self.n += 1
        return self.ts if self.n <= 2 else self.ts + self.adv

    def sleep(self, _s):
        pass

    def monotonic(self):
        raise RuntimeError("monotonic() appele : sequence de clock derivee")


def main():
    kit = json.load(open(KITSRC))
    os.makedirs(OUTDIR, exist_ok=True)
    for name in sorted(kit):
        f = kit[name]
        e.time = FrozenClock(int(f["ts"]), float(f["latency_ms"]))
        goplus = f.get("goplus")
        e.check_goplus_malicious = lambda to, chain_id, _g=goplus: (
            {"unavailable": True} if _g and _g.get("unavailable")
            else (dict(_g) if _g else {})
        )
        jev = f.get("jev")
        e.jev_semantic_check = lambda *a, _j=jev: (dict(_j) if _j else None)
        v = e.check_transaction(f["to"], f["calldata"], value=f["value"],
                                nonce=f.get("nonce"))
        out = os.path.join(OUTDIR, name + ".json")
        with open(out, "w") as fh:
            fh.write(json.dumps(v, indent=2, sort_keys=True) + "\n")
        print(f"{name:22s} verdict={v['verdict']:7s} binding={v['binding']['kind']:11s} "
              f"checks_failed={sorted(v['checks_failed'])} status={v['evaluation_status']}")
    print("signing verify_key:", e.VERIFY_KEY_HEX[:16] + "…")


if __name__ == "__main__":
    main()
