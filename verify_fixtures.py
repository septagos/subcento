#!/usr/bin/env python3
"""
Vérificateur hors-ligne des fixtures publique de verdict Subcento.
Aucun reseau, aucune confiance : chaque fixture JSON est re-verifiee contre sa
propre cle verify_key embarquee (canonical = exactement la liste de champs du
README). Un seul champ change -> ecchec.

Usage : python3 verify_fixtures.py [dossier]   (defaut: ./fixtures)
Sortie 0 = toutes les fixtures valident.
"""
import hashlib
import json
import sys
from pathlib import Path

from nacl.encoding import HexEncoder
from nacl.signing import VerifyKey

# Meme liste que README.md ("Verify a verdict — in 10 lines") — modifier l'un
# sans l'autre est volontairement un echec de cette batterie.
FIELDS = ("verdict", "to", "function", "value", "calldata_sha256", "reasons",
          "timestamp", "chain_id", "binding", "evaluation_status",
          "checks_failed", "limits")


def verify(verdict: dict) -> None:
    payload = {k: verdict[k] for k in FIELDS}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).digest()
    VerifyKey(verdict["verify_key"], HexEncoder).verify(
        digest, bytes.fromhex(verdict["signature"]))


def main() -> int:
    folder = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parent / "fixtures")
    files = sorted(folder.glob("*.json"))
    if not files:
        print(f"AUCUNE fixture dans {folder}")
        return 1
    bad = 0
    for f in files:
        v = json.loads(f.read_text())
        try:
            verify(v)
            print(f"  ok   {f.name:28s} {v['verdict']:7s} {v['evaluation_status']:12s} "
                  f"binding={v['binding']['kind']}")
        except Exception as e:
            bad += 1
            print(f"  FAIL {f.name}: {e}")
    if bad:
        print(f"\n{bad} fixture(s) NON VERIFIEE(S)")
        return 1
    print(f"\n{len(files)} fixtures verifiees hors-ligne — signatures valides")
    return 0


if __name__ == "__main__":
    sys.exit(main())
