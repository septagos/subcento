#!/usr/bin/env python3
"""
Vérificateur hors-ligne des fixtures publique de verdict Subcento (v2).

Doctrine 20/10/26 (fil erc-8004#99, critique bbv0219) : la cle de verification
ne vient PLUS du JSON qu'elle verifie. Une cle embarquee dans un fichier est
une AFFIRMATION ; verifier l'affirmation avec elle-meme laisse passer toute
resignature par une cle etrangere. Le verificateur exige donc la cle ATTENDUE
hors bande (--expected-verify-key) et echoue si :
  1. la cle embarquee diffeere de la cle attendue ;
  2. la signature ne porte pas sur le payload canonique (exactement la liste
     de 12 champs du README — meme liste, meme ordre de tri, meme JSON
     compact) verifiee avec la cle ATTENDUE ;
  3. la structure ment : binding.kind inconnu, nonce-bound sans nonce bytes32
     (0x + 64 hex), evaluation_status inconnu, checks_failed non trie.

Usage :
  python3 verify_fixtures.py --expected-verify-key <hex64> [dossier]
  python3 verify_fixtures.py --trust-embedded [dossier]  # DEV ONLY, refuse
                                                         # en production par
                                                         # la banniere d'alerte
Sortie 0 = toutes les fixtures valident contre la cle attendue.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from nacl.encoding import HexEncoder
from nacl.signing import VerifyKey

# Meme liste que README.md ("Verify a verdict — in 10 lines") — modifier l'un
# sans l'autre est volontairement un echec de cette batterie.
FIELDS = ("verdict", "to", "function", "value", "calldata_sha256", "reasons",
          "timestamp", "chain_id", "binding", "evaluation_status",
          "checks_failed", "limits")

_HEX64 = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")
_BINDING_KINDS = ("shape-bound", "nonce-bound")
_STATUSES = ("measured", "not-measured")


def canonical_bytes(verdict: dict) -> bytes:
    payload = {k: verdict[k] for k in FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def check_structure(verdict: dict) -> None:
    """Invariants de forme — une fixture structurellement menteuse est
    rejettee AVANT toute consideration de signature."""
    cd = verdict["calldata_sha256"]
    if not (isinstance(cd, str) and _HEX64.match(cd)):
        raise ValueError(f"calldata_sha256 non-bytes32 : {cd!r}")
    binding = verdict["binding"]
    if not isinstance(binding, dict) or binding.get("kind") not in _BINDING_KINDS:
        raise ValueError(f"binding.kind inconnu : {binding!r}")
    if binding["kind"] == "nonce-bound":
        nonce = binding.get("nonce")
        if not (isinstance(nonce, str) and nonce.startswith("0x")
                and re.match(r"^0x[0-9a-f]{64}$", nonce)):
            raise ValueError(f"nonce-bound sans nonce bytes32 valide : {nonce!r}")
    if verdict["evaluation_status"] not in _STATUSES:
        raise ValueError(f"evaluation_status inconnu : {verdict['evaluation_status']!r}")
    cf = verdict["checks_failed"]
    if not isinstance(cf, list) or cf != sorted(cf):
        raise ValueError(f"checks_failed non trie(e) : {cf!r}")


def verify(verdict: dict, expected_key: str) -> None:
    """Lever si la fixture n'est pas un verdict signe par expected_key."""
    check_structure(verdict)
    embedded = verdict["verify_key"]
    norm_expected = expected_key.lower().removeprefix("0x")
    norm_embedded = embedded.lower().removeprefix("0x")
    if norm_embedded != norm_expected:
        raise ValueError(
            f"cle embarquee ({norm_embedded[:16]}…) != cle attendue "
            f"({norm_expected[:16]}…) : la fixture n'a pas ete produite par "
            "le signing key annonce — ressignature probable")
    digest = hashlib.sha256(canonical_bytes(verdict)).digest()
    VerifyKey(norm_expected.encode(), HexEncoder).verify(
        digest, bytes.fromhex(verdict["signature"]))


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Verificateur hors-ligne des fixtures de verdict Subcento.")
    ap.add_argument("--expected-verify-key", metavar="HEX64",
                    help="cle de verification attendue, fournie hors bande "
                         "(site /health, autorite racine). OBLIGATOIRE sauf en "
                         "mode dev.")
    ap.add_argument("--trust-embedded", action="store_true",
                    help="DEV ONLY : verifie contre la cle embarquee (la "
                         "faille critiquee par erc-8004#99). Banner d'alerte.")
    ap.add_argument("folder", nargs="?",
                    default=str(Path(__file__).parent / "fixtures"))
    args = ap.parse_args()

    if args.trust_embedded and not args.expected_verify_key:
        print("!! MODE DEV : verification contre cle EMBARQUEE. Cette voie "
              "accepte les resignatures etangeres — ne JAMAIS s'en servir "
              "pour une decision, seulement pour du debug de fixture.")
    elif not args.expected_verify_key:
        ap.error("--expected-verify-key requis (ou --trust-embedded en dev)")

    folder = Path(args.folder)
    files = sorted(folder.glob("*.json"))
    if not files:
        print(f"AUCUNE fixture dans {folder}")
        return 1
    bad = 0
    keys_to_try = ([args.expected_verify_key] if args.expected_verify_key else [])
    for f in files:
        v = json.loads(f.read_text())
        tried = keys_to_try or [v["verify_key"]]
        ok = False
        err = Exception("aucune cle testee")
        for k in tried:
            try:
                verify(v, k)
                ok = True
                break
            except Exception as e:
                err = e
        if ok:
            print(f"  ok   {f.name:28s} {v['verdict']:7s} {v['evaluation_status']:12s} "
                  f"binding={v['binding']['kind']}")
        else:
            bad += 1
            print(f"  FAIL {f.name}: {err}")
    if bad:
        print(f"\n{bad} fixture(s) NON VERIFIEE(S)")
        return 1
    print(f"\n{len(files)} fixtures verifiees hors-ligne — signatures valides "
          f"contre la cle attendue")
    return 0


if __name__ == "__main__":
    sys.exit(main())
