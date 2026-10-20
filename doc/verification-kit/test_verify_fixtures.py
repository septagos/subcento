#!/usr/bin/env python3
"""
test_verify_fixtures.py — É4 OBLIGATOIRE (doctrine 20/10/26, fil erc-8004#99).

Prouve que le verificateur v2 ne tombe pas dans la faille signalee par bbv0219 :
"verifier une signature avec la cle embarquee dans le fichier verifie laisse
passer n'importe quelle ressignature".

Attacke simulee : fixture legitime RE-SIGNEE avec une cle etrangere, champ
verify_key remplace par la cle etrangere, le tout structurellement parfait.

Resultats attends :
  A. ancien verificateur (HEAD pre-20/10, cle embarquee seule) : ACCEPTE
     l'attaque  -> c'est la faille, documentee en preuve.
  B. nouveau verificateur avec --expected-verify-key (cle legitime) : REJETTE.
  C. nouveau verificateur, fixture legitime + bonne cle attendue : ACCEPTE.
  D. champ unique altere (verdict CAUTION->SAFE) resigne a la cle etrangere :
     REJETTE.
  E. nonce-bound avec nonce non-bytes32 : REJETTE (structure, pas signature).
"""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey, VerifyKey

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import verify_fixtures as vf  # noqa: E402

FIELDS = vf.FIELDS
LEGIT_FOLDER = HERE / "fixtures"

def foreign_key():
    """Cle de test ETRANGERE a celle des fixtures : generee ici, jetee en fin
    de test. Deterministe via seed fixe (test reproductible, aucun secret)."""
    return SigningKey(seed=b"\x01" * 32)

def resign(verdict: dict, sk: SigningKey) -> dict:
    v = dict(verdict)
    payload = {k: v[k] for k in FIELDS}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).digest()
    sig = sk.sign(digest).signature
    v["signature"] = sig.hex()
    v["verify_key"] = sk.verify_key.encode(encoder=HexEncoder).decode()
    return v

def old_style_verify(verdict: dict) -> bool:
    """Logique de l'ancien verificateur : cle EMBARQUEE uniquement."""
    payload = {k: verdict[k] for k in FIELDS}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).digest()
    try:
        VerifyKey(verdict["verify_key"], HexEncoder).verify(
            digest, bytes.fromhex(verdict["signature"]))
        return True
    except Exception:
        return False

def run_cli(folder: Path, key: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HERE / "verify_fixtures.py"),
         "--expected-verify-key", key, str(folder)],
        capture_output=True, text=True)

def main() -> int:
    results = []
    sk_foreign = foreign_key()
    legit = json.loads((LEGIT_FOLDER / "block_sanctioned.json").read_text())
    legit_key = legit["verify_key"]
    forged = resign(legit, sk_foreign)

    with tempfile.TemporaryDirectory() as tmp:
        fdir = Path(tmp)
        (fdir / "block_sanctioned.json").write_text(
            json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n")

        # A. preuve de la faille : l'ancien verificateur ACCEPTE la forgée
        a_ok = old_style_verify(forged)
        results.append(("A ancien verificateur accepte la resignature etrangere "
                        f"(faille prouvee) : {a_ok}", a_ok is True))

        # B. nouveau verificateur : REJETTE
        r = run_cli(fdir, legit_key)
        b_ok = r.returncode == 1 and "NON VERIFIEE" in r.stdout
        results.append((f"B nouveau verificateur rejette la forgée (exit={r.returncode})", b_ok))
        print("--- preuve B (sortie verificateur sur forgée) ---")
        print(r.stdout.strip())

        # C. nouveau verificateur sur les VRAIES fixtures : ACCEPTE
        r = run_cli(LEGIT_FOLDER, legit_key)
        c_ok = r.returncode == 0 and "NON" not in r.stdout
        results.append((f"C vraies fixtures acceptees avec cle attendue (exit={r.returncode})", c_ok))

        # D. altification d'un champ + ressignature etrangere : REJETTE
        tampered = dict(forged)
        tampered["verdict"] = "SAFE"
        tampered = resign(tampered, sk_foreign)
        with tempfile.TemporaryDirectory() as tmp2:
            fdir2 = Path(tmp2)
            (fdir2 / "t.json").write_text(
                json.dumps(tampered, sort_keys=True, separators=(",", ":")) + "\n")
            r = run_cli(fdir2, legit_key)
            d_ok = r.returncode == 1
            results.append((f"D SAFE forge + cle attendue legitime : rejet (exit={r.returncode})", d_ok))

        # E. structure menteuse : nonce-bound sans bytes32 -> rejet AVANT signature
        bad_struct = json.loads((LEGIT_FOLDER / "caution_transfer.json").read_text())
        bad_struct["binding"] = {"kind": "nonce-bound", "nonce": "0xdeadbeef"}
        try:
            vf.verify(resign(bad_struct, sk_foreign), legit_key)
            e_ok = False
        except ValueError as ex:
            e_ok = "bytes32" in str(ex)
        results.append((f"E nonce-bound non-bytes32 rejet sur structure ({e_ok})", e_ok))

    fails = [m for m, ok in results if not ok]
    for m, ok in results:
        print(("  OK  " if ok else "  FAIL") + " " + m)
    if fails:
        print(f"\n{len(fails)} test(s) ECHEUES")
        return 1
    print("\nÉ4 — RESIGNATURE ETRANGERE REJETEE : BATTERIE VERTE")
    return 0

if __name__ == "__main__":
    sys.exit(main())
