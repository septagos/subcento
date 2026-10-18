#!/usr/bin/env python3
"""
Client Subcento — exemple d'appel depuis un agent IA.

L'agent envoie sa transaction en attente, reçoit le verdict signé,
et décide de signer ou non.
"""

import requests

# Endpoint x402 (le client x402 gère le paiement USDC automatiquement)
SUBCENTO_URL = "https://subcento.alterfield.com/check"

def verify_transaction(to: str, calldata: str, value: int = 0) -> dict:
    """
    Demande un verdict à Subcento avant de signer la transaction.
    À utiliser dans la boucle de décision de l'agent.
    """
    payload = {
        "to": to,
        "calldata": calldata,
        "value": value,
        "chain_id": 8453,  # Base
    }
    resp = requests.post(SUBCENTO_URL, json=payload, timeout=5)
    resp.raise_for_status()
    return resp.json()


def agent_decision_loop(to: str, calldata: str, value: int = 0) -> bool:
    """
    Exemple de boucle de décision d'un agent :
      - SAFE → signe
      - CAUTION → demande confirmation humaine
      - BLOCK → refuse
    """
    verdict = verify_transaction(to, calldata, value)
    print(f"Subcento verdict: {verdict['verdict']} (latency: {verdict.get('latency_ms')}ms)")
    print(f"Reasons: {verdict['reasons']}")

    if verdict["verdict"] == "SAFE":
        print("✅ Signing transaction...")
        return True
    elif verdict["verdict"] == "CAUTION":
        print("⚠️  CAUTION — escalate to human for approval")
        return False
    else:
        print("🚫 BLOCK — refusing transaction")
        return False


if __name__ == "__main__":
    # Exemple : approval illimité vers une adresse suspecte
    agent_decision_loop(
        to="0xDeAdBeefDeAdBeefDeAdBeefDeAdBeefDeAdBeef",
        calldata="0x095ea7b3" + "0"*24 + "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" + "f"*64,
    )
