#!/usr/bin/env python3
"""
Met a jour ofac_blocklist.json depuis la liste SDN du Tresor americain.
Usage : .venv/bin/python update_ofac_blocklist.py
Freq conseilles : hebdomadaire (la liste est publiee presque chaque semaine).
"""
import datetime
import json
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

S = "{https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/XML}"
URL = "https://www.treasury.gov/ofac/downloads/sdn.xml"
OUT = Path(__file__).parent / "ofac_blocklist.json"


def main() -> None:
    print(f"Téléchargement {URL} ...")
    req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0"})
    raw = urllib.request.urlopen(req, timeout=120).read()
    root = ET.fromstring(raw)
    buckets: dict[str, set] = {}
    for ide in root.iter(S + "id"):
        t = ide.find(S + "idType")
        n = ide.find(S + "idNumber")
        if t is None or n is None or not (t.text or "").startswith("Digital Currency Address"):
            continue
        ticker = t.text.split(" - ")[-1].strip().lower()
        buckets.setdefault(ticker, set()).add(n.text.strip())
    pub_el = root.find(f".//{S}Publish_Date")
    out = {
        "source": "OFAC SDN (US Treasury)",
        "url": URL,
        "published": pub_el.text if pub_el is not None else "?",
        "generated": datetime.date.today().isoformat(),
        "counts": {k: len(v) for k, v in sorted(buckets.items())},
        "addresses": {k: sorted(v) for k, v in sorted(buckets.items())},
    }
    OUT.write_text(json.dumps(out, indent=1))
    print(f"OK | publication: {out['published']} | tickers: {out['counts']}")


if __name__ == "__main__":
    main()
