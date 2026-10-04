"""Runs every email in tests/cases/manifest.json through the analyzer (offline) and prints what it made of each one.
    python tests/run_cases.py            # table
    python tests/run_cases.py P05 B03    # details for the named cases"""
import json
import os
import sys
import time
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from phishing_analyzer.analyzer import analyze_email

HERE = os.path.join(os.path.dirname(__file__), "cases")
ORDER = {"low": 0, "suspicious": 1, "likely_phishing": 2, "high": 3}
with open(os.path.join(HERE, "manifest.json"), encoding="utf-8") as fh:
    manifest = json.load(fh)
want = set(sys.argv[1:])

ok = 0
for c in manifest:
    with open(os.path.join(HERE, c["file"]), "rb") as fh:
        raw = fh.read().decode("utf-8", "replace")
    t0 = time.time()
    try:
        r = analyze_email(raw, network_enabled=False).to_dict()
        err = None
    except Exception as e:  # noqa: BLE001
        r, err = None, "".join(traceback.format_exception_only(type(e), e)).strip()
    dt = time.time() - t0
    if err:
        print(f"{c['id']}  EXCEPTION {err}")
        continue
    good = ORDER[r["risk"]] >= ORDER[c["min_risk"]] if c["expected"] == "phish" else r["risk"] == "low"
    ok += good
    flag = "ok  " if good else "MISS" if c["expected"] == "phish" else "FALSE"
    print(f"{c['id']} {flag} want>={c['min_risk']:15} got {r['risk']:15} score {r['score']:3}  {r['classification'][:34]:34} ({dt:.1f}s)  {c['title'][:60]}")
    if c["id"] in want or (not want and not good):
        for f in r["findings"]:
            print(f"        - [{f['severity']}] {f['title']}  ({f['code']}, {f['points']})")
        for l in r["links"][:6]:
            print(f"        link {l['host']} risk={l['risk']} score={l['score']}")
        for a in r["attachments"]:
            print(f"        attachment {a['filename']} type={a['detected_type']} risk={a['risk']} score={a['score']} {[f['code'] for f in a['findings']]}")
print(f"\n{ok}/{len(manifest)} as expected")
