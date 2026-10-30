"""Look up the CAPEC attack patterns related to one or more CWEs.

Reads resources/cwe_db.json (refreshed by update_cwe_db.py) and
resources/capec_db.json (refreshed by update_capec_db.py).

Modes:
    direct   CAPECs listed on the CWE itself
    nearest  walk up the ChildOf hierarchy (View 1000) level by level and
             stop at the first level that has CAPECs (default)
    all      the CWE and all its ancestors, like cve2cwe.py + cwe2capec.py

Usage:
    python cwe2capec_lookup.py 79
    python cwe2capec_lookup.py CWE-787 CWE-416 --mode all
    python cwe2capec_lookup.py 89 --json
"""
import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
CWE_FILE = os.path.join(ROOT, "resources/cwe_db.json")
CAPEC_FILE = os.path.join(ROOT, "resources/capec_db.json")
MODES = ("direct", "nearest", "all")


# Normalize "79", "CWE-79", "cwe_79" or "CWE 079" to "79"
def parse_cwe_id(value: str):
    m = re.fullmatch(r"(?:CWE[-_ ]?)?(\d+)", value.strip(), re.IGNORECASE)
    if not m:
        raise argparse.ArgumentTypeError(f"invalid CWE ID: {value!r}")
    return str(int(m.group(1)))


def load_json(path):
    with open(path, 'r') as f:
        return json.load(f)


# Walk the ChildOf hierarchy breadth-first, one level of CWEs at a time
def levels(cwe: str, cwe_db: dict):
    level, seen = [cwe], {cwe}
    while level:
        yield level
        next_level = []
        for current in level:
            for parent in cwe_db.get(current, {}).get("ChildOf", []):
                if parent not in seen:
                    seen.add(parent)
                    next_level.append(parent)
        level = next_level


# Map each related CAPEC to the CWEs it was found on
def lookup(cwe: str, cwe_db: dict, mode: str):
    sources = {}
    for level in levels(cwe, cwe_db):
        for current in level:
            for capec in cwe_db.get(current, {}).get("RelatedAttackPatterns", []):
                sources.setdefault(capec, []).append(current)
        if mode == "direct" or (mode == "nearest" and sources):
            break
    return sources


def build_result(cwe: str, cwe_db: dict, capec_db: dict, mode: str):
    found = cwe in cwe_db
    sources = lookup(cwe, cwe_db, mode) if found else {}
    return {
        "cwe": f"CWE-{cwe}",
        "found": found,
        "mode": mode,
        "capec": [
            {
                "id": f"CAPEC-{capec}",
                "name": capec_db.get(capec, {}).get("name", ""),
                "via": [f"CWE-{c}" for c in sorted(via, key=int)],
            }
            for capec, via in sorted(sources.items(), key=lambda item: int(item[0]))
        ],
    }


def print_text(results):
    for result in results:
        if not result["found"]:
            continue
        print(f"== {result['cwe']} [{result['mode']}] {len(result['capec'])} CAPEC")
        if not result["capec"] and result["mode"] == "direct":
            print("  (no CAPEC on this CWE, try --mode nearest)")
        for entry in result["capec"]:
            # Only show the origin of CAPECs inherited from an ancestor
            suffix = "" if result["cwe"] in entry["via"] else f"  (via {', '.join(entry['via'])})"
            print(f"  {entry['id']:<11} {entry['name']}{suffix}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("cwe", nargs="+", type=parse_cwe_id, help="CWE IDs, e.g. 79 or CWE-79")
    parser.add_argument("--mode", choices=MODES, default="nearest", help="lookup strategy (default: nearest)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    args = parser.parse_args()

    cwe_db = load_json(CWE_FILE)
    capec_db = load_json(CAPEC_FILE)
    results = [build_result(cwe, cwe_db, capec_db, args.mode) for cwe in dict.fromkeys(args.cwe)]

    missing = [r["cwe"] for r in results if not r["found"]]
    for cwe in missing:
        print(f"[-] {cwe} not found in {os.path.relpath(CWE_FILE, ROOT)}", file=sys.stderr)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_text(results)
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
