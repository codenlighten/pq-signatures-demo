#!/usr/bin/env python3
"""Builds third_party/nist-acvp/mldsa65.json from NIST's ACVP files. Standard library only.

    python3 -I tools/filter_vectors.py DIR_WITH_THE_SIX_FILES COMMIT OUTPUT

DIR holds {keyGen,sigGen,sigVer}-{prompt,expectedResults}.json, downloaded from
gen-val/json-files/ML-DSA-<mode>-FIPS204/ of github.com/usnistgov/ACVP-Server at COMMIT.
Only ML-DSA-65 is kept, and for signing and verification only the external, pure interface this library uses.
"""

import hashlib
import json
import sys
from pathlib import Path


def load(path: Path) -> dict:
    data = json.loads(path.read_text())
    return data[1] if isinstance(data, list) else data


def wanted(mode: str, group: dict) -> bool:
    if group.get("parameterSet") != "ML-DSA-65":
        return False
    if mode == "keyGen":
        return True
    return group.get("signatureInterface") == "external" and group.get("preHash") == "pure"


def main() -> None:
    source, commit, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    out: dict = {
        "source": {
            "repository": "https://github.com/usnistgov/ACVP-Server",
            "commit": commit,
            "paths": "gen-val/json-files/ML-DSA-{keyGen,sigGen,sigVer}-FIPS204/{prompt,expectedResults}.json",
            "sha256": {},
        }
    }
    for mode in ("keyGen", "sigGen", "sigVer"):
        files = {kind: source / f"{mode}-{kind}.json" for kind in ("prompt", "expectedResults")}
        for path in files.values():
            out["source"]["sha256"][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        expected = {
            (g["tgId"], t["tcId"]): t for g in load(files["expectedResults"])["testGroups"] for t in g["tests"]
        }
        cases = []
        for group in load(files["prompt"])["testGroups"]:
            if not wanted(mode, group):
                continue
            for test in group["tests"]:
                case = {"tgId": group["tgId"], **test, **expected[(group["tgId"], test["tcId"])]}
                if mode == "sigGen":
                    case["deterministic"] = group["deterministic"]
                cases.append(case)
        out[mode] = cases
        print(f"{mode}: {len(cases)} ML-DSA-65 cases")
    output.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
