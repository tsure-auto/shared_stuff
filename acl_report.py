#!/usr/bin/env python3
"""
acl_json_entry_counts.py

Scan a directory of normalized ACL JSON files and produce a CSV inventory
of rule counts per ACL per device.

Expected schema (minimum):
{
  "hostname": "device1",
  "normalized_ip_access_list": {
    "ACL_NAME": {
      "10": { ...rule... },
      "20": { ...rule... }
    }
  }
}

Counts:
- entry_count: number of ACE objects under the ACL (number of sequence keys)
- permit_count / deny_count: based on rule["action"]
- proto histogram fields: tcp/udp/ip/icmp/other/unknown

Usage:
  python acl_json_entry_counts.py --input-dir ./json_outputs --out acl_counts.csv
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def safe_int(s: str) -> Optional[int]:
    try:
        return int(s)
    except Exception:
        return None


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def is_rule_obj(x: Any) -> bool:
    return isinstance(x, dict) and ("action" in x or "protocol" in x or "src_type" in x or "dst_type" in x)


def main() -> int:
    ap = argparse.ArgumentParser(description="Count ACL entries per ACL across many normalized ACL JSON files.")
    ap.add_argument("--input-dir", required=True, help="Directory containing JSON files")
    ap.add_argument("--glob", default="*.json", help="Glob pattern (default: *.json)")
    ap.add_argument("--out", required=True, help="Output CSV path")
    args = ap.parse_args()

    in_dir = Path(args.input_dir).expanduser().resolve()
    if not in_dir.exists() or not in_dir.is_dir():
        raise SystemExit(f"ERROR: input-dir is not a directory: {in_dir}")

    files = sorted([p for p in in_dir.glob(args.glob) if p.is_file()])
    if not files:
        raise SystemExit(f"ERROR: no files matched {args.glob} in {in_dir}")

    out_path = Path(args.out).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rows: List[Dict[str, Any]] = []

    for fp in files:
        try:
            data = load_json(fp)
        except Exception as e:
            rows.append({
                "source_file": str(fp),
                "hostname": fp.stem,
                "acl_name": "",
                "entry_count": "",
                "permit_count": "",
                "deny_count": "",
                "tcp": "",
                "udp": "",
                "ip": "",
                "icmp": "",
                "other_proto": "",
                "unknown_proto": "",
                "error": f"json_load_error: {e}",
            })
            continue

        hostname = str(data.get("hostname") or fp.stem)

        acls = data.get("normalized_ip_access_list")
        if not isinstance(acls, dict):
            rows.append({
                "source_file": str(fp),
                "hostname": hostname,
                "acl_name": "",
                "entry_count": 0,
                "permit_count": 0,
                "deny_count": 0,
                "tcp": 0,
                "udp": 0,
                "ip": 0,
                "icmp": 0,
                "other_proto": 0,
                "unknown_proto": 0,
                "error": "missing_or_invalid_normalized_ip_access_list",
            })
            continue

        for acl_name, acl_rules in acls.items():
            if not isinstance(acl_rules, dict):
                rows.append({
                    "source_file": str(fp),
                    "hostname": hostname,
                    "acl_name": str(acl_name),
                    "entry_count": 0,
                    "permit_count": 0,
                    "deny_count": 0,
                    "tcp": 0,
                    "udp": 0,
                    "ip": 0,
                    "icmp": 0,
                    "other_proto": 0,
                    "unknown_proto": 0,
                    "error": "acl_rules_not_a_dict",
                })
                continue

            # only count real rule objects
            # sort keys numerically when possible (not required for counting, but helpful for debugging)
            keys = list(acl_rules.keys())
            sorted_keys = sorted(keys, key=lambda k: safe_int(str(k)) if safe_int(str(k)) is not None else 10**12)

            entry_count = 0
            permit_count = 0
            deny_count = 0
            proto_counts = {"tcp": 0, "udp": 0, "ip": 0, "icmp": 0, "other_proto": 0, "unknown_proto": 0}

            for k in sorted_keys:
                r = acl_rules.get(k)
                if not is_rule_obj(r):
                    continue

                entry_count += 1

                action = (r.get("action") or "").lower()
                if action == "permit":
                    permit_count += 1
                elif action == "deny":
                    deny_count += 1

                proto = (r.get("protocol") or "").lower()
                if proto in ("tcp", "udp", "ip", "icmp"):
                    proto_counts[proto] += 1
                elif proto == "":
                    proto_counts["unknown_proto"] += 1
                else:
                    proto_counts["other_proto"] += 1

            rows.append({
                "source_file": str(fp),
                "hostname": hostname,
                "acl_name": str(acl_name),
                "entry_count": entry_count,
                "permit_count": permit_count,
                "deny_count": deny_count,
                "tcp": proto_counts["tcp"],
                "udp": proto_counts["udp"],
                "ip": proto_counts["ip"],
                "icmp": proto_counts["icmp"],
                "other_proto": proto_counts["other_proto"],
                "unknown_proto": proto_counts["unknown_proto"],
                "error": "",
            })

    fieldnames = [
        "hostname",
        "acl_name",
        "entry_count",
        "permit_count",
        "deny_count",
        "tcp",
        "udp",
        "ip",
        "icmp",
        "other_proto",
        "unknown_proto",
        "source_file",
        "error",
    ]

    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    print(f"Wrote CSV: {out_path}")
    print(f"Files processed: {len(files)} | Rows: {len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
