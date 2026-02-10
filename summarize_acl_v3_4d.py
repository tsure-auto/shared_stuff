#!/usr/bin/env python3
"""
summarize_acl_v3_1.py

V3.1 = V3 logic + performance improvements for huge ACLs:
- Avoid deepcopy() (use shallow copies + copy-on-write on mutated fields)
- Sample logs per event type (full counts still in JSON report)
- Compact JSON output by default (pretty JSON optional)
- Progress bars:
    - Uses tqdm if installed
    - Falls back to periodic console progress prints

GT/LT logic still not merged/changed.
"""

from __future__ import annotations

import argparse
import json
import logging
import hashlib
import itertools
import sys
from dataclasses import dataclass, asdict
from collections import defaultdict
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network, IPv4Address, IPv4Network, collapse_addresses
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# -----------------------------
# Progress helpers (tqdm + fallback)
# -----------------------------

_TQDM_AVAILABLE = False
try:
    from tqdm import tqdm  # type: ignore
    _TQDM_AVAILABLE = True
except Exception:
    _TQDM_AVAILABLE = False


def iter_with_progress(
    iterable,
    total: int,
    desc: str,
    enabled: bool,
    fallback_every: int,
    force_fallback: bool,
):
    """
    Wrap an iterable with a progress indicator.

    - If force_fallback=True: ALWAYS print progress lines every `fallback_every` items.
      (Works even when tqdm can't render live, e.g. non-TTY, piped output, some IDE runners.)
    - Else if tqdm is available: use tqdm progress bar (written to stderr).
    - Else: fallback progress lines.

    enabled=False returns iterable unchanged.
    """
    if not enabled:
        return iterable

    def _fallback_gen():
        for idx, item in enumerate(iterable, start=1):
            if fallback_every and (idx == 1 or idx % fallback_every == 0 or idx == total):
                pct = (idx / total) * 100 if total else 0.0
                print(f"[progress] {desc}: {idx}/{total} ({pct:5.1f}%)", flush=True)
            yield item

    if force_fallback:
        return _fallback_gen()

    if _TQDM_AVAILABLE:
        # tqdm generally renders best to stderr; dynamic_ncols helps avoid weird wrapping.
        return tqdm(
            iterable,
            total=total,
            desc=desc,
            unit="rule",
            mininterval=0.2,
            dynamic_ncols=True,
            file=sys.stderr,
            leave=True,
        )

    return _fallback_gen()

def progress_note(logger: logging.Logger, msg: str):
    # Small helper to show a single-line "alive" note in stdout even if verbose is off
    print(msg, flush=True)
    logger.info(msg)


# -----------------------------
# Report structures
# -----------------------------

@dataclass
class AclReport:
    acl_name: str
    original_rule_count: int = 0
    final_rule_count: int = 0

    permits: int = 0
    denies: int = 0

    deduped_count: int = 0
    remark_differ_only_count: int = 0

    # adjacent merges
    ports_merged_eq_count: int = 0
    ranges_merged_count: int = 0

    # non-adjacent folding
    ports_folded_eq_groups: int = 0
    ports_folded_eq_rules_removed: int = 0

    redundant_flagged_by_ip_permit: int = 0
    redundant_flagged_by_broader_permit: int = 0

    cidr_pack_applied_groups: int = 0
    cidr_pack_skipped_groups: int = 0
    cidr_pack_applied_rules_removed: int = 0
    cidr_pack_applied_rules_added: int = 0

    # subnet exact-cover packing (APPLY)
    subnet_pack_applied_groups: int = 0
    subnet_pack_skipped_groups: int = 0
    subnet_pack_applied_rules_removed: int = 0
    subnet_pack_applied_rules_added: int = 0

    not_mergeable_count: int = 0
    not_mergeable_reasons: Dict[str, int] = None

    operator_histogram: Dict[str, int] = None

    def __post_init__(self):
        if self.not_mergeable_reasons is None:
            self.not_mergeable_reasons = {}
        if self.operator_histogram is None:
            self.operator_histogram = {}


# -----------------------------
# Logging sampler
# -----------------------------

class LogSampler:
    """
    Log the first N examples per event type; always count all occurrences.
    """
    def __init__(self, logger: logging.Logger, sample_limit: int):
        self.logger = logger
        self.sample_limit = max(0, int(sample_limit))
        self.counts: Dict[str, int] = {}

    def bump(self, event: str) -> int:
        self.counts[event] = self.counts.get(event, 0) + 1
        return self.counts[event]

    def info(self, event: str, msg: str, *args) -> None:
        n = self.bump(event)
        if self.sample_limit and n <= self.sample_limit:
            self.logger.info(msg, *args)

    def warning(self, event: str, msg: str, *args) -> None:
        n = self.bump(event)
        if self.sample_limit and n <= self.sample_limit:
            self.logger.warning(msg, *args)

    def debug(self, event: str, msg: str, *args) -> None:
        n = self.bump(event)
        if self.sample_limit and n <= self.sample_limit:
            self.logger.debug(msg, *args)


# -----------------------------
# Change tracking (low I/O)
# -----------------------------

@dataclass
class ChangeTracker:
    """Collect change counters + bounded samples; written once at end.

    Design goals:
      - low I/O: only written once at end
      - bounded memory: keep only N sample events per event type
      - audit-friendly: include before/after snapshots for sampled events
      - seq mapping: store internal rule ids (rid) so we can attach final new seq numbers after renumbering
    """
    max_samples_per_event: int = 200
    counts: Dict[str, int] = None
    samples: Dict[str, List[Dict[str, Any]]] = None

    def __post_init__(self):
        if self.counts is None:
            self.counts = defaultdict(int)
        if self.samples is None:
            self.samples = defaultdict(list)

    def record(self, event: str, payload: Dict[str, Any]) -> None:
        self.counts[event] += 1
        s = self.samples[event]
        if self.max_samples_per_event > 0 and len(s) < self.max_samples_per_event:
            s.append(payload)

    def enrich_acl(self, acl_name: str, rid_to_newseq: Dict[int, str]) -> None:
        """Attach final new sequence numbers to any sampled events for this ACL that reference rids."""
        for ev, items in self.samples.items():
            for it in items:
                if it.get("acl") != acl_name:
                    continue

                # single rid fields
                for k, v in list(it.items()):
                    if k.endswith("_rid") and isinstance(v, int):
                        it[k.replace("_rid", "_new_seq")] = rid_to_newseq.get(v)
                    if k.endswith("_rids") and isinstance(v, list):
                        it[k.replace("_rids", "_new_seqs")] = [rid_to_newseq.get(x) for x in v if isinstance(x, int)]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "totals": dict(self.counts),
            "samples": dict(self.samples),
        }


def rule_public(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Return only schema fields relevant to audit."""
    return {
        "action": rule.get("action"),
        "protocol": rule.get("protocol"),
        "src_type": rule.get("src_type"),
        "src_addr": rule.get("src_addr"),
        "src_mask": rule.get("src_mask"),
        "src_port_op": rule.get("src_port_op"),
        "src_ports": rule.get("src_ports"),
        "dst_type": rule.get("dst_type"),
        "dst_addr": rule.get("dst_addr"),
        "dst_mask": rule.get("dst_mask"),
        "dst_port_op": rule.get("dst_port_op"),
        "dst_ports": rule.get("dst_ports"),
        "remark": rule.get("remark"),
        "options": rule.get("options"),
    }


def rule_hash(rule: Dict[str, Any]) -> str:
    s = json.dumps(rule_public(rule), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# -----------------------------
# Helpers: ports / operators
# -----------------------------

def normalize_port_list(ports: Any) -> Optional[List[int]]:
    if ports is None:
        return None
    if isinstance(ports, list):
        return [int(str(p).strip()) for p in ports]
    return [int(str(ports).strip())]


def ports_to_sorted_unique_str(ports: List[int]) -> List[str]:
    return [str(p) for p in sorted(set(ports))]


def merge_ranges_if_possible(ranges: List[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    if not ranges:
        return None
    rs = [(min(a, b), max(a, b)) for a, b in ranges]
    rs.sort()
    cur_start, cur_end = rs[0]
    for a, b in rs[1:]:
        if a <= cur_end + 1:
            cur_end = max(cur_end, b)
        else:
            return None
    return (cur_start, cur_end)


# -----------------------------
# Helpers: wildcard <-> prefix
# -----------------------------

def wildcard_to_prefix(wildcard_mask: str) -> int:
    parts = [int(x) for x in wildcard_mask.split(".")]
    if len(parts) != 4:
        raise ValueError(f"Invalid wildcard mask: {wildcard_mask}")
    subnet = [255 - p for p in parts]
    bits = "".join(f"{p:08b}" for p in subnet)
    if "01" in bits:
        raise ValueError(f"Non-contiguous subnet mask derived from wildcard: {wildcard_mask}")
    return bits.count("1")


def prefix_to_wildcard(prefix: int) -> str:
    if prefix < 0 or prefix > 32:
        raise ValueError(f"Invalid prefix: {prefix}")
    bits = ("1" * prefix) + ("0" * (32 - prefix))
    octets = [int(bits[i:i+8], 2) for i in range(0, 32, 8)]
    w = [255 - o for o in octets]
    return ".".join(str(x) for x in w)


def rule_side_network(rule: Dict[str, Any], side: str) -> Optional[IPv4Network]:
    st = rule.get(f"{side}_type")
    addr = rule.get(f"{side}_addr")
    mask = rule.get(f"{side}_mask")

    if st == "any":
        return ip_network("0.0.0.0/0")
    if st == "host" and addr:
        return ip_network(f"{addr}/32")
    if st == "subnet" and addr and mask:
        try:
            prefix = wildcard_to_prefix(mask)
            return ip_network(f"{addr}/{prefix}", strict=False)
        except ValueError:
            return None
    return None


def convert_network_to_schema(net: IPv4Network, side: str) -> Dict[str, Any]:
    if net.prefixlen == 32:
        return {
            f"{side}_type": "host",
            f"{side}_addr": str(net.network_address),
            f"{side}_mask": None,
        }
    return {
        f"{side}_type": "subnet",
        f"{side}_addr": str(net.network_address),
        f"{side}_mask": prefix_to_wildcard(net.prefixlen),
    }


# -----------------------------
# Dedupe signature (ignore seq/remark/options)
# -----------------------------

def semantic_key_for_dedupe(rule: Dict[str, Any]) -> Tuple:
    return (
        rule.get("action"),
        rule.get("protocol"),
        rule.get("src_type"),
        rule.get("src_addr"),
        rule.get("src_mask"),
        rule.get("src_port_op"),
        tuple(rule.get("src_ports") or ()) if isinstance(rule.get("src_ports"), list) else rule.get("src_ports"),
        rule.get("dst_type"),
        rule.get("dst_addr"),
        rule.get("dst_mask"),
        rule.get("dst_port_op"),
        tuple(rule.get("dst_ports") or ()) if isinstance(rule.get("dst_ports"), list) else rule.get("dst_ports"),
    )


# -----------------------------
# Merge eq / range (adjacent only)
# -----------------------------

def rules_equal_except(rule_a: Dict[str, Any], rule_b: Dict[str, Any], ignore_fields: List[str]) -> bool:
    a = dict(rule_a)
    b = dict(rule_b)
    for f in ignore_fields:
        a[f] = None
        b[f] = None
    return semantic_key_for_dedupe(a) == semantic_key_for_dedupe(b)


def can_merge_eq_ports(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    if a.get("dst_port_op") != "eq" or b.get("dst_port_op") != "eq":
        return False
    return rules_equal_except(a, b, ["dst_ports", "remark", "seq", "options"])


def merge_eq_ports(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(a)
    pa = normalize_port_list(a.get("dst_ports")) or []
    pb = normalize_port_list(b.get("dst_ports")) or []
    merged["dst_ports"] = ports_to_sorted_unique_str(pa + pb)
    return merged


def can_merge_range(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    if a.get("dst_port_op") != "range" or b.get("dst_port_op") != "range":
        return False
    return rules_equal_except(a, b, ["dst_ports", "remark", "seq", "options"])


def merge_range(a: Dict[str, Any], b: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    pa = normalize_port_list(a.get("dst_ports")) or []
    pb = normalize_port_list(b.get("dst_ports")) or []
    if len(pa) != 2 or len(pb) != 2:
        return None
    merged = merge_ranges_if_possible([(pa[0], pa[1]), (pb[0], pb[1])])
    if merged is None:
        return None
    out = dict(a)
    out["dst_ports"] = [str(merged[0]), str(merged[1])]
    return out


def mismatch_reason(a: Dict[str, Any], b: Dict[str, Any]) -> str:
    fields = [
        "action", "protocol",
        "src_type", "src_addr", "src_mask", "src_port_op", "src_ports",
        "dst_type", "dst_addr", "dst_mask", "dst_port_op"
    ]
    diffs = [f for f in fields if a.get(f) != b.get(f)]
    if diffs:
        return "fields_mismatch:" + ",".join(diffs[:6]) + ("" if len(diffs) <= 6 else f",+{len(diffs)-6}_more")
    return "unknown_mismatch"


# -----------------------------
# Redundancy checks (flag only)
# -----------------------------

def ports_semantics(rule: Dict[str, Any]) -> Tuple[str, Optional[Any]]:
    op = rule.get("dst_port_op")
    ports = normalize_port_list(rule.get("dst_ports"))
    if op is None:
        return ("null", None)
    if op == "eq":
        return ("eq", set(ports or []))
    if op == "range":
        if ports and len(ports) == 2:
            lo, hi = min(ports[0], ports[1]), max(ports[0], ports[1])
            return ("range", (lo, hi))
        return ("range", None)
    return (str(op), None)  # gt/lt etc. pass-through


def ports_covered(rule: Dict[str, Any], earlier: Dict[str, Any]) -> bool:
    rop, rval = ports_semantics(rule)
    eop, evalv = ports_semantics(earlier)

    if eop == "null":
        return rop == "null"
    if rop == "null":
        return False

    if eop == "eq" and rop == "eq":
        return isinstance(evalv, set) and isinstance(rval, set) and rval.issubset(evalv)

    if eop == "range" and rop == "range":
        if isinstance(evalv, tuple) and isinstance(rval, tuple):
            return evalv[0] <= rval[0] and evalv[1] >= rval[1]
        return False

    return False


def rule_covered_by_earlier_permit(rule: Dict[str, Any], earlier: Dict[str, Any]) -> bool:
    if earlier.get("action") != "permit":
        return False
    if earlier.get("protocol") == "ip":
        return False
    if rule.get("protocol") != earlier.get("protocol"):
        return False

    rs = rule_side_network(rule, "src")
    rd = rule_side_network(rule, "dst")
    es = rule_side_network(earlier, "src")
    ed = rule_side_network(earlier, "dst")
    if None in (rs, rd, es, ed):
        return False

    if not (rs.subnet_of(es) and rd.subnet_of(ed)):
        return False

    return ports_covered(rule, earlier)


def rule_covered_by_ip_permit(rule: Dict[str, Any], earlier: Dict[str, Any]) -> bool:
    if earlier.get("action") != "permit" or earlier.get("protocol") != "ip":
        return False
    rs = rule_side_network(rule, "src")
    rd = rule_side_network(rule, "dst")
    es = rule_side_network(earlier, "src")
    ed = rule_side_network(earlier, "dst")
    if None in (rs, rd, es, ed):
        return False
    return rs.subnet_of(es) and rd.subnet_of(ed)


# -----------------------------
# Exact-cover CIDR packing (APPLY)
# -----------------------------

def exact_cidr_cover_for_hosts(hosts: List[IPv4Address]) -> List[IPv4Network]:
    nets = [ip_network(f"{h}/32") for h in hosts]
    return list(collapse_addresses(nets))


def packing_group_key(rule: Dict[str, Any], vary_side: str) -> Tuple:
    if vary_side == "src":
        return (
            rule.get("action"), rule.get("protocol"),
            rule.get("dst_type"), rule.get("dst_addr"), rule.get("dst_mask"),
            rule.get("dst_port_op"), tuple(rule.get("dst_ports") or ()),
            rule.get("src_type"), rule.get("src_mask"),
            rule.get("src_port_op"), tuple(rule.get("src_ports") or ()),
        )
    return (
        rule.get("action"), rule.get("protocol"),
        rule.get("src_type"), rule.get("src_addr"), rule.get("src_mask"),
        rule.get("src_port_op"), tuple(rule.get("src_ports") or ()),
        rule.get("dst_type"), rule.get("dst_mask"),
        rule.get("dst_port_op"), tuple(rule.get("dst_ports") or ()),
    )


def apply_exact_host_packing_contiguous(
    rules: List[Dict[str, Any]],
    acl_name: str,
    logger: logging.Logger,
    logs: LogSampler,
    rep: AclReport,
    tracker: ChangeTracker,
    alloc_rid,
    vary_side: str,
    min_hosts: int = 4,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    i = 0
    # No tqdm here by default; dedupe/fold are the big ones.
    while i < len(rules):
        r = rules[i]

        if r.get("action") != "permit" or r.get("action") == "deny":
            out.append(r)
            i += 1
            continue

        if r.get(f"{vary_side}_type") != "host":
            out.append(r)
            i += 1
            continue

        key = packing_group_key(r, vary_side)

        run: List[Dict[str, Any]] = [r]
        j = i + 1
        while j < len(rules):
            nxt = rules[j]
            if nxt.get("action") == "deny" or nxt.get("action") != "permit":
                break
            if nxt.get(f"{vary_side}_type") != "host":
                break
            if packing_group_key(nxt, vary_side) != key:
                break
            run.append(nxt)
            j += 1

        if len(run) < min_hosts:
            out.extend(run)
            i = j
            continue

        host_ips = [ip_address(x[f"{vary_side}_addr"]) for x in run if x.get(f"{vary_side}_addr")]
        cidrs = exact_cidr_cover_for_hosts(host_ips)
        cidrs = [c for c in cidrs if isinstance(c, IPv4Network)]
        # Sort once up-front so reporting can safely reference the sorted list.
        cidrs_sorted = sorted(cidrs, key=lambda n: (int(n.network_address), n.prefixlen))

        if len(cidrs) >= len(run):
            rep.cidr_pack_skipped_groups += 1
            tracker.record("CIDR_PACK_SKIPPED", {
                "acl": acl_name,
                "side": vary_side,
                "run_rule_rids": [x.get("_rid") for x in run],
                "run_orig_seqs": sorted({s for x in run for s in (x.get("_orig_seq_keys") or [])}),
                "before_rules": [rule_public(x) for x in run[:10]],
                "before_rules_truncated": (len(run) > 10),
                "hosts": len(run),
                "cidrs": len(cidrs),
                "cidrs_list": [str(c) for c in cidrs],
            })
            logs.info(
                "CIDR_PACK_SKIPPED",
                "CIDR_PACK_SKIPPED_NOT_WORTH_IT acl=%s side=%s hosts=%d cidrs=%d",
                acl_name, vary_side, len(run), len(cidrs)
            )
            out.extend(run)
            i = j
            continue

        rep.cidr_pack_applied_groups += 1
        rep.cidr_pack_applied_rules_removed += len(run)
        rep.cidr_pack_applied_rules_added += len(cidrs)

        tracker.record("CIDR_PACK_APPLIED", {
            "acl": acl_name,
            "side": vary_side,
            "removed_rule_rids": [x.get("_rid") for x in run],
            "removed_orig_seqs": sorted({s for x in run for s in (x.get("_orig_seq_keys") or [])}),
            "before_rules": [rule_public(x) for x in run[:10]],
            "before_rules_truncated": (len(run) > 10),
            "hosts_removed": len(run),
            "cidrs_added": len(cidrs_sorted),
            "cidrs_list": [str(c) for c in cidrs_sorted],
        })

        logs.warning(
            "CIDR_PACK_APPLIED",
            "CIDR_PACK_APPLIED acl=%s side=%s hosts=%d cidrs=%d cidrs_list=%s",
            acl_name, vary_side, len(run), len(cidrs), [str(c) for c in cidrs]
        )

        template = run[0]

        combined_orig_seqs = sorted({s for x in run for s in (x.get("_orig_seq_keys") or [])})
        added_rids: List[int] = []
        after_rules_sample: List[Dict[str, Any]] = []

        for net in cidrs_sorted:
            nr = dict(template)
            nr.update(convert_network_to_schema(net, vary_side))
            nr["_rid"] = alloc_rid()
            nr["_orig_seq_key"] = template.get("_orig_seq_key")
            nr["_orig_seq_keys"] = combined_orig_seqs
            added_rids.append(nr["_rid"])
            if len(after_rules_sample) < 10:
                after_rules_sample.append(rule_public(nr))
            base_remark = (template.get("remark") or "").strip()
            nr["remark"] = (base_remark + " | summarized_exact_cidr_cover").strip(" |")
            out.append(nr)

        # Add a separate sampled event to show the after-rules for this group (bounded)
        tracker.record("CIDR_PACK_AFTER", {
            "acl": acl_name,
            "side": vary_side,
            "added_rule_rids": added_rids,
            "after_rules": after_rules_sample,
            "after_rules_truncated": (len(cidrs_sorted) > 10),
            "source_group_removed_orig_seqs": combined_orig_seqs,
        })

        i = j

    return out


def apply_exact_subnet_packing_contiguous(
    rules: List[Dict[str, Any]],
    acl_name: str,
    logger: logging.Logger,
    logs: LogSampler,
    rep: AclReport,
    tracker: ChangeTracker,
    alloc_rid,
    vary_side: str,
    min_subnets: int = 2,
) -> List[Dict[str, Any]]:
    """
    Exact-cover packing for contiguous runs of *subnet* rules (not hosts).

    Safety:
      - Uses collapse_addresses() over the set of IPv4Network values, which represents the exact union.
      - Only applies when the collapsed list is strictly shorter than the original run (reduces rule count).
      - Does not cross deny boundaries or semantic mismatches (contiguous-run constraint).

    This complements host packing: if host packing creates /30s, this can optionally merge adjacent /30s into /29, etc.
    """
    out: List[Dict[str, Any]] = []
    i = 0

    while i < len(rules):
        r = rules[i]

        # Only consider permit rules; never cross deny
        if r.get("action") == "deny" or r.get("action") != "permit":
            out.append(r)
            i += 1
            continue

        if r.get(f"{vary_side}_type") != "subnet":
            out.append(r)
            i += 1
            continue

        key = packing_group_key(r, vary_side)

        run: List[Dict[str, Any]] = [r]
        j = i + 1
        while j < len(rules):
            nxt = rules[j]
            if nxt.get("action") == "deny" or nxt.get("action") != "permit":
                break
            if nxt.get(f"{vary_side}_type") != "subnet":
                break
            if packing_group_key(nxt, vary_side) != key:
                break
            run.append(nxt)
            j += 1

        if len(run) < min_subnets:
            out.extend(run)
            i = j
            continue

        nets: List[IPv4Network] = []
        bad = False
        for x in run:
            n = rule_side_network(x, vary_side)
            if n is None:
                bad = True
                break
            nets.append(n)

        if bad or not nets:
            out.extend(run)
            i = j
            continue

        collapsed = list(collapse_addresses(nets))
        collapsed = [c for c in collapsed if isinstance(c, IPv4Network)]

        if len(collapsed) >= len(run):
            rep.subnet_pack_skipped_groups += 1
            tracker.record("SUBNET_PACK_SKIPPED", {
                "acl": acl_name,
                "side": vary_side,
                "subnets": len(run),
                "collapsed": len(collapsed),
            })
            logs.info(
                "SUBNET_PACK_SKIPPED",
                "SUBNET_PACK_SKIPPED_NOT_WORTH_IT acl=%s side=%s subnets=%d collapsed=%d",
                acl_name, vary_side, len(run), len(collapsed)
            )
            out.extend(run)
            i = j
            continue

        rep.subnet_pack_applied_groups += 1
        rep.subnet_pack_applied_rules_removed += len(run)
        rep.subnet_pack_applied_rules_added += len(collapsed)

        # Sample: avoid dumping huge lists unless sampling allows it
        tracker.record("SUBNET_PACK_APPLIED", {
            "acl": acl_name,
            "side": vary_side,
            "subnets_removed": len(run),
            "collapsed_added": len(collapsed),
            "collapsed": [str(c) for c in collapsed],
        })

        logs.warning(
            "SUBNET_PACK_APPLIED",
            "SUBNET_PACK_APPLIED acl=%s side=%s subnets=%d collapsed=%d collapsed_list=%s",
            acl_name, vary_side, len(run), len(collapsed), [str(c) for c in collapsed]
        )

        template = run[0]
        collapsed_sorted = sorted(collapsed, key=lambda n: (int(n.network_address), n.prefixlen))

        combined_orig_seqs = sorted({s for x in run for s in (x.get("_orig_seq_keys") or [])})
        added_rids: List[int] = []
        after_rules_sample: List[Dict[str, Any]] = []

        for net in collapsed_sorted:
            nr = dict(template)
            nr.update(convert_network_to_schema(net, vary_side))
            nr["_rid"] = alloc_rid()
            nr["_orig_seq_key"] = template.get("_orig_seq_key")
            nr["_orig_seq_keys"] = combined_orig_seqs
            added_rids.append(nr["_rid"])
            if len(after_rules_sample) < 10:
                after_rules_sample.append(rule_public(nr))
            base_remark = (template.get("remark") or "").strip()
            nr["remark"] = (base_remark + " | summarized_exact_subnet_cover").strip(" |")
            out.append(nr)

        tracker.record("SUBNET_PACK_AFTER", {
            "acl": acl_name,
            "side": vary_side,
            "added_rule_rids": added_rids,
            "after_rules": after_rules_sample,
            "after_rules_truncated": (len(collapsed_sorted) > 10),
            "source_group_removed_orig_seqs": combined_orig_seqs,
        })

        i = j

    return out



# -----------------------------
# Non-adjacent folding in permit windows (O(n))
# -----------------------------

def fold_key_eq(rule: Dict[str, Any]) -> Optional[Tuple]:
    if rule.get("action") != "permit":
        return None
    if rule.get("dst_port_op") != "eq":
        return None
    return (
        rule.get("action"),
        rule.get("protocol"),
        rule.get("src_type"), rule.get("src_addr"), rule.get("src_mask"),
        rule.get("src_port_op"), tuple(rule.get("src_ports") or ()),
        rule.get("dst_type"), rule.get("dst_addr"), rule.get("dst_mask"),
        rule.get("dst_port_op"),
    )


def fold_eq_ports_within_permit_windows(
    rules: List[Dict[str, Any]],
    acl_name: str,
    logs: LogSampler,
    rep: AclReport,
    tracker: ChangeTracker,
    show_progress: bool,
    fallback_every: int,
    force_fallback: bool,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    window: List[Dict[str, Any]] = []
    seen: Dict[Tuple, Dict[str, Any]] = {}
    seen_ports: Dict[Tuple, set] = {}

    def flush_window():
        for r in window:
            if r.get("_fold_drop"):
                continue
            out.append(r)
        window.clear()
        seen.clear()
        seen_ports.clear()

    wrapped = iter_with_progress(
        rules,
        total=len(rules),
        desc=f"{acl_name}: fold",
        enabled=show_progress,
        fallback_every=fallback_every,
        force_fallback=force_fallback,
    )

    for r in wrapped:
        if r.get("action") == "deny":
            flush_window()
            out.append(r)
            continue

        fk = fold_key_eq(r)
        if fk is None:
            window.append(r)
            continue

        ports = normalize_port_list(r.get("dst_ports")) or []
        if fk not in seen:
            canon = r
            seen[fk] = canon
            seen_ports[fk] = set(ports)
            window.append(canon)
            continue

        canon = seen[fk]
        seen_ports[fk].update(ports)

        r["_fold_drop"] = True
        window.append(r)

        rep.ports_folded_eq_rules_removed += 1
        rep.ports_folded_eq_groups += 1

        # Track: dropped rule + canonical mutation
        tracker.record("FOLD_DROP", {
            "acl": acl_name,
            "dropped_seq": r.get("_orig_seq_key"),
            "canon_seq": canon.get("_orig_seq_key"),
        })

        canon["dst_ports"] = ports_to_sorted_unique_str(list(seen_ports[fk]))
        tracker.record("FOLD_PORTS_WINDOW", {
            "acl": acl_name,
            "canon_seq": canon.get("_orig_seq_key"),
            "dropped_seq": r.get("_orig_seq_key"),
            "ports_after": canon.get("dst_ports"),
        })

        logs.info(
            "PORTS_FOLDED_EQ",
            "PORTS_FOLDED_EQ acl=%s ports_now=%s",
            acl_name, canon["dst_ports"]
        )

    flush_window()
    return out


# -----------------------------
# Core summarization logic
# -----------------------------

def summarize_acl_rules(
    acl_name: str,
    rules_in_order: List[Tuple[str, Dict[str, Any]]],
    logger: logging.Logger,
    logs: LogSampler,
    tracker: ChangeTracker,
    show_progress: bool,
    fallback_every: int,
    force_fallback: bool,
) -> Tuple[List[Dict[str, Any]], AclReport]:
    rep = AclReport(acl_name=acl_name)
    rep.original_rule_count = len(rules_in_order)

    for _, r in rules_in_order:
        if r.get("action") == "permit":
            rep.permits += 1
        elif r.get("action") == "deny":
            rep.denies += 1
        op = r.get("dst_port_op") or "null"
        rep.operator_histogram[op] = rep.operator_histogram.get(op, 0) + 1

    logger.info(
        "INPUT_STATS acl=%s total=%d permits=%d denies=%d operators=%s",
        acl_name, rep.original_rule_count, rep.permits, rep.denies, rep.operator_histogram
    )

    # Step 1: Deduplicate (ignore seq/remark)
    seen: Dict[Tuple, Dict[str, Any]] = {}
    kept: List[Tuple[str, Dict[str, Any]]] = []

    # ACL-local rule id allocator (used for mapping to new sequence numbers after renumbering)
    rid_counter = itertools.count(1)
    def alloc_rid() -> int:
        return next(rid_counter)

    wrapped = iter_with_progress(
        rules_in_order,
        total=len(rules_in_order),
        desc=f"{acl_name}: dedupe",
        enabled=show_progress,
        fallback_every=fallback_every,
        force_fallback=force_fallback,
    )

    for seq_key, rule in wrapped:
        k = semantic_key_for_dedupe(rule)
        if k in seen:
            prev = seen[k]

            # track that this canonical rule now represents multiple original seqs
            prev.setdefault("_orig_seq_keys", [prev.get("_orig_seq_key")]).append(seq_key)

            if (prev.get("remark") or "") != (rule.get("remark") or ""):
                rep.remark_differ_only_count += 1
                tracker.record("REMARK_DIFFER_ONLY", {
                    "acl": acl_name,
                    "kept_rid": prev.get("_rid"),
                    "kept_orig_seqs": list(prev.get("_orig_seq_keys") or []),
                    "dropped_seq": seq_key,
                    "kept_rule": rule_public(prev),
                    "dropped_rule": rule_public(rule),
                })
                logs.warning(
                    "REMARK_DIFFER_ONLY",
                    "REMARK_DIFFER_ONLY acl=%s kept_seq=%s dropped_seq=%s",
                    acl_name, prev.get("_orig_seq_key"), seq_key
                )

            rep.deduped_count += 1
            tracker.record("DEDUP_DROP", {
                "acl": acl_name,
                "kept_rid": prev.get("_rid"),
                "kept_orig_seqs": list(prev.get("_orig_seq_keys") or []),
                "dropped_seq": seq_key,
                "kept_rule_hash": rule_hash(prev),
                "dropped_rule_hash": rule_hash(rule),
            })
            logs.info("DEDUPED_RULE", "DEDUPED_RULE acl=%s dropped_seq=%s kept_seq=%s", acl_name, seq_key, prev.get("_orig_seq_key"))
            continue

        rr = dict(rule)  # shallow copy
        rr["_rid"] = next(rid_counter)
        rr["_orig_seq_key"] = seq_key
        rr["_orig_seq_keys"] = [seq_key]
        seen[k] = rr
        kept.append((seq_key, rr))


# Step 2: Flag redundancy covered by earlier permit ip (no delete)
    ip_permits_seen: List[Dict[str, Any]] = []
    for seq_key, rule in kept:
        if rule.get("action") == "permit" and rule.get("protocol") == "ip":
            ip_permits_seen.append(rule)
            continue
        if not ip_permits_seen:
            continue
        for earlier in ip_permits_seen:
            if rule_covered_by_ip_permit(rule, earlier):
                rep.redundant_flagged_by_ip_permit += 1
                tracker.record("FLAG_REDUNDANT_BY_IP_PERMIT", {
                    "acl": acl_name,
                    "flagged_rid": rule.get("_rid"),
                    "covering_rid": earlier.get("_rid"),
                    "flagged_orig_seqs": list(rule.get("_orig_seq_keys") or []),
                    "covering_orig_seqs": list(earlier.get("_orig_seq_keys") or []),
                    "flagged_rule": rule_public(rule),
                    "covering_rule": rule_public(earlier),
                })
                logs.warning(
                    "REDUNDANT_COVERED_BY_IP_PERMIT",
                    "REDUNDANT_COVERED_BY_IP_PERMIT acl=%s seq=%s covered_by_seq=%s",
                    acl_name, seq_key, earlier.get("_orig_seq_key")
                )
                break

    # Step 3: Adjacent merges (no reordering, stop at deny boundaries)
    merged_out: List[Dict[str, Any]] = []
    i = 0
    while i < len(kept):
        seq_key, rule = kept[i]

        if rule.get("action") == "deny":
            merged_out.append(rule)
            i += 1
            continue

        current = rule
        base_seq = seq_key
        j = i + 1
        while j < len(kept):
            next_seq, nxt = kept[j]
            if nxt.get("action") == "deny":
                break

            if current.get("dst_port_op") == "eq" and nxt.get("dst_port_op") == "eq" and can_merge_eq_ports(current, nxt):
                before = normalize_port_list(current.get("dst_ports")) or []
                current = merge_eq_ports(current, nxt)
                current.setdefault("_orig_seq_keys", [current.get("_orig_seq_key")]).extend(list(nxt.get("_orig_seq_keys") or [next_seq]))
                after = normalize_port_list(current.get("dst_ports")) or []
                rep.ports_merged_eq_count += 1
                tracker.record("MERGE_PORTS_ADJACENT", {
                    "acl": acl_name,
                    "canon_rid": current.get("_rid"),
                    "merged_rid": nxt.get("_rid"),
                    "canon_orig_seqs": list(current.get("_orig_seq_keys") or []),
                    "merged_orig_seqs": list(nxt.get("_orig_seq_keys") or []),
                    "ports_before": ports_to_sorted_unique_str(before),
                    "ports_after": ports_to_sorted_unique_str(after),
                    "canon_rule_after": rule_public(current),
                })
                logs.info(
                    "PORTS_MERGED_EQ",
                    "PORTS_MERGED_EQ acl=%s base_seq=%s merged_seq=%s ports_before=%s ports_after=%s",
                    acl_name, base_seq, next_seq,
                    ports_to_sorted_unique_str(before),
                    ports_to_sorted_unique_str(after)
                )
                j += 1
                continue

            if current.get("dst_port_op") == "range" and nxt.get("dst_port_op") == "range" and can_merge_range(current, nxt):
                candidate = merge_range(current, nxt)
                if candidate is not None:
                    rep.ranges_merged_count += 1
                    tracker.record("MERGE_RANGE_ADJACENT", {
                        "acl": acl_name,
                        "canon_rid": current.get("_rid"),
                        "merged_rid": nxt.get("_rid"),
                        "canon_orig_seqs": list(current.get("_orig_seq_keys") or []),
                        "merged_orig_seqs": list(nxt.get("_orig_seq_keys") or []),
                        "range_after": candidate.get("dst_ports"),
                        "canon_rule_after": rule_public(candidate),
                    })
                    logs.info(
                        "RANGE_MERGED",
                        "RANGE_MERGED acl=%s base_seq=%s merged_seq=%s new_range=%s",
                        acl_name, base_seq, next_seq, candidate.get("dst_ports")
                    )
                    current = candidate
                    current.setdefault("_orig_seq_keys", [current.get("_orig_seq_key")]).extend(list(nxt.get("_orig_seq_keys") or [next_seq]))
                    j += 1
                    continue
                rep.not_mergeable_count += 1
                rep.not_mergeable_reasons["range_not_contiguous"] = rep.not_mergeable_reasons.get("range_not_contiguous", 0) + 1
                logs.info(
                    "CANNOT_MERGE",
                    "CANNOT_MERGE acl=%s reason=range_not_contiguous seq_a=%s seq_b=%s",
                    acl_name, base_seq, next_seq
                )
                break

            rep.not_mergeable_count += 1
            reason = mismatch_reason(current, nxt)
            rep.not_mergeable_reasons[reason] = rep.not_mergeable_reasons.get(reason, 0) + 1
            logs.info("CANNOT_MERGE", "CANNOT_MERGE acl=%s reason=%s seq_a=%s seq_b=%s", acl_name, reason, base_seq, next_seq)
            break

        merged_out.append(current)
        i = j if j > i + 1 else i + 1

    # Step 3.5 (V3): Non-adjacent folding in permit windows
    merged_out = fold_eq_ports_within_permit_windows(
        merged_out,
        acl_name,
        logs,
        rep,
        tracker,
        show_progress=show_progress,
        fallback_every=fallback_every,
        force_fallback=force_fallback,
    )

    # Step 4: Exact CIDR packing (src then dst)
    merged_out = apply_exact_host_packing_contiguous(merged_out, acl_name, logger, logs, rep, tracker, alloc_rid, vary_side="src", min_hosts=4)
    merged_out = apply_exact_host_packing_contiguous(merged_out, acl_name, logger, logs, rep, tracker, alloc_rid, vary_side="dst", min_hosts=4)
    merged_out = apply_exact_subnet_packing_contiguous(merged_out, acl_name, logger, logs, rep, tracker, alloc_rid, vary_side="src", min_subnets=2)
    merged_out = apply_exact_subnet_packing_contiguous(merged_out, acl_name, logger, logs, rep, tracker, alloc_rid, vary_side="dst", min_subnets=2)

    # Step 5: Flag redundancy covered by earlier broader permit (not ip) (no delete)
    earlier_permits: List[Dict[str, Any]] = []
    for r in merged_out:
        if r.get("action") == "permit":
            for e in earlier_permits:
                if rule_covered_by_earlier_permit(r, e):
                    rep.redundant_flagged_by_broader_permit += 1
                    tracker.record("FLAG_REDUNDANT_BY_BROADER_PERMIT", {
                    "acl": acl_name,
                    "flagged_rid": r.get("_rid"),
                    "covering_rid": e.get("_rid"),
                    "flagged_orig_seqs": list(r.get("_orig_seq_keys") or []),
                    "covering_orig_seqs": list(e.get("_orig_seq_keys") or []),
                    "flagged_rule": rule_public(r),
                    "covering_rule": rule_public(e),
                })
                    logs.warning(
                        "REDUNDANT_COVERED_BY_BROADER_PERMIT",
                        "REDUNDANT_COVERED_BY_BROADER_PERMIT acl=%s rule_remark=%r covered_by_remark=%r",
                        acl_name, r.get("remark"), e.get("remark")
                    )
                    break
            earlier_permits.append(r)

    # Cleanup internal keys
    for r in merged_out:
        r.pop("_fold_drop", None)

    rep.final_rule_count = len(merged_out)

    logger.info(
        "OUTPUT_STATS acl=%s original=%d final=%d deduped=%d remark_differ=%d merged_eq=%d merged_range=%d "
        "fold_removed=%d redundant_ip_flagged=%d redundant_broader_flagged=%d cidr_applied_groups=%d cidr_removed=%d cidr_added=%d subnet_applied_groups=%d subnet_removed=%d subnet_added=%d not_mergeable=%d",
        acl_name,
        rep.original_rule_count,
        rep.final_rule_count,
        rep.deduped_count,
        rep.remark_differ_only_count,
        rep.ports_merged_eq_count,
        rep.ranges_merged_count,
        rep.ports_folded_eq_rules_removed,
        rep.redundant_flagged_by_ip_permit,
        rep.redundant_flagged_by_broader_permit,
        rep.cidr_pack_applied_groups,
        rep.cidr_pack_applied_rules_removed,
        rep.cidr_pack_applied_rules_added,
        rep.subnet_pack_applied_groups,
        rep.subnet_pack_applied_rules_removed,
        rep.subnet_pack_applied_rules_added,
        rep.not_mergeable_count,
    )

    return merged_out, rep


def renumber_rules(rules: List[Dict[str, Any]], start: int = 10, step: int = 10) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    n = start
    for r in rules:
        out[str(n)] = r
        n += step
    return out


# -----------------------------
# IO / CLI
# -----------------------------

def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Dict[str, Any], pretty: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        if pretty:
            json.dump(data, f, indent=2, sort_keys=False)
        else:
            json.dump(data, f, separators=(",", ":"), sort_keys=False)


def setup_logger(log_path: Path, verbose: bool = False) -> logging.Logger:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(f"acl_summarizer_{log_path.stem}")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.INFO if verbose else logging.WARNING)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    return logger


def safe_int(k: str) -> int:
    try:
        return int(k)
    except Exception:
        return 10**12


def main() -> int:
    ap = argparse.ArgumentParser(description="Summarize Cisco normalized ACL JSON (V3.1 fast + progress bars).")
    ap.add_argument("--input", required=True, help="Path to input JSON file")
    ap.add_argument("--outdir", default="out", help="Output directory")
    ap.add_argument("--verbose", action="store_true", help="Also print INFO logs to stdout")
    ap.add_argument("--log-sample", type=int, default=50, help="Log first N examples per event type (default 50). Use 0 for counters-only.")
    ap.add_argument("--pretty-json", action="store_true", help="Write indented JSON outputs (slower for huge files).")
    ap.add_argument("--max-event-samples", type=int, default=200,
                    help="Max sample change events stored per event type in the changes report. Use 0 for counts-only.")

    # Progress controls
    ap.add_argument("--progress", action="store_true",
                    help="Show progress indicators (tqdm if available; otherwise prints progress lines).")
    ap.add_argument("--force-fallback-progress", action="store_true",
                    help="Always print progress lines (never use tqdm). Useful when tqdm only refreshes at the end.")
    ap.add_argument("--progress-phase-every", type=int, default=2000,
                    help="Print progress every N rules per phase when using fallback progress (default 2000).")

    # Back-compat alias (older flag name)
    ap.add_argument("--progress-fallback-every", type=int, default=None,
                    help=argparse.SUPPRESS)

    args = ap.parse_args()
    # Effective fallback interval (supports the older --progress-fallback-every flag)
    effective_progress_every = args.progress_phase_every if args.progress_fallback_every is None else args.progress_fallback_every


    inp_path = Path(args.input).expanduser().resolve()
    outdir = Path(args.outdir).expanduser().resolve()

    data = load_json(inp_path)
    hostname = str(data.get("hostname") or inp_path.stem)

    log_path = outdir / f"summarize_{hostname}.log"
    logger = setup_logger(log_path, verbose=args.verbose)
    logs = LogSampler(logger, sample_limit=args.log_sample)
    tracker = ChangeTracker(max_samples_per_event=args.max_event_samples)

    t0 = datetime.now(timezone.utc)

    if "normalized_ip_access_list" not in data or not isinstance(data["normalized_ip_access_list"], dict):
        logger.error("Input missing normalized_ip_access_list dict")
        return 2

    overall_report: Dict[str, Any] = {
        "hostname": hostname,
        "input_file": str(inp_path),
        "output_dir": str(outdir),
        "started_utc": t0.isoformat(),
        "settings": {
            "log_sample": args.log_sample,
            "pretty_json": args.pretty_json,
            "progress": args.progress,
            "force_fallback_progress": args.force_fallback_progress,
            "progress_every": effective_progress_every,
            "tqdm_available": _TQDM_AVAILABLE,
        },
        "acls": {},
        "totals": {
            "original_rules": 0,
            "final_rules": 0,
            "deduped": 0,
            "remark_differ_only": 0,
            "merged_eq": 0,
            "merged_range": 0,
            "fold_removed": 0,
            "redundant_flagged_by_ip_permit": 0,
            "redundant_flagged_by_broader_permit": 0,
            "cidr_pack_applied_groups": 0,
            "cidr_pack_skipped_groups": 0,
            "cidr_pack_applied_rules_removed": 0,
            "cidr_pack_applied_rules_added": 0,
            "subnet_pack_applied_groups": 0,
            "subnet_pack_skipped_groups": 0,
            "subnet_pack_applied_rules_removed": 0,
            "subnet_pack_applied_rules_added": 0,
            "not_mergeable": 0,
        },
    }

    out_data = dict(data)
    out_data["normalized_ip_access_list"] = {}

    acls = data["normalized_ip_access_list"]

    progress_note(logger, f"Starting summarization for {hostname}. ACLs={len(acls)} tqdm_available={_TQDM_AVAILABLE}")

    for acl_name, acl_rules in acls.items():
        if not isinstance(acl_rules, dict):
            logger.warning("Skipping acl=%s because rules not a dict", acl_name)
            continue

        ordered_items = [(k, acl_rules[k]) for k in sorted(acl_rules.keys(), key=lambda x: safe_int(str(x)))]
        ordered_items = [(k, r) for k, r in ordered_items if isinstance(r, dict)]

        progress_note(logger, f"ACL_START {acl_name} rules={len(ordered_items)}")

        summarized_rules, rep = summarize_acl_rules(
            acl_name,
            ordered_items,
            logger,
            logs,
            tracker,
            show_progress=args.progress,
            fallback_every=effective_progress_every,
            force_fallback=args.force_fallback_progress,
        )
        renumbered = renumber_rules(summarized_rules, start=10, step=10)

        # Build rid -> new sequence mapping for audit (sample events) then strip internal fields
        rid_to_newseq: Dict[int, str] = {}
        for new_seq, rr in renumbered.items():
            if isinstance(rr, dict) and isinstance(rr.get("_rid"), int):
                rid_to_newseq[int(rr["_rid"])] = str(new_seq)

        tracker.enrich_acl(acl_name, rid_to_newseq)

        # strip internal fields from output
        for rr in renumbered.values():
            if isinstance(rr, dict):
                rr.pop("_rid", None)
                rr.pop("_orig_seq_key", None)
                rr.pop("_orig_seq_keys", None)
                rr.pop("_fold_drop", None)
        out_data["normalized_ip_access_list"][acl_name] = renumbered
        overall_report["acls"][acl_name] = asdict(rep)

        overall_report["totals"]["original_rules"] += rep.original_rule_count
        overall_report["totals"]["final_rules"] += rep.final_rule_count
        overall_report["totals"]["deduped"] += rep.deduped_count
        overall_report["totals"]["remark_differ_only"] += rep.remark_differ_only_count
        overall_report["totals"]["merged_eq"] += rep.ports_merged_eq_count
        overall_report["totals"]["merged_range"] += rep.ranges_merged_count
        overall_report["totals"]["fold_removed"] += rep.ports_folded_eq_rules_removed
        overall_report["totals"]["redundant_flagged_by_ip_permit"] += rep.redundant_flagged_by_ip_permit
        overall_report["totals"]["redundant_flagged_by_broader_permit"] += rep.redundant_flagged_by_broader_permit
        overall_report["totals"]["cidr_pack_applied_groups"] += rep.cidr_pack_applied_groups
        overall_report["totals"]["cidr_pack_skipped_groups"] += rep.cidr_pack_skipped_groups
        overall_report["totals"]["cidr_pack_applied_rules_removed"] += rep.cidr_pack_applied_rules_removed
        overall_report["totals"]["cidr_pack_applied_rules_added"] += rep.cidr_pack_applied_rules_added
        overall_report["totals"]["subnet_pack_applied_groups"] += rep.subnet_pack_applied_groups
        overall_report["totals"]["subnet_pack_skipped_groups"] += rep.subnet_pack_skipped_groups
        overall_report["totals"]["subnet_pack_applied_rules_removed"] += rep.subnet_pack_applied_rules_removed
        overall_report["totals"]["subnet_pack_applied_rules_added"] += rep.subnet_pack_applied_rules_added
        overall_report["totals"]["not_mergeable"] += rep.not_mergeable_count

        progress_note(logger, f"ACL_DONE {acl_name} original={rep.original_rule_count} final={rep.final_rule_count}")

    t1 = datetime.now(timezone.utc)
    overall_report["finished_utc"] = t1.isoformat()
    overall_report["duration_ms"] = int((t1 - t0).total_seconds() * 1000)
    overall_report["log_sample_counts"] = logs.counts

    out_json_path = outdir / f"summarized_{hostname}.json"
    report_path = outdir / f"summarize_{hostname}_report.json"
    changes_path = outdir / f"summarize_{hostname}_changes.json"

    write_json(out_json_path, out_data, pretty=args.pretty_json)
    write_json(report_path, overall_report, pretty=True)  # report stays readable
    write_json(changes_path, {
        "hostname": hostname,
        "input_file": str(inp_path),
        "output_dir": str(outdir),
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "max_event_samples": args.max_event_samples,
        **tracker.to_dict(),
    }, pretty=True)

    progress_note(logger, f"WROTE summarized_json={out_json_path} report={report_path} changes={changes_path} log={log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
