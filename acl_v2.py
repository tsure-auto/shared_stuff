#!/usr/bin/env python3
"""
summarize_acl_v3_1.py

V3.1 = V3 logic + performance improvements for huge ACLs:
- Avoid deepcopy() (use shallow copies + copy-on-write on mutated fields)
- Sample logs per event type (full counts still in JSON report)
- Compact JSON output by default (pretty JSON optional)
- Progress heartbeat for long ACLs

GT/LT logic still not merged/changed.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network, IPv4Address, IPv4Network, collapse_addresses
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


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
    # Shallow copies only (v3.1)
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
    merged = dict(a)  # shallow
    pa = normalize_port_list(a.get("dst_ports")) or []
    pb = normalize_port_list(b.get("dst_ports")) or []
    merged["dst_ports"] = ports_to_sorted_unique_str(pa + pb)  # replace list
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
    vary_side: str,
    min_hosts: int = 4,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    i = 0
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

        if len(cidrs) >= len(run):
            rep.cidr_pack_skipped_groups += 1
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

        logs.warning(
            "CIDR_PACK_APPLIED",
            "CIDR_PACK_APPLIED acl=%s side=%s hosts=%d cidrs=%d cidrs_list=%s",
            acl_name, vary_side, len(run), len(cidrs), [str(c) for c in cidrs]
        )

        template = run[0]  # no copy yet
        cidrs_sorted = sorted(cidrs, key=lambda n: (int(n.network_address), n.prefixlen))

        for net in cidrs_sorted:
            nr = dict(template)  # shallow copy
            nr.update(convert_network_to_schema(net, vary_side))
            base_remark = (template.get("remark") or "").strip()
            nr["remark"] = (base_remark + " | summarized_exact_cidr_cover").strip(" |")
            out.append(nr)

        i = j

    return out


# -----------------------------
# Non-adjacent folding in permit windows (V3 feature, now O(n))
# -----------------------------

def fold_key_eq(rule: Dict[str, Any]) -> Optional[Tuple]:
    if rule.get("action") != "permit":
        return None
    if rule.get("dst_port_op") != "eq":
        return None
    # This is the semantics key excluding dst_ports and remark/seq/options
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
    progress_every: int,
) -> List[Dict[str, Any]]:
    """
    Fold non-adjacent eq rules within contiguous windows separated by denies.
    We keep the first occurrence as canonical; later matches are removed and ports unioned.
    """
    out: List[Dict[str, Any]] = []
    window: List[Dict[str, Any]] = []
    seen: Dict[Tuple, Dict[str, Any]] = {}   # fold_key -> canonical rule dict in window
    seen_ports: Dict[Tuple, set] = {}        # fold_key -> port set
    removed_seqs: Dict[Tuple, List[str]] = {}  # fold_key -> list of removed orig keys (if present)

    def flush_window():
        # Emit window in original order, skipping rules marked _fold_drop
        for r in window:
            if r.get("_fold_drop"):
                continue
            out.append(r)
        window.clear()
        seen.clear()
        seen_ports.clear()
        removed_seqs.clear()

    for idx, r in enumerate(rules, start=1):
        if progress_every and idx % progress_every == 0:
            logs.logger.info("PROGRESS acl=%s processed=%d/%d", acl_name, idx, len(rules))

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
            # first occurrence in this window
            canon = r
            seen[fk] = canon
            seen_ports[fk] = set(ports)
            window.append(canon)
            continue

        # fold into canonical
        canon = seen[fk]
        seen_ports[fk].update(ports)

        # mark this rule as dropped from output
        r["_fold_drop"] = True
        window.append(r)

        rep.ports_folded_eq_rules_removed += 1

        # update canonical rule's dst_ports (copy-on-write list)
        canon["dst_ports"] = ports_to_sorted_unique_str(list(seen_ports[fk]))

        # log sampled example
        rep.ports_folded_eq_groups += 1  # counts fold events (not unique keys); good enough for ops reporting
        logs.info(
            "PORTS_FOLDED_EQ",
            "PORTS_FOLDED_EQ acl=%s fold_key=%s ports_now=%s",
            acl_name, fk, canon["dst_ports"]
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
    progress_every: int,
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

    for i, (seq_key, rule) in enumerate(rules_in_order, start=1):
        if progress_every and i % progress_every == 0:
            logger.info("PROGRESS acl=%s dedupe=%d/%d", acl_name, i, len(rules_in_order))

        k = semantic_key_for_dedupe(rule)
        if k in seen:
            prev = seen[k]
            if (prev.get("remark") or "") != (rule.get("remark") or ""):
                rep.remark_differ_only_count += 1
                logs.warning(
                    "REMARK_DIFFER_ONLY",
                    "REMARK_DIFFER_ONLY acl=%s kept_seq=%s dropped_seq=%s",
                    acl_name, prev.get("_orig_seq_key"), seq_key
                )
            rep.deduped_count += 1
            logs.info("DEDUPED_RULE", "DEDUPED_RULE acl=%s dropped_seq=%s kept_seq=%s", acl_name, seq_key, prev.get("_orig_seq_key"))
            continue

        rr = dict(rule)  # shallow copy (v3.1)
        rr["_orig_seq_key"] = seq_key
        seen[k] = rr
        kept.append((seq_key, rr))

    # Step 2: Flag redundancy covered by earlier permit ip (no delete)
    ip_permits_seen: List[Dict[str, Any]] = []
    for seq_key, rule in kept:
        if rule.get("action") == "permit" and rule.get("protocol") == "ip":
            ip_permits_seen.append(rule)
            continue
        # Fast path: if there are no ip permits, skip loop
        if not ip_permits_seen:
            continue
        for earlier in ip_permits_seen:
            if rule_covered_by_ip_permit(rule, earlier):
                rep.redundant_flagged_by_ip_permit += 1
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
                after = normalize_port_list(current.get("dst_ports")) or []
                rep.ports_merged_eq_count += 1
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
                    logs.info(
                        "RANGE_MERGED",
                        "RANGE_MERGED acl=%s base_seq=%s merged_seq=%s new_range=%s",
                        acl_name, base_seq, next_seq, candidate.get("dst_ports")
                    )
                    current = candidate
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

    # Step 3.5 (V3): Non-adjacent folding in permit windows (O(n), sampled logs)
    merged_out = fold_eq_ports_within_permit_windows(merged_out, acl_name, logs, rep, progress_every)

    # Step 4: Exact CIDR packing (src then dst)
    merged_out = apply_exact_host_packing_contiguous(merged_out, acl_name, logger, logs, rep, vary_side="src", min_hosts=4)
    merged_out = apply_exact_host_packing_contiguous(merged_out, acl_name, logger, logs, rep, vary_side="dst", min_hosts=4)

    # Step 5: Flag redundancy covered by earlier broader permit (not ip) (no delete)
    earlier_permits: List[Dict[str, Any]] = []
    for r in merged_out:
        if r.get("action") == "permit":
            for e in earlier_permits:
                if rule_covered_by_earlier_permit(r, e):
                    rep.redundant_flagged_by_broader_permit += 1
                    logs.warning(
                        "REDUNDANT_COVERED_BY_BROADER_PERMIT",
                        "REDUNDANT_COVERED_BY_BROADER_PERMIT acl=%s rule_remark=%r covered_by_remark=%r",
                        acl_name, r.get("remark"), e.get("remark")
                    )
                    break
            earlier_permits.append(r)

    # Cleanup internal keys
    for r in merged_out:
        r.pop("_orig_seq_key", None)
        r.pop("_fold_drop", None)

    rep.final_rule_count = len(merged_out)

    logger.info(
        "OUTPUT_STATS acl=%s original=%d final=%d deduped=%d remark_differ=%d merged_eq=%d merged_range=%d "
        "fold_removed=%d redundant_ip_flagged=%d redundant_broader_flagged=%d cidr_applied_groups=%d cidr_removed=%d cidr_added=%d not_mergeable=%d",
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
    ap = argparse.ArgumentParser(description="Summarize Cisco normalized ACL JSON (V3.1 fast).")
    ap.add_argument("--input", required=True, help="Path to input JSON file")
    ap.add_argument("--outdir", default="out", help="Output directory")
    ap.add_argument("--verbose", action="store_true", help="Also print INFO logs to stdout")
    ap.add_argument("--log-sample", type=int, default=50, help="Log first N examples per event type (default 50). Use 0 for counters-only.")
    ap.add_argument("--pretty-json", action="store_true", help="Write indented JSON outputs (slower for huge files).")
    ap.add_argument("--progress-every", type=int, default=5000, help="Progress heartbeat every N rules (default 5000). Use 0 to disable.")
    args = ap.parse_args()

    inp_path = Path(args.input).expanduser().resolve()
    outdir = Path(args.outdir).expanduser().resolve()

    data = load_json(inp_path)
    hostname = str(data.get("hostname") or inp_path.stem)

    log_path = outdir / f"summarize_{hostname}.log"
    logger = setup_logger(log_path, verbose=args.verbose)
    logs = LogSampler(logger, sample_limit=args.log_sample)

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
            "progress_every": args.progress_every,
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
            "not_mergeable": 0,
        },
    }

    out_data = dict(data)  # shallow copy top-level
    out_data["normalized_ip_access_list"] = {}

    for acl_name, acl_rules in data["normalized_ip_access_list"].items():
        if not isinstance(acl_rules, dict):
            logger.warning("Skipping acl=%s because rules not a dict", acl_name)
            continue

        ordered_items = [(k, acl_rules[k]) for k in sorted(acl_rules.keys(), key=lambda x: safe_int(str(x)))]
        ordered_items = [(k, r) for k, r in ordered_items if isinstance(r, dict)]

        logger.info("ACL_START acl=%s rules=%d", acl_name, len(ordered_items))

        summarized_rules, rep = summarize_acl_rules(
            acl_name,
            ordered_items,
            logger,
            logs,
            progress_every=args.progress_every,
        )
        renumbered = renumber_rules(summarized_rules, start=10, step=10)
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
        overall_report["totals"]["not_mergeable"] += rep.not_mergeable_count

        logger.info("ACL_DONE acl=%s original=%d final=%d", acl_name, rep.original_rule_count, rep.final_rule_count)

    t1 = datetime.now(timezone.utc)
    overall_report["finished_utc"] = t1.isoformat()
    overall_report["duration_ms"] = int((t1 - t0).total_seconds() * 1000)
    overall_report["log_sample_counts"] = logs.counts

    out_json_path = outdir / f"summarized_{hostname}.json"
    report_path = outdir / f"summarize_{hostname}_report.json"

    write_json(out_json_path, out_data, pretty=args.pretty_json)
    write_json(report_path, overall_report, pretty=True)  # report stays readable

    logger.info("WROTE summarized_json=%s report=%s log=%s", out_json_path, report_path, log_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
