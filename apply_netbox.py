# apply_netbox.py
# Python 3.8/3.9 compatible

import json
import os
import sys
import argparse
from typing import Any, Dict, List, Optional
import requests
from tqdm import tqdm
import logging
import re
import random
from functools import lru_cache

# ----------------- config -----------------
NETBOX_URL = os.getenv("NETBOX_URL", "http://127.0.0.1:8000").rstrip("/")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN")
VERIFY_SSL = os.getenv("VERIFY_SSL", "false").lower() == "true"
TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "20"))
HEX6_RE = re.compile(r'^[0-9a-f]{6}$', re.I)

if not NETBOX_TOKEN:
    print("ERROR: Set NETBOX_TOKEN env var")
    sys.exit(1)

# --- Logging setup ---
LOG_FILE = os.getenv("NETBOX_APPLY_LOG", "apply_netbox.log")
logging.basicConfig(
    filename=LOG_FILE,
    filemode="a",
    format="%(asctime)s %(levelname)s: %(message)s",
    level=logging.INFO
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(levelname)s: %(message)s')
console.setFormatter(formatter)
logging.getLogger().addHandler(console)

S = requests.Session()
S.headers.update({
    "Authorization": f"Token {NETBOX_TOKEN}",
    "Accept": "application/json",
    "Content-Type": "application/json",
})
S.verify = VERIFY_SSL

# ----------------- helpers -----------------

def _normalize_hex(s: str) -> Optional[str]:
    if not s:
        return None
    s = s.strip().lstrip('#').lower()
    # expand 3-digit form
    if len(s) == 3 and re.fullmatch(r'[0-9a-f]{3}', s):
        s = ''.join(ch*2 for ch in s)
    if not HEX6_RE.fullmatch(s):
        return None
    return s

@lru_cache(maxsize=1)
def get_allowed_role_colors() -> List[str]:
    """
    Try to fetch allowed color choices for DeviceRole from NetBox.
    Returns a list of normalized 6-hex strings (lowercase, no '#').
    Falls back to a reasonable palette if choices API is unavailable.
    """
    try:
        # Newer NetBox exposes /api/extras/choices/
        r = S.get(api_url("extras/choices/"), timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
        colors = set()
        # choices payload shape: { "choices": [ { "model": "dcim.devicerole", "field": "color", "choices": [ {"value": "..."} ] }, ... ] }
        for grp in data.get("choices", []):
            model = grp.get("model") or grp.get("name")  # some versions use "name"
            field = grp.get("field")
            if (model == "dcim.devicerole" or model == "dcim.DeviceRole") and field == "color":
                for c in grp.get("choices", []):
                    v = _normalize_hex(str(c.get("value", "")))
                    if v:
                        colors.add(v)
        if colors:
            return sorted(colors)
    except Exception as e:
        logging.info(f"Could not load choices from extras/choices: {e}")

    # Fallback palette (valid hex strings). Add/adjust as you like.
    fallback = [
        "e53935","d81b60","8e24aa","5e35b1","3949ab","1e88e5","039be5","00acc1",
        "00897b","43a047","7cb342","c0ca33","fdd835","ffb300","fb8c00","f4511e",
        "6d4c41","757575","546e7a"
    ]
    return fallback

def pick_colors_for_roles(role_items: List[Dict[str, Any]]) -> Dict[str, str]:
    """
    For each role (by slug), choose a color from the allowed list.
    - If the role already has a valid color and it’s allowed, keep it.
    - Otherwise assign randomly without repetition until the pool is exhausted,
      then reshuffle and continue (so roles > colors still works).
    Returns: { role_slug: hex6 }
    """
    allowed = get_allowed_role_colors()
    pool_master = allowed[:]  # copy
    random.shuffle(pool_master)

    # Build a working pool we can pop from
    pool = pool_master[:]
    assigned: Dict[str, str] = {}

    # First pass: respect valid + allowed colors already present
    for r in role_items:
        slug = r.get("slug")
        raw = r.get("color")
        norm = _normalize_hex(raw) if raw else None
        if norm and norm in allowed:
            assigned[slug] = norm

    # Second pass: assign to the rest
    for r in role_items:
        slug = r.get("slug")
        if slug in assigned:
            continue
        if not pool:
            # Reuse: reset and reshuffle to keep random spread
            pool = pool_master[:]
            random.shuffle(pool)
        assigned[slug] = pool.pop()
    return assigned


def api_url(path: str) -> str:
    return f"{NETBOX_URL}/api/{path.strip('/')}/"

def load_json(path: str) -> Optional[Any]:
    if not os.path.isfile(path):
        return None
    with open(path, "r") as f:
        return json.load(f)

def get_all(path: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    url = api_url(path)
    params = dict(params or {})
    params.setdefault("limit", 200)
    params.setdefault("offset", 0)
    out: List[Dict[str, Any]] = []
    while True:
        r = S.get(url, params=params, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
        out.extend(data.get("results", []))
        nxt = data.get("next")
        if not nxt:
            break
        from urllib.parse import urlparse, parse_qs
        q = parse_qs(urlparse(nxt).query)
        params["offset"] = int(q.get("offset", ["0"])[0])
    return out

def get_first_id(path: str, params: Dict[str, Any]) -> Optional[int]:
    r = S.get(api_url(path), params=params, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    if data.get("count", 0) > 0:
        return data["results"][0]["id"]
    return None

def strip_none(d: Dict[str, Any]) -> Dict[str, Any]:
    """Return a shallow copy without None values."""
    return {k: v for k, v in d.items() if v is not None}

def normalize_status(s):
    """Accept 'active' or {'value':'active','label':...} and return 'active'."""
    if isinstance(s, str):
        return s
    if isinstance(s, dict):
        return s.get("value") or (s.get("label") or "").lower() or None
    return None

def upsert_by_slug(path: str, slug: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    url = api_url(path)
    r = S.get(url, params={"slug": slug}, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    clean = strip_none(payload)
    if data.get("count", 0) > 0:
        obj_id = data["results"][0]["id"]
        pr = S.patch(f"{url}{obj_id}/", json=clean, timeout=TIMEOUT)
        if pr.status_code >= 400:
            logging.error(f"PATCH {path}/{obj_id} failed. Payload: {json.dumps(clean, indent=2)} Server said: {pr.text}")
        pr.raise_for_status()
        logging.info(f"PATCH {path}/{obj_id} succeeded.")
        return pr.json()
    else:
        cr = S.post(url, json=clean, timeout=TIMEOUT)
        if cr.status_code >= 400:
            logging.error(f"POST {path} failed. Payload: {json.dumps(clean, indent=2)} Server said: {cr.text}")
        cr.raise_for_status()
        logging.info(f"POST {path} succeeded.")
        return cr.json()

def upsert_device(name: str, site_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    url = api_url("dcim/devices")
    r = S.get(url, params={"name": name, "site_id": site_id}, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    clean = strip_none(payload)
    if data.get("count", 0) > 0:
        dev_id = data["results"][0]["id"]
        pr = S.patch(f"{url}{dev_id}/", json=clean, timeout=TIMEOUT)
        if pr.status_code >= 400:
            logging.error(f"PATCH dcim/devices/{dev_id} failed. Payload: {json.dumps(clean, indent=2)} Server said: {pr.text}")
        pr.raise_for_status()
        logging.info(f"PATCH dcim/devices/{dev_id} succeeded.")
        return pr.json()
    else:
        cr = S.post(url, json=clean, timeout=TIMEOUT)
        if cr.status_code >= 400:
            logging.error(f"POST dcim/devices failed. Payload: {json.dumps(clean, indent=2)} Server said: {cr.text}")
        cr.raise_for_status()
        logging.info(f"POST dcim/devices succeeded.")
        return cr.json()

def delete_by_id(path, obj_id, dry_run=False):
    url = f"{api_url(path)}{obj_id}/"
    if dry_run:
        logging.info(f"[dry-run] DELETE {url}")
        return True
    r = S.delete(url, timeout=TIMEOUT)
    if r.status_code in (204, 404):
        logging.info(f"DELETE {url} succeeded.")
        return True
    if r.status_code >= 400:
        logging.error(f"DELETE {url} failed: {r.status_code} {r.text}")
    r.raise_for_status()
    return True

# ----------------- apply functions -----------------

def apply_manufacturers(items: List[Dict[str, Any]]) -> None:
    if not items:
        return
    print(f"Applying manufacturers ({len(items)})...")
    for m in tqdm(items, desc="Manufacturers", unit="item"):
        payload = {
            "name": m["name"],
            "slug": m["slug"],
            "description": m.get("description") or "",
            "tags": m.get("tags") or []
        }
        upsert_by_slug("dcim/manufacturers", m["slug"], payload)

def apply_device_roles(items: List[Dict[str, Any]]) -> None:
    if not items:
        return
    print(f"Applying device roles ({len(items)})...")

    # Decide colors up front
    color_map = pick_colors_for_roles(items)

    for r in tqdm(items, desc="Device Roles", unit="item"):
        payload = {
            "name": r["name"],
            "slug": r["slug"],
            "color": color_map.get(r["slug"]),  # normalized 6-hex (no '#')
            "vm_role": r.get("vm_role", False),
            "description": r.get("description") or "",
            "tags": r.get("tags") or []
        }
        payload = strip_none(payload)
        upsert_by_slug("dcim/device-roles", r["slug"], payload)

def apply_regions(items: List[Dict[str, Any]]) -> None:
    if not items:
        return
    print(f"Applying regions ({len(items)})...")
    for r in tqdm(items, desc="Regions", unit="item"):
        payload = {
            "name": r["name"],
            "slug": r["slug"],
            "description": r.get("description") or "",
            "tags": r.get("tags") or []
        }
        upsert_by_slug("dcim/regions", r["slug"], payload)

def apply_sites(items: List[Dict[str, Any]]) -> None:
    if not items:
        return
    print(f"Applying sites ({len(items)})...")
    for s in tqdm(items, desc="Sites", unit="item"):
        reg_slug = s.get("region")
        region_id = get_first_id("dcim/regions", {"slug": reg_slug}) if reg_slug else None
        payload = {
            "name": s["name"],
            "slug": s["slug"],
            "status": normalize_status(s.get("status")) or "active",
            "region": region_id,
            "description": s.get("description") or "",
            "facility": s.get("facility"),
            "asn": s.get("asn"),
            "physical_address": s.get("physical_address"),
            "shipping_address": s.get("shipping_address"),
            "latitude": s.get("latitude"),
            "longitude": s.get("longitude"),
            "contact_name": s.get("contact_name"),
            "contact_phone": s.get("contact_phone"),
            "contact_email": s.get("contact_email"),
            "tags": s.get("tags") or []
        }
        payload = strip_none(payload)
        upsert_by_slug("dcim/sites", s["slug"], payload)

def apply_locations(items: List[Dict[str, Any]]) -> None:
    if not items:
        return
    print(f"Applying locations ({len(items)})...")
    for l in tqdm(items, desc="Locations", unit="item"):
        site_slug = l.get("site")
        if not site_slug:
            raise ValueError(f"Location '{l.get('slug')}' missing site")
        site_id = get_first_id("dcim/sites", {"slug": site_slug})
        if not site_id:
            raise ValueError(f"Site not found for slug '{site_slug}' (needed by location '{l.get('slug')}')")

        url = api_url("dcim/locations")
        r = S.get(url, params={"slug": l["slug"], "site_id": site_id}, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()

        payload = {
            "name": l["name"],
            "slug": l["slug"],
            "site": site_id,
            "status": normalize_status(l.get("status")) or "active",
            "description": l.get("description") or "",
            "tags": l.get("tags") or []
        }
        payload = strip_none(payload)

        if data.get("count", 0) > 0:
            loc_id = data["results"][0]["id"]
            pr = S.patch(f"{url}{loc_id}/", json=payload, timeout=TIMEOUT)
            if pr.status_code >= 400:
                print(f"\nPATCH dcim/locations/{loc_id} failed.\nPayload:\n{json.dumps(payload, indent=2)}\nServer said:\n{pr.text}\n")
            pr.raise_for_status()
        else:
            cr = S.post(url, json=payload, timeout=TIMEOUT)
            if cr.status_code >= 400:
                print(f"\nPOST dcim/locations failed.\nPayload:\n{json.dumps(payload, indent=2)}\nServer said:\n{cr.text}\n")
            cr.raise_for_status()

def apply_device_types(items: List[Dict[str, Any]]) -> None:
    if not items:
        return
    print(f"Applying device types ({len(items)})...")
    for dt in tqdm(items, desc="Device Types", unit="item"):
        man_slug = dt.get("manufacturer")
        man_id = get_first_id("dcim/manufacturers", {"slug": man_slug}) if man_slug else None
        payload = {
            "manufacturer": man_id,
            "model": dt["model"],
            "slug": dt["slug"],
            "part_number": dt.get("part_number"),
            "u_height": dt.get("u_height", 1),
            "is_full_depth": dt.get("is_full_depth", True),
            "weight": dt.get("weight"),
            "weight_unit": dt.get("weight_unit"),
            "airflow": dt.get("airflow"),
            "comments": dt.get("comments") or "",
            "tags": dt.get("tags") or []
        }
        payload = strip_none(payload)
        upsert_by_slug("dcim/device-types", dt["slug"], payload)

def apply_devices(items: List[Dict[str, Any]]) -> None:
    if not items:
        return
    print(f"Applying devices ({len(items)})...")
    for d in tqdm(items, desc="Devices", unit="item"):
        site_slug = d.get("site")
        if not site_slug:
            raise ValueError(f"Device '{d.get('name')}' missing 'site'")
        site_id = get_first_id("dcim/sites", {"slug": site_slug})
        if not site_id:
            raise ValueError(f"Site not found for slug '{site_slug}'")
        role_id  = get_first_id("dcim/device-roles", {"slug": d.get("role")}) if d.get("role") else None
        dtype_id = get_first_id("dcim/device-types", {"slug": d.get("device_type")}) if d.get("device_type") else None
        loc_id   = get_first_id("dcim/locations", {"slug": d.get("location"), "site_id": site_id}) if d.get("location") else None

        payload = {
            "name": d["name"],
            "site": site_id,
            "role": role_id,
            "device_type": dtype_id,
            "status": normalize_status(d.get("status")) or "active",
            "description": d.get("description") or "",
            "comments": d.get("comments") or "",
            "serial": d.get("serial"),
            "asset_tag": d.get("asset_tag"),
            "tags": d.get("tags") or []
        }
        if loc_id:
            payload["location"] = loc_id
        if d.get("rack"):
            rack_id = get_first_id("dcim/racks", {"site_id": site_id, "name": d["rack"]})
            if rack_id:
                payload["rack"] = rack_id
                if d.get("position") is not None:
                    payload["position"] = d["position"]
                if d.get("face"):
                    payload["face"] = d["face"]

        payload = strip_none(payload)
        upsert_device(d["name"], site_id, payload)

# ----------------- prune functions -----------------

def delete_guard_msg(kind: str, slug: str, obj_id: int, reason: str):
    logging.warning(f"Skip {kind} '{slug}' (id={obj_id}) – {reason}.")

def prune_devices(desired_devices: List[Dict[str, Any]], dry_run=False):
    desired_pairs = set((d["name"], d.get("site")) for d in desired_devices if d.get("name") and d.get("site"))
    current = get_all("dcim/devices")
    to_delete = []
    for dev in current:
        site_slug = (dev.get("site") or {}).get("slug") if isinstance(dev.get("site"), dict) else None
        key = (dev.get("name"), site_slug)
        if key not in desired_pairs:
            to_delete.append(dev)
    if not to_delete:
        return
    print(f"Pruning devices: {len(to_delete)}")
    for dev in tqdm(to_delete, desc="Prune Devices", unit="item"):
        delete_by_id("dcim/devices", dev["id"], dry_run=dry_run)

def prune_locations(desired_locations: List[Dict[str, Any]], dry_run=False):
    desired_pairs = set((l["slug"], l.get("site")) for l in desired_locations if l.get("slug"))
    current = get_all("dcim/locations")
    to_delete = []
    for loc in current:
        site_slug = (loc.get("site") or {}).get("slug") if isinstance(loc.get("site"), dict) else None
        key = (loc.get("slug"), site_slug)
        if key not in desired_pairs:
            to_delete.append(loc)
    if not to_delete:
        return
    print(f"Pruning locations: {len(to_delete)}")
    for loc in tqdm(to_delete, desc="Prune Locations", unit="item"):
        devs = get_all("dcim/devices", {"location_id": loc["id"]})
        if devs:
            delete_guard_msg("location", loc.get("slug"), loc["id"], f"has {len(devs)} device(s)")
            continue
        delete_by_id("dcim/locations", loc["id"], dry_run=dry_run)

def prune_sites(desired_sites: List[Dict[str, Any]], dry_run=False):
    desired = set(s["slug"] for s in desired_sites if s.get("slug"))
    current = get_all("dcim/sites")
    to_delete = [s for s in current if s.get("slug") not in desired]
    if not to_delete:
        return
    print(f"Pruning sites: {len(to_delete)}")
    for s in tqdm(to_delete, desc="Prune Sites", unit="item"):
        locs = get_all("dcim/locations", {"site_id": s["id"]})
        devs = get_all("dcim/devices", {"site_id": s["id"]})
        if locs or devs:
            delete_guard_msg("site", s.get("slug"), s["id"], f"{len(locs)} location(s), {len(devs)} device(s) present")
            continue
        delete_by_id("dcim/sites", s["id"], dry_run=dry_run)

def prune_regions(desired_regions: List[Dict[str, Any]], dry_run=False):
    desired = set(r["slug"] for r in desired_regions if r.get("slug"))
    current = get_all("dcim/regions")
    to_delete = [r for r in current if r.get("slug") not in desired]
    if not to_delete:
        return
    print(f"Pruning regions: {len(to_delete)}")
    for r in tqdm(to_delete, desc="Prune Regions", unit="item"):
        sites = get_all("dcim/sites", {"region_id": r["id"]})
        if sites:
            delete_guard_msg("region", r.get("slug"), r["id"], f"has {len(sites)} site(s)")
            continue
        delete_by_id("dcim/regions", r["id"], dry_run=dry_run)

def prune_device_types(desired_dtypes: List[Dict[str, Any]], dry_run=False):
    desired = set(dt["slug"] for dt in desired_dtypes if dt.get("slug"))
    current = get_all("dcim/device-types")
    to_delete = [dt for dt in current if dt.get("slug") not in desired]
    if not to_delete:
        return
    print(f"Pruning device types: {len(to_delete)}")
    for dt in tqdm(to_delete, desc="Prune Device Types", unit="item"):
        in_use = get_all("dcim/devices", {"device_type_id": dt["id"]})
        if in_use:
            delete_guard_msg("device-type", dt.get("slug"), dt["id"], f"used by {len(in_use)} device(s)")
            continue
        delete_by_id("dcim/device-types", dt["id"], dry_run=dry_run)

def prune_manufacturers(desired_mfrs: List[Dict[str, Any]], dry_run=False):
    desired = set(m["slug"] for m in desired_mfrs if m.get("slug"))
    current = get_all("dcim/manufacturers")
    to_delete = [m for m in current if m.get("slug") not in desired]
    if not to_delete:
        return
    print(f"Pruning manufacturers: {len(to_delete)}")
    for m in tqdm(to_delete, desc="Prune Manufacturers", unit="item"):
        dtypes = get_all("dcim/device-types", {"manufacturer_id": m["id"]})
        if dtypes:
            delete_guard_msg("manufacturer", m.get("slug"), m["id"], f"has {len(dtypes)} device-type(s)")
            continue
        delete_by_id("dcim/manufacturers", m["id"], dry_run=dry_run)

def prune_device_roles(desired_roles: List[Dict[str, Any]], dry_run=False):
    desired = set(r["slug"] for r in desired_roles if r.get("slug"))
    current = get_all("dcim/device-roles")
    to_delete = [r for r in current if r.get("slug") not in desired]
    if not to_delete:
        return
    print(f"Pruning device roles: {len(to_delete)}")
    for r in tqdm(to_delete, desc="Prune Device Roles", unit="item"):
        in_use = get_all("dcim/devices", {"role_id": r["id"]})
        if in_use:
            delete_guard_msg("device-role", r.get("slug"), r["id"], f"used by {len(in_use)} device(s)")
            continue
        delete_by_id("dcim/device-roles", r["id"], dry_run=dry_run)

# ----------------- main -----------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Apply JSON back to NetBox (upsert).")
    ap.add_argument("--in", dest="indir", required=True, help="Input directory with JSON files")
    ap.add_argument("--prune", action="store_true", help="Delete resources not present in JSON")
    ap.add_argument("--dry-run", action="store_true", help="Show what would be deleted without doing it")
    args = ap.parse_args()

    indir = os.path.abspath(args.indir)

    manufacturers = load_json(os.path.join(indir, "manufacturers.json")) or []
    device_roles  = load_json(os.path.join(indir, "device_roles.json")) or []
    regions       = load_json(os.path.join(indir, "regions.json")) or []
    sites         = load_json(os.path.join(indir, "sites.json")) or []
    locations     = load_json(os.path.join(indir, "locations.json")) or []
    device_types  = load_json(os.path.join(indir, "device_types.json")) or []
    devices       = load_json(os.path.join(indir, "devices.json")) or []
    custom_fields = load_json(os.path.join(indir, "custom_fields.json")) or []

    print("Starting NetBox apply...")
    logging.info("Starting NetBox apply...")
    apply_manufacturers(manufacturers)
    apply_device_roles(device_roles)
    apply_regions(regions)
    apply_sites(sites)
    apply_locations(locations)
    apply_device_types(device_types)
    apply_devices(devices)

    # --- Custom Fields Sync ---
    print(f"Applying custom fields ({len(custom_fields)})...")
    # Get current custom fields from NetBox
    current_fields = get_all("extras/custom-fields")
    current_by_name = {f["name"]: f for f in current_fields}
    desired_names = set(f["name"] for f in custom_fields)

    # Upsert or update
    for cf in custom_fields:
        payload = strip_none(cf)
        # Ensure 'type' is a string, not a dict
        if isinstance(payload.get("type"), dict):
            payload["type"] = payload["type"].get("value")
        if cf["name"] in current_by_name:
            # Update if changed
            obj = current_by_name[cf["name"]]
            changed = any(payload.get(k) != obj.get(k) for k in payload)
            if changed:
                pr = S.patch(f"{api_url('extras/custom-fields')}{obj['id']}/", json=payload, timeout=TIMEOUT)
                if pr.status_code >= 400:
                    logging.error(f"PATCH custom-field/{obj['id']} failed. Payload: {json.dumps(payload, indent=2)} Server said: {pr.text}")
                pr.raise_for_status()
                logging.info(f"PATCH custom-field/{obj['id']} succeeded.")
        else:
            cr = S.post(api_url("extras/custom-fields"), json=payload, timeout=TIMEOUT)
            if cr.status_code >= 400:
                logging.error(f"POST custom-field {cf['name']} failed. Payload: {json.dumps(payload, indent=2)} Server said: {cr.text}")
            cr.raise_for_status()
            logging.info(f"POST custom-field {cf['name']} succeeded.")

    # Delete fields not present in JSON
    for name, obj in current_by_name.items():
        if name not in desired_names:
            dr = S.delete(f"{api_url('extras/custom-fields')}{obj['id']}/", timeout=TIMEOUT)
            if dr.status_code in (204, 404):
                logging.info(f"DELETE custom-field/{obj['id']} succeeded.")
            else:
                logging.error(f"DELETE custom-field/{obj['id']} failed: {dr.status_code} {dr.text}")
            dr.raise_for_status()

    # Optional prune
    if args.prune:
        print("\n=== PRUNE PHASE ===")
        logging.info("=== PRUNE PHASE ===")
        prune_devices(devices, dry_run=args.dry_run)
        prune_locations(locations, dry_run=args.dry_run)
        prune_sites(sites, dry_run=args.dry_run)
        prune_regions(regions, dry_run=args.dry_run)
        prune_device_types(device_types, dry_run=args.dry_run)
        prune_manufacturers(manufacturers, dry_run=args.dry_run)
        prune_device_roles(device_roles, dry_run=args.dry_run)

    print("Apply complete.")
    logging.info("Apply complete.")

if __name__ == "__main__":
    main()

