# dump_netbox.py
# Python 3.8/3.9 compatible
import json
import os
import sys
import argparse
from typing import Any, Dict, List, Optional
import requests

NETBOX_URL = os.getenv("NETBOX_URL", "http://localhost:8000").rstrip("/")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN")
VERIFY_SSL = os.getenv("VERIFY_SSL", "false").lower() == "true"
TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "20"))

if not NETBOX_TOKEN:
    print("ERROR: Set NETBOX_TOKEN env var")
    sys.exit(1)

S = requests.Session()
S.headers.update({
    "Authorization": f"Token {NETBOX_TOKEN}",
    "Accept": "application/json",
    "Content-Type": "application/json",
})
S.verify = VERIFY_SSL


def api_url(path: str) -> str:
    return f"{NETBOX_URL}/api/{path.strip('/')}/"


def get_all(path: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Paginate NetBox list endpoints and return all results."""
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
        # extract next offset
        from urllib.parse import urlparse, parse_qs
        q = parse_qs(urlparse(nxt).query)
        params["offset"] = int(q.get("offset", ["0"])[0])
    return out


def ensure_dir(path: str) -> None:
    if not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)


def dump_json(path: str, obj: Any) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2, sort_keys=False)
        f.write("\n")
    os.replace(tmp, path)


# ---------- NEW HELPERS ----------
def id_of(x: Any) -> Optional[int]:
    """Return the integer id from an int/dict/None."""
    if x is None:
        return None
    if isinstance(x, int):
        return x
    if isinstance(x, dict):
        return x.get("id")
    return None  # unexpected types -> treat as missing


def map_lookup(obj_or_id: Any, by_id: Dict[int, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Return object from a by_id map whether input is id, dict, or None."""
    _id = id_of(obj_or_id)
    if _id is None:
        return None
    return by_id.get(_id)

def delete_by_id(path, obj_id, dry_run=False):
    url = f"{api_url(path)}{obj_id}/"
    if dry_run:
        print(f"[dry-run] DELETE {url}")
        return True
    r = S.delete(url, timeout=TIMEOUT)
    if r.status_code in (204, 404):
        return True
    if r.status_code >= 400:
        print(f"DELETE {url} failed: {r.status_code} {r.text}")
    r.raise_for_status()
    return True

def existing_slugs(path, extra_params=None):
    params = dict(extra_params or {})
    objs = get_all(path, params)
    # return map: slug -> full object
    return {o.get("slug"): o for o in objs if o.get("slug")}



# ----------------------------------


def main() -> None:
    ap = argparse.ArgumentParser(description="Dump current NetBox data to JSON files.")
    ap.add_argument("--out", required=True, help="Output directory for JSON files")
    args = ap.parse_args()

    outdir = os.path.abspath(args.out)
    ensure_dir(outdir)

    # --- Pull base datasets ---
    print("Fetching regions/sites/locations...")
    regions = get_all("dcim/regions")
    sites = get_all("dcim/sites")
    locations = get_all("dcim/locations")

    print("Fetching manufacturers/device roles/device types/devices/custom fields...")
    manufacturers = get_all("dcim/manufacturers")
    device_roles = get_all("dcim/device-roles")
    device_types = get_all("dcim/device-types")
    devices = get_all("dcim/devices")
    custom_fields = get_all("extras/custom-fields")

    # --- Build quick lookup maps by id ---
    region_by_id = {r["id"]: r for r in regions}
    site_by_id = {s["id"]: s for s in sites}
    loc_by_id = {l["id"]: l for l in locations}
    mfr_by_id = {m["id"]: m for m in manufacturers}
    role_by_id = {r["id"]: r for r in device_roles}
    dtype_by_id = {d["id"]: d for d in device_types}

    # --- Build Regions tree: Region -> Sites -> Locations ---
    # Normalize foreign keys to IDs first
    sites_by_region: Dict[Optional[int], List[Dict[str, Any]]] = {}
    for s in sites:
        reg_id = id_of(s.get("region"))  # could be dict or int or None
        sites_by_region.setdefault(reg_id, []).append(s)

    locs_by_site: Dict[int, List[Dict[str, Any]]] = {}
    for l in locations:
        sid = id_of(l.get("site"))  # could be dict or int
        if sid is not None:
            locs_by_site.setdefault(sid, []).append(l)

    regions_tree: List[Dict[str, Any]] = []
    for reg in regions:
        reg_entry = {
            "name": reg.get("name"),
            "slug": reg.get("slug"),
            "description": reg.get("description") or "",
            "tags": [t.get("name") for t in reg.get("tags", [])] if isinstance(reg.get("tags"), list) else [],
            "sites": []
        }
        for s in sorted(sites_by_region.get(reg["id"], []), key=lambda x: x.get("name", "")):
            site_entry = {
                "name": s.get("name"),
                "slug": s.get("slug"),
                "status": s.get("status", "active"),
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
                "tags": [t.get("name") for t in s.get("tags", [])] if isinstance(s.get("tags"), list) else [],
                "locations": []
            }
            for l in sorted(locs_by_site.get(s["id"], []), key=lambda x: x.get("name", "")):
                site_entry["locations"].append({
                    "name": l.get("name"),
                    "slug": l.get("slug"),
                    "description": l.get("description") or "",
                    "status": l.get("status", "active"),
                    "tags": [t.get("name") for t in l.get("tags", [])] if isinstance(l.get("tags"), list) else []
                })
            reg_entry["sites"].append(site_entry)
        regions_tree.append(reg_entry)

    dump_json(os.path.join(outdir, "regions_tree.json"), regions_tree)

    # --- Manufacturers (flat) ---
    manufacturers_out = [{
        "name": m.get("name"),
        "slug": m.get("slug"),
        "description": m.get("description") or "",
        "tags": [t.get("name") for t in m.get("tags", [])] if isinstance(m.get("tags"), list) else []
    } for m in manufacturers]
    dump_json(os.path.join(outdir, "manufacturers.json"), manufacturers_out)

    # --- Device Roles (flat) ---
    roles_out = [{
        "name": r.get("name"),
        "slug": r.get("slug"),
        "color": r.get("color"),
        "vm_role": r.get("vm_role", False),
        "description": r.get("description") or "",
        "tags": [t.get("name") for t in r.get("tags", [])] if isinstance(r.get("tags"), list) else []
    } for r in device_roles]
    dump_json(os.path.join(outdir, "device_roles.json"), roles_out)

    # --- Custom Fields (flat) ---
    custom_fields_out = []
    for cf in custom_fields:
        custom_fields_out.append({
            "name": cf.get("name"),
            "label": cf.get("label"),
            "type": cf.get("type"),
            "description": cf.get("description"),
            "required": cf.get("required", False),
            "applies_to": cf.get("applies_to", []),
        })
    dump_json(os.path.join(outdir, "custom_fields.json"), custom_fields_out)

    # --- Device Types (flat), resolve manufacturer to slug ---
    dtypes_out = []
    for dt in device_types:
        man_obj = map_lookup(dt.get("manufacturer"), mfr_by_id)
        dtypes_out.append({
            "manufacturer": man_obj.get("slug") if man_obj else None,
            "model": dt.get("model"),
            "slug": dt.get("slug"),
            "part_number": dt.get("part_number"),
            "u_height": dt.get("u_height"),
            "is_full_depth": dt.get("is_full_depth"),
            "weight": dt.get("weight"),
            "weight_unit": dt.get("weight_unit"),
            "airflow": dt.get("airflow"),
            "comments": dt.get("comments") or "",
            "tags": [t.get("name") for t in dt.get("tags", [])] if isinstance(dt.get("tags"), list) else []
        })
    dump_json(os.path.join(outdir, "device_types.json"), dtypes_out)

    # --- Devices (flat), resolve FKs to slugs/names ---
    devices_out = []
    for d in devices:
        site_obj = map_lookup(d.get("site"), site_by_id)
        loc_obj = map_lookup(d.get("location"), loc_by_id)
        role_obj = map_lookup(d.get("role"), role_by_id)
        dtype_obj = map_lookup(d.get("device_type"), dtype_by_id)

        # rack is often nested object; prefer rack name
        rack_name = None
        rack_val = d.get("rack")
        if isinstance(rack_val, dict):
            rack_name = rack_val.get("name")
        elif isinstance(rack_val, str):
            rack_name = rack_val  # just in case of custom serialization

        devices_out.append({
            "name": d.get("name"),
            "status": d.get("status"),
            "site": site_obj.get("slug") if site_obj else None,
            "location": loc_obj.get("slug") if loc_obj else None,
            "role": role_obj.get("slug") if role_obj else None,
            "device_type": dtype_obj.get("slug") if dtype_obj else None,
            "serial": d.get("serial"),
            "asset_tag": d.get("asset_tag"),
            "description": d.get("description") or "",
            "comments": d.get("comments") or "",
            "platform": (d.get("platform") or {}).get("slug") if isinstance(d.get("platform"), dict) else None,
            "tenant": (d.get("tenant") or {}).get("slug") if isinstance(d.get("tenant"), dict) else None,
            "rack": rack_name,
            "position": d.get("position"),
            "face": d.get("face"),
            "tags": [t.get("name") for t in d.get("tags", [])] if isinstance(d.get("tags"), list) else []
        })


    dump_json(os.path.join(outdir, "devices.json"), devices_out)

    # --- Flat Regions ---
    regions_out = [{
        "name": r.get("name"),
        "slug": r.get("slug"),
        "description": r.get("description") or "",
        "tags": [t.get("name") for t in r.get("tags", [])] if isinstance(r.get("tags"), list) else []
    } for r in regions]
    dump_json(os.path.join(outdir, "regions.json"), regions_out)

    # --- Flat Sites (with region by slug) ---
    sites_out = []
    for s in sites:
        reg_obj = map_lookup(s.get("region"), region_by_id)
        sites_out.append({
            "name": s.get("name"),
            "slug": s.get("slug"),
            "region": reg_obj.get("slug") if reg_obj else None,
            "status": s.get("status", "active"),
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
            "tags": [t.get("name") for t in s.get("tags", [])] if isinstance(s.get("tags"), list) else []
        })
    dump_json(os.path.join(outdir, "sites.json"), sites_out)

    # --- Flat Locations (with site by slug) ---
    locations_out = []
    for l in locations:
        site_obj = map_lookup(l.get("site"), site_by_id)
        locations_out.append({
            "name": l.get("name"),
            "slug": l.get("slug"),
            "site": site_obj.get("slug") if site_obj else None,
            "status": l.get("status", "active"),
            "description": l.get("description") or "",
            "tags": [t.get("name") for t in l.get("tags", [])] if isinstance(l.get("tags"), list) else []
        })
    dump_json(os.path.join(outdir, "locations.json"), locations_out)


    print(f"Done. Wrote JSON to: {outdir}")
    print("Files: regions_tree.json, manufacturers.json, device_roles.json, device_types.json, devices.json")


if __name__ == "__main__":
    main()

