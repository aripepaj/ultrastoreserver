import unicodedata
import json
import re
from datetime import datetime

FAILED_LOG_FILE = "failed_orders.log"

def normalize_city(city_name: str) -> str:
    city_name = (city_name or "").strip().lower()
    city_name = unicodedata.normalize("NFKD", city_name).encode("ASCII", "ignore").decode("utf-8")
    city_name = city_name.replace("-", " ").replace("ë", "e").replace("ç", "c")
    return city_name

def vendor_key(name: str) -> str:
    return (name or "").strip().lower()

def load_partners(path: str = "partners.json") -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def log_failed_order(order_id, reason, extra=None):
    entry = {"ts": datetime.utcnow().isoformat() + "Z", "order_id": order_id, "reason": reason}
    if extra is not None:
        entry["extra"] = extra
    print("[FAILED_ORDER]", json.dumps(entry, ensure_ascii=False), flush=True)
    try:
        with open(FAILED_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass

def extract_phone(order: dict):
    shipping = order.get("shipping_address") or {}
    billing  = order.get("billing_address") or {}
    customer = order.get("customer") or {}
    default_addr = customer.get("default_address") or {}
    return (shipping.get("phone")
            or order.get("phone")
            or billing.get("phone")
            or customer.get("phone")
            or default_addr.get("phone"))

def phone_kosovo_local(phone: str) -> str:
    """
    Convert +383xxxx or 00383xxxx to local 0xxxx, and strip all non-digits.
    Examples:
      +38344123456  -> 044123456
      0038345123456 -> 045123456
      044 123 456   -> 044123456
    """
    if not phone:
        return ""
    p = str(phone).strip().replace(" ", "")
    if p.startswith("+383"):
        return "0" + re.sub(r"\D", "", p[4:])
    if p.startswith("00383"):
        return "0" + re.sub(r"\D", "", p[5:])
    return re.sub(r"\D", "", p)

def extract_address(order: dict) -> str:
    shipping = order.get("shipping_address") or {}
    billing  = order.get("billing_address") or {}
    chosen = shipping if shipping.get("address1") else billing
    parts = []
    if chosen.get("address1"): parts.append(chosen["address1"])
    if chosen.get("address2"): parts.append(chosen["address2"])
    if chosen.get("zip"):      parts.append(chosen["zip"])
    if chosen.get("city"):     parts.append(chosen["city"])
    return ", ".join(parts)

def variant_text(line_item: dict) -> str:
    """
    Build a compact variant description from Shopify line_item.
    Uses variant_title if present, else constructs from 'properties' (list of dicts name/value),
    skipping empty or Shopify-internal fields (name starting with '_').
    """
    vt = line_item.get("variant_title")
    if vt:
        return vt
    props = line_item.get("properties") or []
    display = []
    if isinstance(props, list):
        for p in props:
            if not isinstance(p, dict):
                continue
            name = (p.get("name") or "").strip()
            value = (p.get("value") or "").strip()
            if not name or not value:
                continue
            if name.startswith("_"):  # internal meta
                continue
            display.append(f"{name}: {value}")
    return " | ".join(display)

def money(amount: float, currency: str = "EUR") -> str:
    try:
        v = float(amount)
    except Exception:
        v = 0.0
    return f"{v:.2f} {currency}"
