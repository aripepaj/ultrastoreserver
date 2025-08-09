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

# ---- Phone formatting helpers ----

def phone_kosovo_local(phone: str) -> str:
    """
    +38344xxxxxx  -> 044xxxxxx
    0038344xxxxxx -> 044xxxxxx
    Otherwise: strip all non-digits.
    """
    if not phone:
        return ""
    p = str(phone).strip().replace(" ", "")
    if p.startswith("+383"):
        return "0" + re.sub(r"\D", "", p[4:])
    if p.startswith("00383"):
        return "0" + re.sub(r"\D", "", p[5:])
    return re.sub(r"\D", "", p)

def phone_international(phone: str) -> str:
    """
    Return +383######### (digits, with a single leading +) if phone looks like Kosovo.
    Otherwise best-effort +digits.
    """
    if not phone:
        return ""
    digits = re.sub(r"\D", "", str(phone))
    # If it already starts with 383..., keep it, else try to detect 0-leading local and convert.
    if digits.startswith("383"):
        return "+" + digits
    if digits.startswith("0"):
        # assume local Kosovo mobile/landline, drop leading 0 and prepend country code
        return "+383" + digits[1:]
    # fallback
    return "+" + digits

def phone_digits_only(phone: str) -> str:
    return re.sub(r"\D", "", str(phone or ""))

def format_phone_for_cheetah(raw: str, mode: str) -> str:
    """
    mode: 'local' (default), 'intl', or 'digits'
    """
    if not raw:
        return ""
    mode = (mode or "local").strip().lower()
    if mode == "intl":
        formatted = phone_international(raw)
    elif mode == "digits":
        formatted = phone_digits_only(raw)
    else:
        formatted = phone_kosovo_local(raw)
    print(f"[PHONE] mode='{mode}' raw='{raw}' -> '{formatted}'", flush=True)
    return formatted

# ---- Address & Variant helpers ----

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

# ---- Pricing (qty-aware, discount-aware) ----

def line_total_amount(li: dict) -> float:
    """
    Robust per-line TOTAL:
      total = unit_price * qty  -  line_discounts
    Prefers discount_allocations; falls back to total_discount.
    """
    try:
        qty = int(li.get("quantity", 1) or 1)
    except Exception:
        qty = 1

    # Shopify line_item.price is the UNIT price before discounts
    try:
        unit = float(li.get("price", 0) or 0)
    except Exception:
        unit = 0.0

    total = unit * qty

    # Prefer discount_allocations (per-line)
    alloc = 0.0
    for d in (li.get("discount_allocations") or []):
        try:
            alloc += float(d.get("amount", 0) or 0)
        except Exception:
            pass

    if alloc <= 0:
        # fallback: total_discount (string)
        try:
            alloc = float(li.get("total_discount", 0) or 0)
        except Exception:
            alloc = 0.0

    total -= alloc
    if total < 0:
        total = 0.0
    return total

def unit_effective_price(li: dict) -> float:
    """Unit price AFTER discounts = line_total / qty."""
    try:
        qty = int(li.get("quantity", 1) or 1)
    except Exception:
        qty = 1
    total = line_total_amount(li)
    return (total / qty) if qty > 0 else 0.0
