import unicodedata
import json
import sys
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
    entry = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "order_id": order_id,
        "reason": reason
    }
    if extra is not None:
        entry["extra"] = extra
    # Print so it shows in Render logs
    print("[FAILED_ORDER]", json.dumps(entry, ensure_ascii=False), flush=True)
    # Also try to write a file (optional)
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

def extract_address(order: dict) -> str:
    shipping = order.get("shipping_address") or {}
    billing  = order.get("billing_address") or {}
    chosen = shipping if shipping.get("address1") else billing
    addr = chosen.get("address1") or ""
    if chosen.get("address2"): addr += f", {chosen['address2']}"
    if chosen.get("zip"):      addr += f", {chosen['zip']}"
    if chosen.get("city"):     addr += f", {chosen['city']}"
    return addr.strip(", ")
