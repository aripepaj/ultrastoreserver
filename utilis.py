import unicodedata
import json
import os
from datetime import datetime

FAILED_LOG_FILE = "failed_orders.log"

def normalize_city(city_name: str) -> str:
    city_name = city_name.strip().lower()
    city_name = unicodedata.normalize('NFKD', city_name).encode('ASCII', 'ignore').decode('utf-8')
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
    with open(FAILED_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")