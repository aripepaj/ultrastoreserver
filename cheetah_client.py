import os
import requests
from utilis import log_failed_order

CHEETAH_USERNAME = os.getenv("CHEETAH_USERNAME")
CHEETAH_PASSWORD = os.getenv("CHEETAH_PASSWORD")

def get_cheetah_token():
    url = "https://postacheetah.com/token"
    data = {
        "username": CHEETAH_USERNAME,
        "password": CHEETAH_PASSWORD,
        "grant_type": "password"
    }
    resp = requests.post(url, data=data, timeout=20)
    try:
        j = resp.json()
    except Exception:
        log_failed_order("UNKNOWN", "Cheetah token parse error", resp.text)
        return None
    return j.get("access_token")

def add_order_to_cheetah(token, payload):
    headers = {"Authorization": f"Bearer {token}"}
    url = "https://postacheetah.com/api/PostaAPI/AddOrder"
    r = requests.post(url, json=payload, headers=headers, timeout=20)
    try:
        result = r.json()
    except Exception:
        result = {"raw": r.text}
    success = r.ok and not (isinstance(result, dict) and result.get("error"))
    return success, result