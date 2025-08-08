import os
import requests
from utilis import log_failed_order

CHEETAH_USERNAME = os.getenv("CHEETAH_USERNAME")
CHEETAH_PASSWORD = os.getenv("CHEETAH_PASSWORD")

def get_cheetah_token():
    url = "https://postacheetah.com/token"
    data = {"username": CHEETAH_USERNAME, "password": CHEETAH_PASSWORD, "grant_type": "password"}
    try:
        resp = requests.post(url, data=data, timeout=20)
    except Exception as e:
        log_failed_order("UNKNOWN", f"Cheetah token request exception: {e}")
        return None
    try:
        j = resp.json()
    except Exception:
        log_failed_order("UNKNOWN", "Cheetah token parse error", resp.text)
        return None
    token = j.get("access_token")
    if not resp.ok or not token:
        log_failed_order("UNKNOWN", f"Cheetah token not ok status={resp.status_code}", j)
        return None
    return token

def add_order_to_cheetah(token, payload):
    headers = {"Authorization": f"Bearer {token}"}
    url = "https://postacheetah.com/api/PostaAPI/AddOrder"
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=20)
    except Exception as e:
        log_failed_order(payload.get("Comment","UNKNOWN"), f"Cheetah AddOrder exception: {e}", payload)
        return False, {"error": str(e)}
    try:
        result = r.json()
    except Exception:
        result = {"raw": r.text}
    result["_http_status"] = r.status_code
    success = r.ok and not (isinstance(result, dict) and result.get("error"))
    if not success:
        log_failed_order(payload.get("Comment","UNKNOWN"), "Cheetah add order failed", result)
    return success, result
