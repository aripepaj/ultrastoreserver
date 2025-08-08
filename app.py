from flask import Flask, request, jsonify, abort
from collections import defaultdict
import os

from utilis import (
    log_failed_order,
    normalize_city,
    extract_phone,
    extract_address,
)
from vendor_registry import VendorRegistry
from email_client import send_email
from cheetah_client import get_cheetah_token, add_order_to_cheetah

app = Flask(__name__)
registry = VendorRegistry()

ALWAYS_EMAIL = os.getenv("ALWAYS_EMAIL", "true").lower() == "true"  # email even if cheetah fails (good for debugging)

# Optional HMAC verification for Shopify (recommended)
SHOPIFY_WEBHOOK_SECRET = os.getenv("SHOPIFY_WEBHOOK_SECRET", "")

city_to_id = {
    "prishtina": 1, "decan": 2, "deçan": 2, "gjakova": 3, "drenas": 4, "gjilan": 5, "dragash": 6, "istog": 7,
    "kacanik": 8, "kaçanik": 8, "kline": 9, "klinë": 9, "fushe kosove": 10, "fushë kosovë": 10, "kamenice": 11,
    "kamenicë": 11, "leposaviq": 12, "lipjan": 13, "obiliq": 14, "rahovec": 15, "peje": 16, "pejë": 16,
    "podujeve": 17, "podujevë": 17, "prizren": 18, "skenderaj": 19, "skënderaj": 19, "shtime": 20, "shterpce": 21,
    "shtërpcë": 21, "suhareke": 22, "suharekë": 22, "ferizaj": 23, "viti": 24, "vushtrri": 25, "zubin potok": 26,
    "zvecan": 27, "zveçan": 27, "malisheve": 28, "malishevë": 28, "novoberde": 29, "novobërdë": 29, "mitrovice": 30,
    "mitrovicë": 30, "junik": 31, "hani i elezit": 32, "mamushe": 33, "mamushë": 33, "gracanice": 34, "graçanicë": 34,
    "ranillug": 35, "partesh": 36, "kllokot": 37, "tirane": 38, "tirana": 38, "durres": 39, "durrës": 39,
    "shkoder": 40, "shkodër": 40, "elbasan": 41, "vlore": 42, "vlorë": 42, "korce": 43, "korçë": 43, "fier": 44,
    "berat": 45, "lushnje": 46, "pogradec": 47, "kavaje": 48, "kavajë": 48, "lac": 49, "laç": 49, "lezhe": 50,
    "lezhë": 50, "kukes": 51, "kukës": 51, "gjirokaster": 52, "gjirokastër": 52, "patos": 53, "kruje": 54, "krujë": 54,
    "kucove": 55, "kuçovë": 55, "sarande": 56, "sarandë": 56, "peshkopi": 57, "burrel": 58, "cerrik": 59,
    "corovode": 60, "çorovodë": 60, "shijak": 61, "librazhd": 62, "tepelene": 63, "gramsh": 64, "polican": 65,
    "bulqize": 66, "bulqizë": 66, "permet": 67, "përmet": 67, "fushe-kruje": 68, "fushë-krujë": 68, "kamez": 69,
    "kamëz": 69, "rreshen": 70, "ballsh": 71, "mamurras": 72, "bajram curri": 73, "erseke": 74, "ersëkë": 74,
    "peqin": 75, "divjake": 76, "divjakë": 76, "selenice": 77, "selenicë": 77, "bilisht": 78, "roskovec": 79,
    "kelcyre": 80, "kelcyrë": 80, "puke": 81, "pukë": 81, "memaliaj": 82, "rrogozhine": 83, "rrogozhinë": 83,
    "himare": 84, "himarë": 84, "delvine": 85, "delvinë": 85, "vore": 86, "vorë": 86, "koplik": 87, "maliq": 88,
    "perrenjas": 89, "shtermeni": 90, "krume": 91, "krumë": 91, "libohove": 92, "libohovë": 92, "orikum": 93,
    "fushe-arrez": 94, "fushë-arrëz": 94, "shengjin": 95, "shëngjin": 95, "rubik": 96, "milot": 97, "leskovik": 98,
    "konispol": 99, "kraste": 100, "kerrabe": 101, "berove": 102, "dellceva": 103, "dellçeva": 103, "kocani": 104,
    "koçani": 104, "kamenica": 105, "peceva": 106, "peçeva": 106, "probishtip": 107, "shtip": 108, "vinica": 109,
    "kratove": 110, "kriva pallanke": 111, "kumanove": 112, "manastir": 113, "demir hisari": 114, "krusheva": 115,
    "prilep": 116, "resnje": 117, "gostivar": 118, "tetove": 119, "tetovë": 119, "shkup": 120, "bogdance": 121,
    "gjevgjeli": 122, "radovishte": 123, "strumica": 124, "vallandova": 125, "diber": 126, "dibër": 126,
    "kercove": 127, "kërçove": 127, "brodi": 128, "oher": 129, "struge": 130, "strugë": 130, "demir kapia": 131,
    "kavadari": 132, "negotine": 133, "sveti nikolle": 134, "veles": 135, "komoran": 137, "bitola": 138,
    "golaj/has": 139, "dhermi": 140,
}

@app.route("/", methods=["GET"])
def index():
    return "Webhook is up and running!"

def _verify_hmac_if_configured():
    if not SHOPIFY_WEBHOOK_SECRET:
        return
    import hmac, hashlib, base64
    raw = request.get_data()
    sig = request.headers.get("X-Shopify-Hmac-Sha256", "")
    digest = base64.b64encode(hmac.new(SHOPIFY_WEBHOOK_SECRET.encode(), raw, hashlib.sha256).digest()).decode()
    if not hmac.compare_digest(digest, sig):
        abort(401)

@app.route("/webhook", methods=["POST"])
def webhook():
    _verify_hmac_if_configured()
    order = request.get_json(silent=True) or {}
    print("Shopify webhook received order_id:", order.get("id"), flush=True)
    resp = process_order(order)
    return jsonify(resp)

def process_order(order: dict):
    # --- city ---
    shipping = order.get("shipping_address") or {}
    city_raw = shipping.get("city", "")
    if not city_raw:
        log_failed_order(order.get("id", "UNKNOWN"), "Missing city", order)
        return {"error": "Missing city"}

    city_norm = normalize_city(city_raw)
    city_id = city_to_id.get(city_norm, 1)
    if city_id == 1 and city_norm != "prishtina":
        log_failed_order(order.get("id", "UNKNOWN"), f"City '{city_raw}' not recognized. Defaulting to Prishtina.")

    # --- contact info ---
    billing = order.get("billing_address") or {}
    phone = extract_phone(order)
    address = extract_address(order)
    first_name = shipping.get("first_name") or billing.get("first_name")
    last_name  = shipping.get("last_name")  or billing.get("last_name")

    missing = []
    if not address: missing.append("address")
    if not first_name: missing.append("first_name")
    if not last_name: missing.append("last_name")
    if missing:
        log_failed_order(order.get("id","UNKNOWN"), f"Missing contact info: {', '.join(missing)}", order)
        return {"error": "Incomplete shipping/contact information"}

    if not phone:
        # Don’t block the flow; log and let Cheetah validate.
        log_failed_order(order.get("id","UNKNOWN"), "No phone found in Shopify payload", order)

    # --- group items by vendor ---
    vendor_items = defaultdict(list)
    for it in order.get("line_items", []):
        vendor = (it.get("vendor") or "Unknown").strip()
        if not it.get("price") or not it.get("quantity"):
            log_failed_order(order.get("id","UNKNOWN"), f"Invalid item data: {it}")
            continue
        vendor_items[vendor].append(it)

    if not vendor_items:
        log_failed_order(order.get("id","UNKNOWN"), "No valid vendor items found", order)
        return {"error": "No valid vendor items"}

    # --- token (get once) ---
    token = get_cheetah_token()
    if not token:
        log_failed_order(order.get("id","UNKNOWN"), "Token not received")
        # Still email vendors so someone sees it
        return _email_vendors(order, vendor_items, address, city_id, phone, first_name, last_name, cheetah_ok=False, cheetah_result={"error":"token"})

    # --- per vendor ---
    results = []
    for vendor, items in vendor_items.items():
        total_price = sum(float(it.get("price", 0)) * it.get("quantity", 1) for it in items)
        payload = {
            "FullName": f"{first_name} {last_name}",
            "Address": address,
            "IDCity": str(city_id),
            "Phone": phone,
            "Amount": f"{total_price:.2f}",
            "Comment": f"Shopify Order ID: {order.get('id','UNKNOWN')}",
            "ShipmentPackage": 1,
            "CanOpen": False,
            "Description": f"Vendor: {vendor}",
            "Fragile": True,
            "Declared": True
        }

        ok, cheetah_result = add_order_to_cheetah(token, payload)
        print(f"[CHEETAH] vendor={vendor} ok={ok} result={cheetah_result}", flush=True)
        results.append({"vendor": vendor, "cheetah": cheetah_result})

        # Email only if Cheetah ok, unless ALWAYS_EMAIL=true
        if ok or ALWAYS_EMAIL:
            email_info = _email_one_vendor(order, vendor, items, first_name, last_name, address, phone, city_id, cheetah_result)
            if email_info:
                results.append({"vendor": vendor, "email": email_info})
        else:
            log_failed_order(order.get("id","UNKNOWN"), "Cheetah add order failed", cheetah_result)

    return results

def _email_vendors(order, vendor_items, address, city_id, phone, first_name, last_name, cheetah_ok, cheetah_result):
    results = []
    for vendor, items in vendor_items.items():
        info = _email_one_vendor(order, vendor, items, first_name, last_name, address, phone, city_id, cheetah_result if cheetah_ok else {"error":"no cheetah"})
        if info:
            results.append({"vendor": vendor, "email": info})
    return results

def _email_one_vendor(order, vendor, items, first_name, last_name, address, phone, city_id, cheetah_result):
    # derive shipment number if present
    shipment_no = (
        (cheetah_result or {}).get("ShipmentNumber")
        or (cheetah_result or {}).get("ID")
        or (cheetah_result or {}).get("OrderNo")
        or "N/A"
    )

    # email body
    lines = []
    for it in items:
        sku = it.get("sku") or ""
        title = it.get("title", "Unknown")
        qty = it.get("quantity", 1)
        price = it.get("price", 0)
        lines.append(f"- {title}{f' ({sku})' if sku else ''} x{qty} @ {price}")

    subject = f"[New Shipment] {vendor} | Order {order.get('id','UNKNOWN')} | Cheetah #{shipment_no}"
    body = (
        f"Vendor: {vendor}\n"
        f"Shopify Order ID: {order.get('id','UNKNOWN')}\n"
        f"Cheetah Shipment No: {shipment_no}\n"
        f"City ID (Cheetah): {city_id}\n\n"
        f"Customer:\n"
        f"  {first_name} {last_name}\n"
        f"  {address}\n"
        f"  Phone: {phone or 'N/A'}\n\n"
        f"Items:\n" + "\n".join(lines)
    )

    recipients = registry.recipients_for(vendor)
    print(f"[EMAIL] vendor='{vendor}' recipients={recipients}", flush=True)
    if not recipients:
        log_failed_order(order.get("id","UNKNOWN"), f"No partner email configured for vendor='{vendor}'")
        return None

    email_res = send_email(recipients, subject, body, order_id=order.get("id","UNKNOWN"))
    print(f"[EMAIL][RESULT] vendor='{vendor}' res={email_res}", flush=True)
    return email_res

if __name__ == "__main__":
    # Let Render set $PORT. Default to 8000 locally.
    port = int(os.getenv("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
