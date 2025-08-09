from flask import Flask, request, jsonify, abort
from collections import defaultdict
import os

from utilis import (
    log_failed_order,
    normalize_city,
    extract_phone,
    extract_address,
    phone_kosovo_local,   # <- convert +383/00383 to local 0...
    variant_text,         # <- build variant text (size/color/etc.)
    money,                # <- format money with currency
)
from vendor_registry import VendorRegistry
from email_client import send_email
from cheetah_client import get_cheetah_token, add_order_to_cheetah

app = Flask(__name__)
registry = VendorRegistry()

ALWAYS_EMAIL = os.getenv("ALWAYS_EMAIL", "true").lower() == "true"
SHOPIFY_WEBHOOK_SECRET = os.getenv("SHOPIFY_WEBHOOK_SECRET", "")

city_to_id = {
    "prishtina": 1, "prishtine": 1,
    "decan": 2, "deçan": 2, "gjakova": 3, "drenas": 4, "gjilan": 5, "dragash": 6, "istog": 7,
    "kacanik": 8, "kaçanik": 8, "kline": 9, "klinë": 9, "fushe kosove": 10, "fushë kosovë": 10,
    "kamenice": 11, "kamenicë": 11, "leposaviq": 12, "lipjan": 13, "obiliq": 14, "rahovec": 15,
    "peje": 16, "pejë": 16, "podujeve": 17, "podujevë": 17, "prizren": 18, "skenderaj": 19, "skënderaj": 19,
    "shtime": 20, "shterpce": 21, "shtërpcë": 21, "suhareke": 22, "suharekë": 22, "ferizaj": 23, "viti": 24,
    "vushtrri": 25, "zubin potok": 26, "zvecan": 27, "zveçan": 27, "malisheve": 28, "malishevë": 28,
    "novoberde": 29, "novobërdë": 29, "mitrovice": 30, "mitrovicë": 30, "junik": 31, "hani i elezit": 32,
    "mamushe": 33, "mamushë": 33, "gracanice": 34, "graçanicë": 34, "ranillug": 35, "partesh": 36, "kllokot": 37,
    "tirane": 38, "tirana": 38, "durres": 39, "durrës": 39, "shkoder": 40, "shkodër": 40, "elbasan": 41,
    "vlore": 42, "vlorë": 42, "korce": 43, "korçë": 43, "fier": 44, "berat": 45, "lushnje": 46, "pogradec": 47,
    "kavaje": 48, "kavajë": 48, "lac": 49, "laç": 49, "lezhe": 50, "lezhë": 50, "kukes": 51, "kukës": 51,
    "gjirokaster": 52, "gjirokastër": 52, "patos": 53, "kruje": 54, "krujë": 54, "kucove": 55, "kuçovë": 55,
    "sarande": 56, "sarandë": 56, "peshkopi": 57, "burrel": 58, "cerrik": 59, "corovode": 60, "çorovodë": 60,
    "shijak": 61, "librazhd": 62, "tepelene": 63, "gramsh": 64, "polican": 65, "bulqize": 66, "bulqizë": 66,
    "permet": 67, "përmet": 67, "fushe-kruje": 68, "fushë-krujë": 68, "kamez": 69, "kamëz": 69, "rreshen": 70,
    "ballsh": 71, "mamurras": 72, "bajram curri": 73, "erseke": 74, "ersëkë": 74, "peqin": 75, "divjake": 76,
    "divjakë": 76, "selenice": 77, "selenicë": 77, "bilisht": 78, "roskovec": 79, "kelcyre": 80, "kelcyrë": 80,
    "puke": 81, "pukë": 81, "memaliaj": 82, "rrogozhine": 83, "rrogozhinë": 83, "himare": 84, "himarë": 84,
    "delvine": 85, "delvinë": 85, "vore": 86, "vorë": 86, "koplik": 87, "maliq": 88, "perrenjas": 89,
    "shtermeni": 90, "krume": 91, "krumë": 91, "libohove": 92, "libohovë": 92, "orikum": 93, "fushe-arrez": 94,
    "fushë-arrëz": 94, "shengjin": 95, "shëngjin": 95, "rubik": 96, "milot": 97, "leskovik": 98, "konispol": 99,
    "kraste": 100, "kerrabe": 101, "berove": 102, "dellceva": 103, "dellçeva": 103, "kocani": 104, "koçani": 104,
    "kamenica": 105, "peceva": 106, "peçeva": 106, "probishtip": 107, "shtip": 108, "vinica": 109, "kratove": 110,
    "kriva pallanke": 111, "kumanove": 112, "manastir": 113, "demir hisari": 114, "krusheva": 115, "prilep": 116,
    "resnje": 117, "gostivar": 118, "tetove": 119, "tetovë": 119, "shkup": 120, "bogdance": 121, "gjevgjeli": 122,
    "radovishte": 123, "strumica": 124, "vallandova": 125, "diber": 126, "dibër": 126, "kercove": 127, "kërçove": 127,
    "brodi": 128, "oher": 129, "struge": 130, "strugë": 130, "demir kapia": 131, "kavadari": 132, "negotine": 133,
    "sveti nikolle": 134, "veles": 135, "komoran": 137, "bitola": 138, "golaj/has": 139, "dhermi": 140,
}

def _verify_hmac_if_configured():
    if not SHOPIFY_WEBHOOK_SECRET:
        return
    import hmac, hashlib, base64
    raw = request.get_data()
    sig = request.headers.get("X-Shopify-Hmac-Sha256", "")
    digest = base64.b64encode(hmac.new(SHOPIFY_WEBHOOK_SECRET.encode(), raw, hashlib.sha256).digest()).decode()
    if not hmac.compare_digest(digest, sig):
        abort(401)

@app.route("/", methods=["GET"])
def index():
    return "Webhook is up and running!"

@app.route("/webhook", methods=["POST"])
def webhook():
    _verify_hmac_if_configured()
    order = request.get_json(silent=True) or {}
    print("Shopify webhook received order_id:", order.get("id"), flush=True)
    resp = process_order(order)
    return jsonify(resp)

# ---------- payment & pricing helpers ----------

def is_prepaid(order: dict) -> bool:
    """
    True if the order is fully paid online (courier should NOT collect).
    If financial_status == 'paid' and gateway is not COD, treat as prepaid.
    """
    fs = (order.get("financial_status") or "").lower()
    gateways = [str(g).lower() for g in (order.get("payment_gateway_names") or [])]
    if fs == "paid" and not any(("cash on delivery" in g) or ("cod" in g) for g in gateways):
        return True
    return False

def line_effective_price(li: dict) -> float:
    """
    Per-line effective unit price: prefer discounted_price; subtract per-line discount allocations if present.
    """
    try:
        base = float(li.get("discounted_price", li.get("price", 0)) or 0)
    except Exception:
        base = 0.0
    alloc = 0.0
    for d in (li.get("discount_allocations") or []):
        try:
            alloc += float(d.get("amount", 0) or 0)
        except Exception:
            pass
    eff = base - alloc
    return eff if eff > 0 else 0.0

# ---------- core processing ----------

def process_order(order: dict):
    # city
    shipping = order.get("shipping_address") or {}
    city_raw = shipping.get("city", "")
    if not city_raw:
        log_failed_order(order.get("id", "UNKNOWN"), "Missing city", order)
        return {"error": "Missing city"}

    city_norm = normalize_city(city_raw)
    city_id = city_to_id.get(city_norm, 1)
    if city_id == 1 and city_norm not in ("prishtina", "prishtine"):
        log_failed_order(order.get("id", "UNKNOWN"), f"City '{city_raw}' not recognized. Defaulting to Prishtina.")

    # contact info
    billing = order.get("billing_address") or {}
    phone_raw = extract_phone(order)
    phone_for_cheetah = phone_kosovo_local(phone_raw)  # +383/00383 -> 0, strip non-digits
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

    if not phone_for_cheetah:
        log_failed_order(order.get("id","UNKNOWN"), f"No usable phone (raw='{phone_raw}') in Shopify payload", order)

    # group by vendor
    vendor_items = defaultdict(list)
    for it in order.get("line_items", []):
        vendor = (it.get("vendor") or "Unknown").strip()
        if not it.get("quantity"):
            log_failed_order(order.get("id","UNKNOWN"), f"Invalid item data (no quantity): {it}")
            continue
        vendor_items[vendor].append(it)

    if not vendor_items:
        log_failed_order(order.get("id","UNKNOWN"), "No valid vendor items found", order)
        return {"error": "No valid vendor items"}

    token = get_cheetah_token()
    if not token:
        log_failed_order(order.get("id","UNKNOWN"), "Token not received")
        # still email vendors so the partners are notified
        return _email_vendors(order, vendor_items, address, city_id, phone_for_cheetah, first_name, last_name,
                              cheetah_ok=False, cheetah_result={"error": "token"})

    currency = order.get("currency") or "EUR"
    prepaid = is_prepaid(order)

    results = []
    for vendor, items in vendor_items.items():
        # per-vendor subtotal (items only)
        items_total = 0.0
        for it in items:
            qty = int(it.get("quantity", 1) or 1)
            items_total += line_effective_price(it) * qty

        amount_for_courier = 0.0 if prepaid else items_total

        payload = {
            "FullName": f"{first_name} {last_name}",
            "Address": address,
            "IDCity": str(city_id),
            "Phone": phone_for_cheetah or "",
            "Amount": f"{amount_for_courier:.2f}",
            "Comment": f"Shopify Order ID: {order.get('id','UNKNOWN')} | {'PREPAID' if prepaid else 'COD'} | raw phone: {phone_raw or 'N/A'}",
            "ShipmentPackage": 1,
            "CanOpen": False,
            "Description": f"Vendor: {vendor}",
            "Fragile": True,
            "Declared": True
        }

        ok, cheetah_result = add_order_to_cheetah(token, payload)
        print(f"[CHEETAH] vendor={vendor} ok={ok} result={cheetah_result}", flush=True)
        results.append({"vendor": vendor, "cheetah": cheetah_result})

        # Email per vendor; guard so one vendor can't crash the whole request
        try:
            if ok or ALWAYS_EMAIL:
                email_info = _email_one_vendor(order, vendor, items, first_name, last_name, address,
                                               phone_for_cheetah, city_id, cheetah_result,
                                               prepaid=prepaid, items_total=items_total, currency=currency,
                                               amount_for_courier=amount_for_courier)
                if email_info:
                    results.append({"vendor": vendor, "email": email_info})
            else:
                log_failed_order(order.get("id","UNKNOWN"), "Cheetah add order failed", cheetah_result)
        except Exception as e:
            log_failed_order(order.get("id","UNKNOWN"), f"Email build/send failed for vendor '{vendor}': {e}")

    return results

def _email_vendors(order, vendor_items, address, city_id, phone, first_name, last_name, cheetah_ok, cheetah_result):
    results = []
    currency = order.get("currency") or "EUR"
    prepaid = is_prepaid(order)
    for vendor, items in vendor_items.items():
        items_total = 0.0
        for it in items:
            qty = int(it.get("quantity", 1) or 1)
            items_total += line_effective_price(it) * qty
        amount_for_courier = 0.0 if prepaid else items_total
        try:
            info = _email_one_vendor(order, vendor, items, first_name, last_name, address, phone, city_id,
                                     cheetah_result if cheetah_ok else {"error":"no cheetah"},
                                     prepaid=prepaid, items_total=items_total, currency=currency,
                                     amount_for_courier=amount_for_courier)
            if info:
                results.append({"vendor": vendor, "email": info})
        except Exception as e:
            log_failed_order(order.get("id","UNKNOWN"), f"Email build/send failed for vendor '{vendor}': {e}")
    return results

def _email_one_vendor(order, vendor, items, first_name, last_name, address, phone, city_id, cheetah_result,
                      prepaid=False, items_total=0.0, currency="EUR", amount_for_courier=0.0):
    # Shipment #
    shipment_no = (
        (cheetah_result or {}).get("ShipmentNumber")
        or (cheetah_result or {}).get("ID")
        or (cheetah_result or {}).get("OrderNo")
        or "N/A"
    )
    badge = "PREPAID" if prepaid else "COD"
    badge_color = "#0d6efd" if prepaid else "#dc3545"

    # Build lines for text + HTML (variant details & line totals). No images.
    lines_txt = []
    rows_html = []
    for it in items:
        sku = it.get("sku") or ""
        title = it.get("title", "Unknown")
        qty = int(it.get("quantity", 1) or 1)
        unit = line_effective_price(it)
        line_total = unit * qty
        variant = variant_text(it)  # e.g., "Size: M | Color: Black"

        # text line
        parts = [title]
        if variant: parts.append(f"[{variant}]")
        if sku: parts.append(f"(SKU: {sku})")
        parts.append(f"x{qty} @ {money(unit, currency)} = {money(line_total, currency)}")
        lines_txt.append("- " + " ".join(parts))

        # HTML row (no image column)
        def safe(s): return (s or "").replace("<","&lt;").replace(">","&gt;")
        rows_html.append(f"""
          <tr>
            <td style="padding:8px;border:1px solid #eee;vertical-align:top">
              <div style="font-weight:600">{safe(title)}</div>
              {f'<div style="color:#555"><small>{safe(variant)}</small></div>' if variant else ''}
              {f'<div style="color:#666"><small>SKU: {safe(sku)}</small></div>' if sku else ''}
            </td>
            <td style="padding:8px;border:1px solid #eee;vertical-align:top">{qty}</td>
            <td style="padding:8px;border:1px solid #eee;vertical-align:top">{money(unit, currency)}</td>
            <td style="padding:8px;border:1px solid #eee;vertical-align:top">{money(line_total, currency)}</td>
          </tr>
        """)

    order_id = order.get("id", "UNKNOWN")

    # Subject + bodies
    subject = f"[New Shipment] {vendor} | {badge} | Order {order_id} | Cheetah #{shipment_no}"
    body_text = (
        f"Vendor: {vendor}\n"
        f"Shopify Order ID: {order_id}\n"
        f"Cheetah Shipment No: {shipment_no}\n"
        f"City ID (Cheetah): {city_id}\n"
        f"Payment: {badge}\n"
        f"Vendor Subtotal: {money(items_total, currency)}\n"
        f"Amount to Collect: {money(amount_for_courier, currency)}\n\n"
        f"Customer:\n"
        f"  {first_name} {last_name}\n"
        f"  {address}\n"
        f"  Phone: {phone or 'N/A'}\n\n"
        f"Items:\n" + "\n".join(lines_txt)
    )

    items_table = f"""
      <table cellpadding="0" cellspacing="0" style="border-collapse:collapse;width:100%;font-family:Arial,sans-serif;font-size:14px">
        <thead>
          <tr>
            <th style="text-align:left;padding:8px;border-bottom:2px solid #ddd;">Item / Variant / SKU</th>
            <th style="text-align:left;padding:8px;border-bottom:2px solid #ddd;">Qty</th>
            <th style="text-align:left;padding:8px;border-bottom:2px solid #ddd;">Unit</th>
            <th style="text-align:left;padding:8px;border-bottom:2px solid #ddd;">Line Total</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows_html)}
        </tbody>
      </table>
    """
    body_html = f"""
      <div style="font-family:Arial,Helvetica,sans-serif;color:#222;font-size:14px;line-height:1.45">
        <h2 style="margin:0 0 8px 0;">New Shipment – {vendor}</h2>
        <div style="margin:0 0 10px 0;">
          <span style="display:inline-block;padding:4px 8px;border-radius:6px;background:{badge_color};color:#fff;font-weight:600;">
            {badge}
          </span>
        </div>
        <p style="margin:0 0 10px 0">
          <b>Shopify Order:</b> {order_id}<br>
          <b>Cheetah Shipment No:</b> {shipment_no}<br>
          <b>City ID (Cheetah):</b> {city_id}<br>
          <b>Vendor Subtotal:</b> {money(items_total, currency)}<br>
          <b>Amount to Collect:</b> {money(amount_for_courier, currency)}
        </p>

        <h3 style="margin:16px 0 8px 0;">Customer</h3>
        <p style="margin:0 0 10px 0;">
          {first_name} {last_name}<br>
          {address}<br>
          Phone: {phone or 'N/A'}
        </p>

        <h3 style="margin:16px 0 8px 0;">Items</h3>
        {items_table}
      </div>
    """

    recipients = registry.recipients_for(vendor)
    print(f"[EMAIL] vendor='{vendor}' recipients={recipients}", flush=True)
    if not recipients:
        log_failed_order(order_id, f"No partner email configured for vendor='{vendor}'")
        return None

    email_res = send_email(
        recipients,
        subject,
        body_text,
        body_html=body_html,
        order_id=order_id
    )
    print(f"[EMAIL][RESULT] vendor='{vendor}' res={email_res}", flush=True)
    return email_res

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
