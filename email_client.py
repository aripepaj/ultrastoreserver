import os
import requests
from utilis import log_failed_order

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
MAIL_FROM = os.getenv("MAIL_FROM", "no-reply@yourdomain.com")
MAIL_FROM_NAME = os.getenv("MAIL_FROM_NAME", "Orders Bot")
MAIL_BCC = os.getenv("MAIL_BCC")  # optional
REPLY_TO = os.getenv("REPLY_TO")  # optional, e.g. orders@ultrastore-ks.com

def send_email(to_emails, subject, body_text, order_id="UNKNOWN"):
    if not SENDGRID_API_KEY:
        log_failed_order(order_id, "Missing SENDGRID_API_KEY for email")
        return {"error": "Email not configured"}

    # Normalize & de-duplicate TO recipients (case-insensitive)
    raw = to_emails if isinstance(to_emails, list) else [to_emails]
    seen = set()
    to_list = []
    for e in raw:
        if not e:
            continue
        k = e.strip().lower()
        if k not in seen:
            seen.add(k)
            to_list.append({"email": e.strip()})

    personalizations = [{"to": to_list}]

    # Only add BCC if present and NOT already in TO
    if MAIL_BCC:
        bcc_addr = MAIL_BCC.strip()
        if bcc_addr.lower() not in {x["email"].lower() for x in to_list}:
            personalizations[0]["bcc"] = [{"email": bcc_addr}]

    payload = {
        "from": {"email": MAIL_FROM, "name": MAIL_FROM_NAME},
        "subject": subject,
        "personalizations": personalizations,
        "content": [{"type": "text/plain", "value": body_text}]
    }

    if REPLY_TO:
        payload["reply_to"] = {"email": REPLY_TO}

    headers = {"Authorization": f"Bearer {SENDGRID_API_KEY}", "Content-Type": "application/json"}
    try:
        r = requests.post("https://api.sendgrid.com/v3/mail/send", headers=headers, json=payload, timeout=15)
    except Exception as e:
        log_failed_order(order_id, f"SendGrid request exception: {e}")
        return {"error": str(e)}

    if r.status_code >= 300:
        log_failed_order(order_id, f"SendGrid error {r.status_code}", r.text)
        return {"error": f"SendGrid {r.status_code}", "body": r.text}
    return {"ok": True}