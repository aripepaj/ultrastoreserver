import os
import requests
from utilis import log_failed_order

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
MAIL_FROM = os.getenv("MAIL_FROM", "no-reply@ultrastore-ks.com")
MAIL_BCC = os.getenv("MAIL_BCC")  # optional

def send_email(to_emails, subject, body_text, order_id="UNKNOWN"):
    if not SENDGRID_API_KEY:
        log_failed_order(order_id, "Missing SENDGRID_API_KEY for email")
        return {"error": "Email not configured"}

    sg_url = "https://api.sendgrid.com/v3/mail/send"
    headers = {"Authorization": f"Bearer {SENDGRID_API_KEY}", "Content-Type": "application/json"}

    to_list = [{"email": e} for e in (to_emails if isinstance(to_emails, list) else [to_emails])]
    personalizations = [{"to": to_list}]
    if MAIL_BCC:
        personalizations[0]["bcc"] = [{"email": MAIL_BCC}]

    payload = {
        "from": {"email": MAIL_FROM, "name": "Orders Bot"},
        "subject": subject,
        "personalizations": personalizations,
        "content": [{"type": "text/plain", "value": body_text}]
    }

    r = requests.post(sg_url, headers=headers, json=payload, timeout=15)
    if r.status_code >= 300:
        log_failed_order(order_id, f"SendGrid error {r.status_code}", r.text)
        return {"error": f"SendGrid {r.status_code}", "body": r.text}
    return {"ok": True}