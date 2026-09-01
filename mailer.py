"""
mailer.py
=========
Msaidizi wa kutuma BARUA PEPE (Email) kwa ajili ya:
  1. Uthibitisho wa email (Email Verification) baada ya usajili
  2. Kubadilisha password (Password Reset) kwa kutumia email

===========================================================================
MUHIMU KUHUSU RENDER (Free Tier):
Tangu Septemba 2025, Render imezuia (block) KABISA muunganisho wa SMTP
(bandari 25, 465, 587) kwa huduma za bure (free web services) - hata
ukiweka SMTP_HOST/USER/PASSWORD sahihi kabisa, kutuma kutashindikana na
hitilafu "[Errno 101] Network is unreachable". Hii ni sera ya Render
yenyewe, siyo tatizo la usanidi wako. (Chanzo: render.com/changelog)

SULUHISHO (bila kulipa Render): Tumia BREVO (zamani Sendinblue) - hii
inatuma barua pepe kupitia HTTPS API (bandari 443) badala ya SMTP, hivyo
HAIZUILIWI na Render free tier. Brevo ina free tier ya barua pepe 300/siku.
===========================================================================

NJIA A - BREVO (Inapendekezwa kwa Render Free Tier):
Weka Environment Variables:

    BREVO_API_KEY  = xkeysib-xxxxxxxxxxxxxxxxxxxxx   (kutoka Brevo Dashboard
                                                        -> SMTP & API -> API Keys)
    MAIL_FROM      = GariFix Tanzania <yourapp@gmail.com>
                     (barua pepe hii LAZIMA iwe "Verified Sender" kwenye
                      akaunti yako ya Brevo - Senders, Domains & Dedicated IPs)

NJIA B - SMTP ya Kawaida (kwa server ya KULIPIWA / computer yako binafsi -
haitafanya kazi kwenye Render free tier):

    SMTP_HOST      = smtp.gmail.com
    SMTP_PORT      = 587
    SMTP_USER      = yourapp@gmail.com
    SMTP_PASSWORD  = app-password-yako (SIYO password ya kawaida ya Gmail)
    MAIL_FROM      = GariFix Tanzania <yourapp@gmail.com>

Kama BREVO_API_KEY ipo, mfumo utaitumia KWANZA (inafanya kazi kila mahali,
ikiwemo Render free tier). Kama haipo, mfumo utajaribu SMTP ya kawaida.
Kama hakuna hata moja iliyosanidiwa, mfumo UTAENDELEA KUFANYA KAZI KAWAIDA
bila kuvunjika (crash) - itaandika tu ujumbe kwenye logs.
"""

import os
import json
import smtplib
import urllib.request
import urllib.error
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# --- Njia A: Brevo (HTTPS API) ---
BREVO_API_KEY = os.environ.get("BREVO_API_KEY")
BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"

# --- Njia B: SMTP ya kawaida ---
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")

MAIL_FROM = os.environ.get("MAIL_FROM", SMTP_USER or "no-reply@garifix.co.tz")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "").rstrip("/")

_brevo_configured = bool(BREVO_API_KEY)
_smtp_configured = bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD)

if _brevo_configured:
    print("[Mailer] BREVO API IMEWEZESHWA - barua pepe zitatumwa kupitia Brevo (HTTPS)")
elif _smtp_configured:
    print("[Mailer] SMTP IMEWEZESHWA - barua pepe zitatumwa kupitia", SMTP_HOST,
          "(Kumbuka: hii haifanyi kazi kwenye Render FREE tier)")
else:
    print("[Mailer] Hakuna BREVO_API_KEY wala SMTP iliyosanidiwa - "
          "kutuma barua pepe kumezimwa (mfumo utaendelea kufanya kazi kawaida).")


def _parse_mail_from(mail_from):
    """Geuza 'Jina <email@x.com>' kuwa (jina, email) - Brevo inahitaji vitenganishwa."""
    mail_from = (mail_from or "").strip()
    if "<" in mail_from and mail_from.endswith(">"):
        name = mail_from.split("<")[0].strip().strip('"')
        email = mail_from.split("<")[1].rstrip(">").strip()
        return name or "GariFix Tanzania", email
    return "GariFix Tanzania", mail_from


def get_base_url():
    """URL ya msingi ya app (kwa ajili ya kutengeneza link za email)."""
    return APP_BASE_URL


def _send_via_brevo(to_email, subject, html_body, text_body=None):
    sender_name, sender_email = _parse_mail_from(MAIL_FROM)

    payload = {
        "sender": {"name": sender_name, "email": sender_email},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html_body,
    }
    if text_body:
        payload["textContent"] = text_body

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        BREVO_API_URL,
        data=data,
        method="POST",
        headers={
            "accept": "application/json",
            "content-type": "application/json",
            "api-key": BREVO_API_KEY,
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
        return True
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        print(f"[Mailer-ERROR][Brevo] Imeshindikana kutuma kwa {to_email}: "
              f"HTTP {e.code} - {body}")
        return False
    except Exception as e:
        print(f"[Mailer-ERROR][Brevo] Imeshindikana kutuma kwa {to_email}: {e}")
        return False


def _send_via_smtp(to_email, subject, html_body, text_body=None):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = MAIL_FROM
        msg["To"] = to_email

        if text_body:
            msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(MAIL_FROM, [to_email], msg.as_string())

        return True
    except Exception as e:
        print(f"[Mailer-ERROR][SMTP] Imeshindikana kutuma kwa {to_email}: {e}")
        return False


def send_email(to_email, subject, html_body, text_body=None):
    """
    Tuma barua pepe moja. Haivunji programu kama mfumo wa email haijasanidiwa
    au kama kutuma kumeshindikana - inarudisha True/False tu.
    Inajaribu Brevo kwanza (ikiwa imesanidiwa), kisha SMTP ya kawaida.
    """
    if not to_email:
        return False

    if _brevo_configured:
        return _send_via_brevo(to_email, subject, html_body, text_body)

    if _smtp_configured:
        return _send_via_smtp(to_email, subject, html_body, text_body)

    print(f"[Mailer-SKIPPED] Kwa {to_email}: {subject}\n{text_body or html_body}")
    return False


def send_verification_email(user, verify_url):
    subject = "GariFix - Thibitisha Email Yako"
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 480px; margin: auto;">
        <h2 style="color:#0D6EFD;">Karibu GariFix, {user.full_name}!</h2>
        <p>Asante kwa kujisajili. Bofya kitufe hapa chini kuthibitisha barua pepe yako:</p>
        <p style="text-align:center; margin: 24px 0;">
            <a href="{verify_url}" style="background:#0D6EFD;color:#fff;padding:12px 24px;
               border-radius:6px;text-decoration:none;font-weight:bold;">
               Thibitisha Email Yangu
            </a>
        </p>
        <p style="color:#666;font-size:13px;">Kama kitufe hakifanyi kazi, nakili link hii kwenye
        browser yako:<br>{verify_url}</p>
        <p style="color:#999;font-size:12px;">Kama hukujisajili GariFix, puuza email hii.</p>
    </div>
    """
    text_body = f"Karibu {user.full_name}! Thibitisha email yako kwa kufungua link hii: {verify_url}"
    return send_email(user.email, subject, html_body, text_body)


def send_password_reset_email(user, reset_url):
    subject = "GariFix - Badilisha Password Yako"
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 480px; margin: auto;">
        <h2 style="color:#0D6EFD;">Umeomba Kubadilisha Password</h2>
        <p>Habari {user.full_name}, bofya kitufe hapa chini kuweka password mpya
        (link hii itaisha muda baada ya saa 1):</p>
        <p style="text-align:center; margin: 24px 0;">
            <a href="{reset_url}" style="background:#198754;color:#fff;padding:12px 24px;
               border-radius:6px;text-decoration:none;font-weight:bold;">
               Weka Password Mpya
            </a>
        </p>
        <p style="color:#666;font-size:13px;">Kama kitufe hakifanyi kazi, nakili link hii kwenye
        browser yako:<br>{reset_url}</p>
        <p style="color:#999;font-size:12px;">Kama hukuomba kubadilisha password, puuza email hii -
        akaunti yako iko salama.</p>
    </div>
    """
    text_body = f"Habari {user.full_name}, weka password mpya kwa kufungua link hii (inaisha muda baada ya saa 1): {reset_url}"
    return send_email(user.email, subject, html_body, text_body)
