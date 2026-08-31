"""
mailer.py
=========
Msaidizi wa kutuma BARUA PEPE (Email) kwa ajili ya:
  1. Uthibitisho wa email (Email Verification) baada ya usajili
  2. Kubadilisha password (Password Reset) kwa kutumia email

JINSI YA KUWEZESHA (SETUP) - Kwenye Render (au server yako):
Weka Environment Variables zifuatazo:

    SMTP_HOST      = smtp.gmail.com          (mfano ukitumia Gmail)
    SMTP_PORT      = 587
    SMTP_USER      = yourapp@gmail.com
    SMTP_PASSWORD  = app-password-yako        (SIYO password ya kawaida ya Gmail -
                                                tengeneza "App Password" kwenye
                                                Google Account Security settings)
    MAIL_FROM      = GariFix Tanzania <yourapp@gmail.com>   (hiari)
    APP_BASE_URL   = https://garifix.onrender.com            (bila "/" mwishoni -
                                                                inatumika kutengeneza
                                                                link za email)

Kama huna Gmail App Password, unaweza kutumia huduma nyingine yoyote ya SMTP
(SendGrid, Mailgun, Brevo/Sendinblue - zote zina free tier) - ingiza tu
SMTP_HOST/PORT/USER/PASSWORD wanazokupa.

Kama HUJAWEKA hizi env variables, mfumo UTAENDELEA KUFANYA KAZI KAWAIDA -
send_email() itaandika tu ujumbe kwenye console/logs badala ya kuvunja
(crash) app nzima, na usajili/reset password bado vitafanya kazi (mtumiaji
ataona ujumbe akijulishwa kuwa email haikutumwa).
"""

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
MAIL_FROM = os.environ.get("MAIL_FROM", SMTP_USER or "no-reply@garifix.co.tz")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "").rstrip("/")

_mail_configured = bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD)

if _mail_configured:
    print("[Mailer] SMTP IMEWEZESHWA - barua pepe zitatumwa kupitia", SMTP_HOST)
else:
    print("[Mailer] SMTP_HOST/SMTP_USER/SMTP_PASSWORD hazijawekwa - "
          "kutuma barua pepe kumezimwa (mfumo utaendelea kufanya kazi kawaida).")


def get_base_url():
    """URL ya msingi ya app (kwa ajili ya kutengeneza link za email)."""
    return APP_BASE_URL


def send_email(to_email, subject, html_body, text_body=None):
    """
    Tuma barua pepe moja. Haivunji programu kama SMTP haijasanidiwa au
    kama kutuma kumeshindikana - inarudisha True/False tu.
    """
    if not to_email:
        return False

    if not _mail_configured:
        print(f"[Mailer-SKIPPED] Kwa {to_email}: {subject}\n{text_body or html_body}")
        return False

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
        print(f"[Mailer-ERROR] Imeshindikana kutuma kwa {to_email}: {e}")
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
