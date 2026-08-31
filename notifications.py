"""
notifications.py
=================
Msaidizi wa kutuma PUSH NOTIFICATIONS kwenda kwenye App ya Android (GariFix)
kwa kutumia Firebase Cloud Messaging (FCM).

JINSI YA KUWEZESHA (SETUP):
1. Fungua https://console.firebase.google.com na tengeneza mradi (project) mpya
   bure kwa jina "GariFix" (au jina lolote).
2. Kwenye Project Settings -> Service Accounts -> "Generate new private key".
   Hii itapakua faili la JSON (mfano: garifix-firebase-adminsdk.json).
3. Weka faili hilo ndani ya folder la mradi huu (Flask) - PENDEKEZO: liite
   "firebase-credentials.json" na LISIWEKE kwenye git (tayari liko kwenye
   .gitignore).
4. Weka environment variable kwenye server yako (au faili la .env):
       FIREBASE_CREDENTIALS_PATH=firebase-credentials.json
5. Sakinisha maktaba (library) inayohitajika:
       pip install firebase-admin

Kama hujafanya usanidi huu bado, mfumo UTAENDELEA KUFANYA KAZI KAWAIDA -
send_notification() itakosa kutuma push notification kimya kimya (itaandika
tu ujumbe kwenye console/logs) badala ya kuvunja (crash) app nzima.
"""

import os

_firebase_app = None
_firebase_available = False

try:
    import firebase_admin
    from firebase_admin import credentials, messaging

    cred_path = os.environ.get("FIREBASE_CREDENTIALS_PATH")
    if cred_path and os.path.exists(cred_path):
        cred = credentials.Certificate(cred_path)
        _firebase_app = firebase_admin.initialize_app(cred)
        _firebase_available = True
        print("[Notifications] Firebase Cloud Messaging IMEWEZESHWA.")
    else:
        print("[Notifications] FIREBASE_CREDENTIALS_PATH haijawekwa - "
              "push notifications zimezimwa (mfumo utaendelea kufanya kazi kawaida).")
except ImportError:
    print("[Notifications] Package 'firebase-admin' haijasakinishwa - "
          "push notifications zimezimwa. Andika: pip install firebase-admin")
except Exception as e:
    print(f"[Notifications] Kosa la kuwezesha Firebase: {e}")


def send_notification(user, title, body, data=None):
    """
    Tuma push notification kwa mtumiaji mmoja (User) mwenye fcm_token.
    Haifanyi chochote (bila hitilafu) kama Firebase haijawezeshwa au
    mtumiaji hana fcm_token bado (yaani hajawahi kufungua App ya Android).
    """
    if not _firebase_available:
        print(f"[Notification-SKIPPED] Kwa {getattr(user, 'full_name', '?')}: {title} - {body}")
        return False

    if not user or not user.fcm_token:
        return False

    try:
        message = messaging.Message(
            notification=messaging.Notification(title=title, body=body),
            data={k: str(v) for k, v in (data or {}).items()},
            token=user.fcm_token,
        )
        messaging.send(message)
        return True
    except Exception as e:
        print(f"[Notification-ERROR] Imeshindikana kutuma kwa {user.full_name}: {e}")
        return False
