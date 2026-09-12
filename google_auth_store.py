# google_auth_store.py
"""Huhifadhi tokens za muda za Google login (njia ya App) kwenye DATABASE
badala ya kumbukumbu ya Python.

SABABU: dictionary ya kawaida inapotea kila Render inapoanzisha upya
service au inapolala (free tier). Ikitokea hivyo kati ya mtumiaji
kubonyeza Google na kurudi kwenye app, token yake inakuwa haipo tena -
na anarudishwa /login bila sababu yoyote inayoonekana."""

from datetime import datetime, timedelta
from extensions import db

PENDING_TOKEN_TTL_SECONDS = 300  # dakika 5


class PendingGoogleAuth(db.Model):
    __tablename__ = "pending_google_auth"

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    action = db.Column(db.String(20), nullable=False)   # login | register | not_registered
    user_id = db.Column(db.Integer, nullable=True)
    email = db.Column(db.String(255), nullable=True)
    name = db.Column(db.String(255), nullable=True)
    role = db.Column(db.String(20), nullable=True)
    expires_at = db.Column(db.DateTime, nullable=False)


def save_pending_google_auth(token, data):
    """Hifadhi token pamoja na taarifa zake. Inarudisha True/False."""
    try:
        db.session.query(PendingGoogleAuth).filter(
            PendingGoogleAuth.expires_at < datetime.utcnow()
        ).delete(synchronize_session=False)

        db.session.add(PendingGoogleAuth(
            token=token,
            action=data.get("action"),
            user_id=data.get("user_id"),
            email=data.get("email"),
            name=data.get("name"),
            role=data.get("role"),
            expires_at=datetime.utcnow() + timedelta(seconds=PENDING_TOKEN_TTL_SECONDS),
        ))
        db.session.commit()
        return True
    except Exception as exc:
        db.session.rollback()
        print(f"[GoogleAuthStore] Imeshindikana kuhifadhi token: {exc}")
        return False


def pop_pending_google_auth(token):
    """Chukua taarifa za token MARA MOJA TU kisha ifute. Inarudisha dict
    au None (kama haipo au muda umeisha)."""
    if not token:
        return None
    try:
        row = PendingGoogleAuth.query.filter_by(token=token).first()
        if not row:
            return None

        expired = row.expires_at < datetime.utcnow()
        data = {
            "action": row.action,
            "user_id": row.user_id,
            "email": row.email,
            "name": row.name,
            "role": row.role,
        }

        db.session.delete(row)
        db.session.commit()

        return None if expired else data
    except Exception as exc:
        db.session.rollback()
        print(f"[GoogleAuthStore] Imeshindikana kusoma token: {exc}")
        return None
