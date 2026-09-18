# api.py
"""
GariFix - API ya Simu (Flutter) - /api/v1/...
================================================
Faili hii ni HURU (standalone) - haiwezi kuvunja website iliyopo (app.py)
kwa sababu haibadilishi routes zozote za HTML. Inatumia JWT (badala ya
session/cookies) kwa sababu Flutter si browser.

JINSI YA KUUNGANISHA NA app.py (angalia ujumbe wa chat kwa maelezo kamili):
    1. `pip install Flask-JWT-Extended google-auth` (ongeza kwenye requirements.txt)
    2. Weka env variable JWT_SECRET_KEY (Render) na GOOGLE_WEB_CLIENT_ID
    3. Kwenye app.py, KARIBU NA MWISHO KABISA (baada ya routes zote za
       admin, kabla ya `if __name__ == "__main__":`), ongeza:

           from flask_jwt_extended import JWTManager
           app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "badilisha-hii")
           jwt = JWTManager(app)

           from api import api_bp
           csrf.exempt(api_bp)
           app.register_blueprint(api_bp)
"""

import os
import requests
import secrets
import uuid
from datetime import timedelta, datetime

from flask import Blueprint, request, jsonify, current_app, redirect, send_from_directory
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required,
    get_jwt_identity, get_jwt, verify_jwt_in_request,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func

from extensions import db
from models import User, Mechanic, ServiceRequest, Review, Notification, ChatMessage
from notifications import send_notification

# --- Google ID token verification ---
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

api_bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")

# Weka hapa "Web application" Client ID kutoka Google Cloud Console (SI ile
# ya Android) - hii ndiyo "audience" sahihi ya id_token unaotoka
# google_sign_in package upande wa Flutter (serverClientId).
GOOGLE_WEB_CLIENT_ID = os.environ.get("GOOGLE_WEB_CLIENT_ID", "")


# =============================================================
# HELPERS (nakala huru - haitegemei app.py, epuka circular import)
# =============================================================

class InvalidImageError(Exception):
    pass


def _validate_image_upload(file_storage):
    if not file_storage or file_storage.filename == "":
        return True, None
    try:
        from PIL import Image
        file_storage.stream.seek(0)
        img = Image.open(file_storage.stream)
        img.verify()
        file_storage.stream.seek(0)
        if img.format not in ("JPEG", "PNG", "GIF", "WEBP"):
            return False, "Aina ya picha isiyoruhusiwa. Tumia JPG, PNG, GIF au WEBP."
        return True, None
    except Exception:
        return False, "Faili hili si picha halali. Tafadhali pakia picha sahihi (JPG/PNG)."


def _cloudinary_configured():
    return bool(os.environ.get("CLOUDINARY_URL"))


def save_uploaded_image(file_storage, folder_hint="general", private=False):
    """Sawa na ile ya app.py - imenakiliwa hapa ili api.py isitegemee
    app.py (kuepuka circular import). Tabia ni ile ile: Cloudinary kwanza,
    fallback kwenye disk ya ndani ya Render."""
    if not file_storage or file_storage.filename == "":
        return None

    is_valid, error_msg = _validate_image_upload(file_storage)
    if not is_valid:
        raise InvalidImageError(error_msg)

    if _cloudinary_configured():
        import cloudinary.uploader
        file_storage.stream.seek(0)
        upload_options = {
            "folder": f"garifix/{folder_hint}",
            "resource_type": "image",
            "overwrite": True,
            "quality": "auto:good",
            "fetch_format": "auto",
            "width": 1600,
            "height": 1600,
            "crop": "limit",
        }
        if private:
            upload_options["type"] = "private"
        result = cloudinary.uploader.upload(file_storage, **upload_options)
        return result["public_id"] if private else result["secure_url"]

    ext = os.path.splitext(secure_filename(file_storage.filename))[1]
    unique_name = f"{uuid.uuid4().hex}{ext}"
    folder_key = "PRIVATE_UPLOAD_FOLDER" if private else "UPLOAD_FOLDER"
    target_folder = current_app.config.get(folder_key) or os.path.join(
        current_app.root_path, "private_uploads" if private else "static/uploads"
    )
    os.makedirs(target_folder, exist_ok=True)
    file_storage.save(os.path.join(target_folder, unique_name))
    return unique_name


def notify_user(user, title, body, data=None):
    """Sawa na app.py: hifadhi Notification kwenye DB + jaribu kutuma FCM push."""
    url = (data or {}).get("url")
    try:
        notif = Notification(user_id=user.id, title=title, body=body, url=url)
        db.session.add(notif)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(f"[API Notification-DB-ERROR] {e}")
        db.session.rollback()
    send_notification(user, title=title, body=body, data=data)


def notify_bilingual(user, title_sw, title_en, body_sw, body_en, data=None):
    """Sawa na notify_user, lakini inachagua Kiswahili au Kiingereza
    kulingana na 'language' aliyoihifadhi mtumiaji kwenye wasifu wake
    (default: Kiswahili, kama hajaweka)."""
    lang = getattr(user, "language", None) or "sw"
    if lang == "en":
        notify_user(user, title=title_en, body=body_en, data=data)
    else:
        notify_user(user, title=title_sw, body=body_sw, data=data)


def _reverse_geocode_in_background(app, service_request_id, latitude, longitude):
    """Inapata jina la mtaa/eneo (Nominatim) NYUMA YA PAZIA (thread tofauti)
    ili isizuie (block) jibu la haraka kwa Mteja wala arifa kwa Fundi.
    'app' inahitajika ili thread hii iweze kutumia database context."""
    import threading

    def _run():
        with app.app_context():
            try:
                geo_response = requests.get(
                    "https://nominatim.openstreetmap.org/reverse",
                    params={"format": "json", "lat": latitude, "lon": longitude, "zoom": 16},
                    headers={"User-Agent": "GariFixApp/1.0 (garifix2026@gmail.com)"},
                    timeout=6,
                )
                if geo_response.status_code == 200:
                    display_name = geo_response.json().get("display_name")
                    if display_name:
                        sr = db.session.get(ServiceRequest, service_request_id)
                        if sr:
                            sr.location = display_name
                            db.session.commit()
            except Exception as e:
                current_app.logger.warning(f"[Reverse-Geocode-BG] Imeshindikana: {e}")

    threading.Thread(target=_run, daemon=True).start()


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def err(message, code=400, error_code=None):
    """error_code (hiari) ni 'kanuni' fupi isiyobadilika (mfano
    'phone_taken') ambayo Flutter inaweza kuitumia kutafsiri ujumbe kwa
    lugha sahihi (SW/EN) - 'message' hapa inabaki Kiswahili tu, ni kwa
    ajili ya website (admin panel) na kwa ajili ya 'debug'."""
    payload = {"status": "error", "message": message}
    if error_code:
        payload["error_code"] = error_code
    return jsonify(payload), code


def current_user_or_error():
    """Chukua User kutoka JWT identity ya sasa. Inarudisha (user, None) au
    (None, (response, code)) kama kuna tatizo."""
    uid = get_jwt_identity()
    if uid == "pending":
        return None, err("Akaunti ya muda (pending) haina ruhusa hapa.", 403)
    user = db.session.get(User, int(uid))
    if not user:
        return None, err("Mtumiaji haipo.", 404)
    if user.status == "blocked":
        return None, err("Akaunti yako imezuiwa (blocked).", 403)
    return user, None


def user_to_dict(user):
    return {
        "id": user.id,
        "full_name": user.full_name,
        "email": user.email,
        "phone": user.phone,
        "role": user.role,
        "profile_photo": user.profile_photo,
    }


ONLINE_THRESHOLD_MINUTES = 15


def _is_online(user):
    """Fundi/Mtumiaji anahesabiwa 'mtandaoni' kama app yake ilituma 'heartbeat'
    ndani ya dakika 5 zilizopita."""
    if not user or not user.last_active:
        return False
    return (datetime.utcnow() - user.last_active) < timedelta(minutes=ONLINE_THRESHOLD_MINUTES)


def mechanic_to_dict(m, include_avg=True):
    d = {
        "id": m.id,
        "user_id": m.user_id,
        "full_name": m.user.full_name if m.user else None,
        "garage_name": m.garage_name,
        "region": m.region,
        "district": m.district,
        "ward": m.ward,
        "street": m.street,
        "specialization": m.specialization,
        "experience": m.experience,
        "description": m.description,
        "profile_photo": m.profile_photo,
        "verified": m.verified,
        "phone": m.user.phone if m.user else None,
        "is_online": _is_online(m.user),
    }
    if include_avg:
        avg = db.session.query(func.avg(Review.rating)).filter_by(mechanic_id=m.id).scalar()
        cnt = Review.query.filter_by(mechanic_id=m.id).count()
        d["average_rating"] = round(avg, 1) if avg else 0
        d["review_count"] = cnt
    return d


def request_to_dict(r):
    return {
        "id": r.id,
        "customer_id": r.customer_id,
        "customer_name": r.customer.full_name if r.customer else None,
        "customer_phone": r.customer.phone if r.customer else None,
        "mechanic_id": r.mechanic_id,
        "mechanic_name": r.mechanic.user.full_name if r.mechanic and r.mechanic.user else None,
        "mechanic_garage_name": r.mechanic.garage_name if r.mechanic else None,
        "mechanic_phone": r.mechanic.user.phone if r.mechanic and r.mechanic.user else None,
        "vehicle_model": r.vehicle_model,
        "problem_description": r.problem_description,
        "location": r.location,
        "latitude": r.latitude,
        "longitude": r.longitude,
        "status": r.status,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def review_to_dict(rv):
    return {
        "id": rv.id,
        "customer_id": rv.customer_id,
        "customer_name": rv.customer.full_name if rv.customer else None,
        "mechanic_id": rv.mechanic_id,
        "rating": rv.rating,
        "comment": rv.comment,
        "created_at": rv.created_at.isoformat() if rv.created_at else None,
    }


TANZANIA_REGIONS = [
    "Arusha", "Dar es Salaam", "Dodoma", "Geita", "Iringa", "Kagera",
    "Katavi", "Kigoma", "Kilimanjaro", "Lindi", "Manyara", "Mara",
    "Mbeya", "Morogoro", "Mtwara", "Mwanza", "Njombe", "Pemba Kaskazini",
    "Pemba Kusini", "Pwani", "Rukwa", "Ruvuma", "Shinyanga", "Simiyu",
    "Singida", "Songwe", "Tabora", "Tanga", "Unguja Kaskazini",
    "Unguja Kusini", "Unguja Mjini Magharibi",
]


# =============================================================
# 1. AUTH
# =============================================================

@api_bp.route("/auth/google", methods=["POST"])
def api_google_login():
    """Body: {"id_token": "...", "role": "customer" | "mechanic"}
    "role" inatumika TU kama mtumiaji ni MPYA kabisa (haipo database)."""
    data = request.get_json(silent=True) or {}
    id_token_str = data.get("id_token")
    chosen_role = data.get("role", "customer")
    if chosen_role not in ("customer", "mechanic"):
        chosen_role = "customer"
    if not id_token_str:
        return err("id_token inahitajika")

    if not GOOGLE_WEB_CLIENT_ID:
        return err("Google Sign-In haijasanidiwa upande wa server (GOOGLE_WEB_CLIENT_ID).", 500)

    try:
        info = google_id_token.verify_oauth2_token(
            id_token_str, google_requests.Request(), GOOGLE_WEB_CLIENT_ID
        )
    except ValueError:
        return err("Google token si sahihi au imeisha muda.", 401)

    email = (info.get("email") or "").strip().lower()
    full_name = info.get("name") or ""
    if not email:
        return err("Imeshindikana kupata email kutoka Google.", 401)

    user = User.query.filter_by(email=email).first()

    if user:
        if user.status == "blocked":
            return err("Akaunti yako imezuiwa (blocked) na Admin.", 403)
        if user.role != chosen_role:
            return err(
                f"Akaunti hii ({email}) tayari imesajiliwa kama '{user.role}'. "
                f"Tumia akaunti nyingine ya Google, au ingia kwenye jukumu sahihi.",
                409,
                error_code="role_mismatch",
            )
        if not user.email_verified:
            user.email_verified = True
            db.session.commit()

        access_token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=30))
        refresh_token = create_refresh_token(identity=str(user.id), expires_delta=timedelta(days=3650))
        needs_mechanic_profile = (user.role == "mechanic" and not user.mechanic_profile)
        mechanic_status = None
        if user.role == "mechanic" and user.mechanic_profile:
            mechanic_status = user.mechanic_profile.verified

        return jsonify({
            "status": "ok",
            "is_new_user": False,
            "needs_mechanic_profile": needs_mechanic_profile,
            "mechanic_status": mechanic_status,
            "needs_phone": (user.role == "customer" and not user.phone),
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": user_to_dict(user),
        }), 200

    # --- Mtumiaji MPYA ---
    if chosen_role == "mechanic":
        # Hatuundi akaunti bado - fundi anahitaji kujaza fomu ndefu zaidi
        # (garage, eneo, kitambulisho). Tunatoa token ya MUDA MFUPI tu.
        pending_token = create_access_token(
            identity="pending",
            additional_claims={"email": email, "full_name": full_name},
            expires_delta=timedelta(minutes=30),
        )
        return jsonify({
            "status": "ok",
            "is_new_user": True,
            "needs_mechanic_profile": True,
            "pending_token": pending_token,
            "email": email,
            "full_name": full_name,
        }), 200

    # Mteja mpya - akaunti inaundwa MOJA KWA MOJA
    new_user = User(
        full_name=full_name or "Mteja GariFix",
        email=email,
        password=generate_password_hash(secrets.token_urlsafe(24)),
        role="customer",
        email_verified=True,
        registered_via_google=True,
    )
    db.session.add(new_user)
    db.session.commit()

    access_token = create_access_token(identity=str(new_user.id), expires_delta=timedelta(days=30))
    refresh_token = create_refresh_token(identity=str(new_user.id), expires_delta=timedelta(days=3650))
    return jsonify({
        "status": "ok",
        "is_new_user": True,
        "needs_mechanic_profile": False,
        "needs_phone": True,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": user_to_dict(new_user),
    }), 200


@api_bp.route("/auth/refresh", methods=["POST"])
@jwt_required(refresh=True)
def api_refresh():
    uid = get_jwt_identity()
    if uid == "pending":
        return err("Token ya muda haiwezi kuongezwa.", 403)
    new_access = create_access_token(identity=uid, expires_delta=timedelta(days=30))
    return jsonify({"status": "ok", "access_token": new_access}), 200


@api_bp.route("/auth/me", methods=["GET"])
@jwt_required()
def api_me():
    user, error = current_user_or_error()
    if error:
        return error
    return jsonify({"status": "ok", "user": user_to_dict(user)}), 200


# =============================================================
# 2. CUSTOMER ONBOARDING
# =============================================================

@api_bp.route("/customer/complete-phone", methods=["POST"])
@jwt_required()
def api_complete_customer_phone():
    user, error = current_user_or_error()
    if error:
        return error
    if user.role != "customer":
        return err("Endpoint hii ni kwa wateja pekee.", 403)

    data = request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip()
    if len(phone) != 10 or not phone.isdigit():
        return err("Tafadhali weka namba sahihi ya simu (tarakimu 10).")
    if User.query.filter(User.phone == phone, User.id != user.id).first():
        return err("Namba hii ya simu tayari inatumiwa na akaunti nyingine.", 409, error_code="phone_taken")

    user.phone = phone
    db.session.commit()
    return jsonify({"status": "ok", "user": user_to_dict(user)}), 200


# =============================================================
# 3. MECHANIC ONBOARDING
# =============================================================

@api_bp.route("/mechanic/complete-profile", methods=["POST"])
@jwt_required()
def api_mechanic_complete_profile():
    """Inatumia PENDING TOKEN (kutoka /auth/google, role=mechanic) AU
    access_token ya kawaida (fundi aliyekataliwa 'rejected' anaomba upya).
    Multipart/form-data: first_name, last_name, phone, garage_name,
    region, district, ward, street, experience, description,
    specialization (fields nyingi kwa specialization moja moja),
    id_document_type, id_document (faili), profile_photo (faili, hiari)."""
    claims = get_jwt()
    uid = get_jwt_identity()

    reapplying_user = None
    if uid == "pending":
        email = claims.get("email")
        full_name_from_google = claims.get("full_name", "")
        if not email:
            return err("Token ya muda si sahihi.", 401)
        if User.query.filter_by(email=email).first():
            return err("Akaunti ya email hii tayari ipo. Ingia badala yake.", 409)
    else:
        reapplying_user = db.session.get(User, int(uid))
        if not reapplying_user or reapplying_user.role != "mechanic":
            return err("Huna ruhusa ya kufanya hivi.", 403)
        if not reapplying_user.mechanic_profile or reapplying_user.mechanic_profile.verified != "rejected":
            return err("Wasifu wako tayari upo/unasubiri idhini.", 409)
        email = reapplying_user.email
        full_name_from_google = reapplying_user.full_name

    form = request.form
    first_name = (form.get("first_name") or "").strip()
    last_name = (form.get("last_name") or "").strip()
    full_name = f"{first_name} {last_name}".strip() or full_name_from_google
    phone = (form.get("phone") or "").strip()
    garage_name = (form.get("garage_name") or "").strip()
    region = (form.get("region") or "").strip()
    district = (form.get("district") or "").strip()
    ward = (form.get("ward") or "").strip()
    street = (form.get("street") or "").strip()
    experience = safe_int(form.get("experience"), default=0)
    description = (form.get("description") or "").strip()
    specializations = form.getlist("specialization")
    specialization = ", ".join(specializations) if specializations else (form.get("specialization") or "").strip()
    id_document_type = (form.get("id_document_type") or "").strip()

    if not first_name or not last_name:
        return err("Jina la kwanza na la mwisho vinahitajika.")
    if not phone or len(phone) != 10 or not phone.isdigit():
        return err("Namba sahihi ya simu (tarakimu 10) inahitajika.")
    if not region or not district or not ward or not street:
        return err("Eneo kamili (Mkoa, Wilaya, Kata, Mtaa) linahitajika.")
    if not specialization:
        return err("Chagua angalau utaalamu mmoja (specialization).")
    if not id_document_type:
        return err("Chagua aina ya kitambulisho.")

    id_doc_file = request.files.get("id_document")
    if not reapplying_user and (not id_doc_file or id_doc_file.filename == ""):
        return err("Kitambulisho (id_document) kinahitajika.")

    existing_phone = User.query.filter(User.phone == phone).first()
    if existing_phone and (not reapplying_user or existing_phone.id != reapplying_user.id):
        return err("Namba hii ya simu tayari imesajiliwa.", 409, error_code="phone_taken")

    try:
        id_document_filename = save_uploaded_image(id_doc_file, folder_hint="id_documents", private=True) if id_doc_file and id_doc_file.filename else None
        profile_photo_filename = save_uploaded_image(request.files.get("profile_photo"), folder_hint="profiles")
    except InvalidImageError as e:
        return err(str(e))

    if reapplying_user:
        user = reapplying_user
        user.full_name = full_name
        user.phone = phone
        m = user.mechanic_profile
        m.garage_name = garage_name
        m.region = region
        m.district = district
        m.ward = ward
        m.street = street
        m.specialization = specialization
        m.experience = experience
        m.description = description
        m.id_document_type = id_document_type
        if id_document_filename:
            m.id_document = id_document_filename
        if profile_photo_filename:
            m.profile_photo = profile_photo_filename
        m.verified = "pending"
        db.session.commit()
    else:
        user = User(
            full_name=full_name,
            phone=phone,
            email=email,
            password=generate_password_hash(secrets.token_urlsafe(24)),
            role="mechanic",
            email_verified=True,
            registered_via_google=True,
        )
        db.session.add(user)
        db.session.commit()

        m = Mechanic(
            user_id=user.id,
            garage_name=garage_name,
            region=region,
            district=district,
            ward=ward,
            street=street,
            specialization=specialization,
            experience=experience,
            description=description,
            profile_photo=profile_photo_filename,
            id_document_type=id_document_type,
            id_document=id_document_filename,
            verified="pending",
        )
        db.session.add(m)
        db.session.commit()

    for admin_user in User.query.filter_by(role="admin").all():
        notify_user(
            admin_user,
            title="Fundi Mpya Anasubiri Idhini - GariFix",
            body=f"{full_name} ({garage_name}) amejisajili (Flutter app) na anasubiri uthibitisho wako.",
            data={"type": "mechanic_pending", "mechanic_id": m.id, "url": "/admin/mechanics"},
        )

    access_token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=30))
    refresh_token = create_refresh_token(identity=str(user.id), expires_delta=timedelta(days=3650))
    return jsonify({
        "status": "ok",
        "message": "Usajili umefanikiwa. Akaunti yako inasubiri uthibitisho wa Admin.",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": user_to_dict(user),
        "mechanic_status": "pending",
    }), 201


# =============================================================
# 4. MECHANICS (kwa mteja) - orodha, search, profile ya umma
# =============================================================

@api_bp.route("/mechanics/search", methods=["GET"])
@jwt_required()
def api_search_mechanics():
    region = request.args.get("region", "").strip()
    district = request.args.get("district", "").strip()
    ward = request.args.get("ward", "").strip()
    specializations = [s.strip() for s in request.args.getlist("specialization") if s.strip()]

    query = Mechanic.query.filter(Mechanic.verified == "approved")
    if region:
        query = query.filter(Mechanic.region.ilike(f"%{region}%"))
    if district:
        query = query.filter(Mechanic.district.ilike(f"%{district}%"))
    if ward:
        query = query.filter(Mechanic.ward.ilike(f"%{ward}%"))
    if specializations:
        # Mechanic ana specialization moja au zaidi (comma-separated) - mtu
        # akichagua kadhaa, tunaonyesha fundi anayefanana na ANGALAU MOJA
        # ya alizochagua (OR), si lazima zote.
        query = query.filter(
            db.or_(*[Mechanic.specialization.ilike(f"%{s}%") for s in specializations])
        )

    mechanics = query.all()
    return jsonify({"status": "ok", "mechanics": [mechanic_to_dict(m) for m in mechanics]}), 200


@api_bp.route("/mechanics/<int:mechanic_id>", methods=["GET"])
@jwt_required()
def api_mechanic_detail(mechanic_id):
    m = Mechanic.query.get_or_404(mechanic_id)
    return jsonify({"status": "ok", "mechanic": mechanic_to_dict(m)}), 200


@api_bp.route("/mechanics/<int:mechanic_id>/reviews", methods=["GET"])
@jwt_required()
def api_mechanic_reviews(mechanic_id):
    Mechanic.query.get_or_404(mechanic_id)
    reviews = Review.query.filter_by(mechanic_id=mechanic_id).order_by(Review.created_at.desc()).all()
    return jsonify({"status": "ok", "reviews": [review_to_dict(r) for r in reviews]}), 200


@api_bp.route("/mechanics/<int:mechanic_id>/reviews", methods=["POST"])
@jwt_required()
def api_add_review(mechanic_id):
    user, error = current_user_or_error()
    if error:
        return error
    if user.role != "customer":
        return err("Wateja pekee ndio wanaoweza kutoa review.", 403)

    mechanic = Mechanic.query.get_or_404(mechanic_id)
    data = request.get_json(silent=True) or {}
    request_id = data.get("request_id")
    rating = safe_int(data.get("rating"), default=0)
    comment = (data.get("comment") or "").strip()

    if rating < 1 or rating > 5:
        return err("Rating lazima iwe kati ya 1 na 5.")

    if request_id:
        existing = Review.query.filter_by(service_request_id=request_id).first()
        if existing:
            return err("Tayari umeshampa fundi huyu rating kwa huduma hii.", 409)

    review = Review(
        customer_id=user.id,
        mechanic_id=mechanic.id,
        service_request_id=request_id,
        rating=rating,
        comment=comment,
    )
    db.session.add(review)
    db.session.commit()

    if mechanic.user:
        notify_bilingual(
            mechanic.user,
            title_sw="Umepata Review Mpya - GariFix", title_en="New Review - GariFix",
            body_sw=f"{user.full_name} amekupa rating ya {rating}/5.",
            body_en=f"{user.full_name} gave you a {rating}/5 rating.",
            data={"type": "new_review", "mechanic_id": mechanic.id, "url": "/mechanic/reviews"},
        )

    return jsonify({"status": "ok", "review": review_to_dict(review)}), 201


# =============================================================
# 5. SERVICE REQUESTS
# =============================================================

@api_bp.route("/requests", methods=["POST"])
@jwt_required()
def api_create_request():
    user, error = current_user_or_error()
    if error:
        return error
    if user.role != "customer":
        return err("Wateja pekee ndio wanaoweza kuomba huduma.", 403)

    data = request.get_json(silent=True) or {}
    mechanic_id = data.get("mechanic_id")
    mechanic = Mechanic.query.get_or_404(mechanic_id) if mechanic_id else None
    vehicle_model = (data.get("vehicle_model") or "").strip()
    problem_description = (data.get("problem_description") or "").strip()
    latitude = data.get("latitude")
    longitude = data.get("longitude")

    if not vehicle_model or not problem_description:
        return err("vehicle_model na problem_description vinahitajika.")
    if latitude is None or longitude is None:
        return err("Chagua eneo lako kwenye ramani (latitude/longitude).")

    try:
        latitude = float(latitude)
        longitude = float(longitude)
    except (TypeError, ValueError):
        return err("Kuratibu za eneo (latitude/longitude) si sahihi.")

    # Jina la mtaa/eneo (reverse geocoding) - hii inafanyika NYUMA YA PAZIA
    # (background thread) ili isichelewesha jibu kwa Mteja WALA arifa kwa
    # Fundi. "location" inaanza kama kuratibu tu, kisha inasasishwa
    # kiotomatiki mara jina la eneo litakapopatikana (dakika chache baadaye).
    full_location = f"{latitude:.5f}, {longitude:.5f}"

    new_request = ServiceRequest(
        customer_id=user.id,
        mechanic_id=mechanic.id if mechanic else None,
        vehicle_model=vehicle_model,
        problem_description=problem_description,
        location=full_location,
        latitude=latitude,
        longitude=longitude,
    )
    db.session.add(new_request)
    db.session.commit()

    if mechanic and mechanic.user:
        notify_bilingual(
            mechanic.user,
            title_sw="Ombi Jipya la Huduma - GariFix", title_en="New Service Request - GariFix",
            body_sw=f"Mteja {user.full_name} ana tatizo la {vehicle_model}. Bofya kuona zaidi.",
            body_en=f"Customer {user.full_name} has an issue with {vehicle_model}. Tap to view.",
            data={"type": "new_request", "request_id": new_request.id, "url": "/mechanic/requests"},
        )

    _reverse_geocode_in_background(current_app._get_current_object(), new_request.id, latitude, longitude)

    return jsonify({"status": "ok", "request": request_to_dict(new_request)}), 201


@api_bp.route("/requests", methods=["GET"])
@jwt_required()
def api_list_requests():
    user, error = current_user_or_error()
    if error:
        return error

    status_filter = request.args.get("status")

    if user.role == "customer":
        query = ServiceRequest.query.filter_by(customer_id=user.id)
    elif user.role == "mechanic":
        mechanic = user.mechanic_profile
        if not mechanic:
            return jsonify({"status": "ok", "requests": []}), 200
        query = ServiceRequest.query.filter_by(mechanic_id=mechanic.id)
    else:
        query = ServiceRequest.query

    if status_filter:
        query = query.filter_by(status=status_filter)

    requests_list = query.order_by(ServiceRequest.created_at.desc()).all()
    return jsonify({"status": "ok", "requests": [request_to_dict(r) for r in requests_list]}), 200


@api_bp.route("/requests/<int:request_id>/accept", methods=["POST"])
@jwt_required()
def api_accept_request(request_id):
    user, error = current_user_or_error()
    if error:
        return error
    if user.role != "mechanic" or not user.mechanic_profile:
        return err("Mafundi pekee ndio wanaoweza kukubali maombi.", 403)

    service = ServiceRequest.query.get_or_404(request_id)
    if service.mechanic_id != user.mechanic_profile.id:
        return err("Hauruhusiwi kutenda kitendo hiki.", 403)

    service.status = "accepted"
    db.session.commit()
    if service.customer:
        notify_bilingual(
            service.customer,
            title_sw="Fundi Amekubali Ombi Lako - GariFix", title_en="Mechanic Accepted Your Request - GariFix",
            body_sw=f"{user.full_name} amekubali kukusaidia na {service.vehicle_model}. Anakuja!",
            body_en=f"{user.full_name} accepted to help with your {service.vehicle_model}. They're on their way!",
            data={"type": "request_accepted", "request_id": service.id, "url": "/customer/requests"},
        )
    return jsonify({"status": "ok", "request": request_to_dict(service)}), 200


@api_bp.route("/requests/<int:request_id>/reject", methods=["POST"])
@jwt_required()
def api_reject_request(request_id):
    user, error = current_user_or_error()
    if error:
        return error
    if user.role != "mechanic" or not user.mechanic_profile:
        return err("Mafundi pekee ndio wanaoweza kukataa maombi.", 403)

    service = ServiceRequest.query.get_or_404(request_id)
    if service.mechanic_id != user.mechanic_profile.id or service.status != "pending":
        return err("Hauruhusiwi kutenda kitendo hiki.", 403)

    service.status = "rejected"
    db.session.commit()
    if service.customer:
        notify_bilingual(
            service.customer,
            title_sw="Fundi Hawezi Kukusaidia kwa Sasa - GariFix", title_en="Mechanic Can't Help Right Now - GariFix",
            body_sw=f"{user.full_name} hawezi kushughulikia tatizo la {service.vehicle_model} kwa muda huu.",
            body_en=f"{user.full_name} is unable to handle your {service.vehicle_model} issue at this time.",
            data={"type": "request_rejected", "request_id": service.id, "url": "/customer/requests"},
        )
    return jsonify({"status": "ok", "request": request_to_dict(service)}), 200


@api_bp.route("/requests/<int:request_id>/complete", methods=["POST"])
@jwt_required()
def api_complete_request(request_id):
    user, error = current_user_or_error()
    if error:
        return error

    service = ServiceRequest.query.get_or_404(request_id)

    if user.role == "customer" and service.customer_id == user.id:
        if service.status != "accepted":
            return err("Huduma hii haiko tayari kuthibitishwa kuwa imekamilika.")
        service.status = "completed"
        db.session.commit()
        if service.mechanic and service.mechanic.user:
            notify_bilingual(
                service.mechanic.user,
                title_sw="Huduma Imethibitishwa Kukamilika - GariFix", title_en="Service Confirmed Completed - GariFix",
                body_sw=f"{user.full_name} amethibitisha kuwa kazi ya {service.vehicle_model} imekamilika.",
                body_en=f"{user.full_name} confirmed that the {service.vehicle_model} job is complete.",
                data={"type": "request_completed", "request_id": service.id, "url": "/mechanic/requests"},
            )
        return jsonify({"status": "ok", "request": request_to_dict(service)}), 200

    return err("Hauruhusiwi kubadilisha taarifa hii.", 403)


# =============================================================
# 6. NOTIFICATIONS
# =============================================================

@api_bp.route("/notifications", methods=["GET"])
@jwt_required()
def api_list_notifications():
    user, error = current_user_or_error()
    if error:
        return error
    notifications = Notification.query.filter_by(user_id=user.id).order_by(Notification.created_at.desc()).limit(50).all()
    return jsonify({
        "status": "ok",
        "unread_count": Notification.query.filter_by(user_id=user.id, is_read=False).count(),
        "notifications": [
            {"id": n.id, "title": n.title, "body": n.body, "url": n.url,
             "is_read": n.is_read, "created_at": n.created_at.isoformat() if n.created_at else None}
            for n in notifications
        ],
    }), 200


@api_bp.route("/notifications/mark-all-read", methods=["POST"])
@jwt_required()
def api_mark_all_read():
    user, error = current_user_or_error()
    if error:
        return error
    Notification.query.filter_by(user_id=user.id, is_read=False).update({"is_read": True})
    db.session.commit()
    return jsonify({"status": "ok"}), 200


@api_bp.route("/fcm-token", methods=["POST"])
@jwt_required()
def api_register_fcm_token():
    user, error = current_user_or_error()
    if error:
        return error
    data = request.get_json(silent=True) or {}
    token = data.get("fcm_token")
    if not token:
        return err("fcm_token haipo.")
    user.fcm_token = token
    db.session.commit()
    return jsonify({"status": "ok"}), 200


@api_bp.route("/heartbeat", methods=["POST"])
@jwt_required()
def api_heartbeat():
    """App inaita hii mara kwa mara (mfano kila dakika 2) ili tuweke
    kumbukumbu kuwa mtumiaji bado 'yupo hai' (mtandaoni)."""
    user, error = current_user_or_error()
    if error:
        return error
    user.last_active = datetime.utcnow()
    db.session.commit()
    return jsonify({"status": "ok"}), 200


@api_bp.route("/set-language", methods=["POST"])
@jwt_required()
def api_set_language():
    """Flutter inaita hii kila mtumiaji anapobadilisha lugha (SW/EN) kwenye
    app, ili arifa za baadaye (push notifications) ziweze kutumwa kwa
    lugha aliyochagua badala ya Kiswahili pekee."""
    user, error = current_user_or_error()
    if error:
        return error
    data = request.get_json(silent=True) or {}
    language = (data.get("language") or "").strip().lower()
    if language not in ("sw", "en"):
        return err("Lugha lazima iwe 'sw' au 'en'.")
    user.language = language
    db.session.commit()
    return jsonify({"status": "ok"}), 200


# =============================================================
# 7. PROFILE
# =============================================================

@api_bp.route("/profile", methods=["GET"])
@jwt_required()
def api_get_profile():
    user, error = current_user_or_error()
    if error:
        return error
    data = user_to_dict(user)
    if user.role == "mechanic" and user.mechanic_profile:
        data["mechanic_profile"] = mechanic_to_dict(user.mechanic_profile)
        # Pia weka juu kabisa (top-level) kwa urahisi wa Flutter (top bar)
        data["average_rating"] = data["mechanic_profile"]["average_rating"]
        data["review_count"] = data["mechanic_profile"]["review_count"]
    return jsonify({"status": "ok", "user": data}), 200


@api_bp.route("/profile", methods=["PUT"])
@jwt_required()
def api_update_profile():
    """multipart/form-data: full_name (hiari), profile_photo (faili, hiari)."""
    user, error = current_user_or_error()
    if error:
        return error

    full_name = (request.form.get("full_name") or "").strip()
    if full_name:
        user.full_name = full_name

    try:
        photo_filename = save_uploaded_image(request.files.get("profile_photo"), folder_hint="profiles")
        if photo_filename:
            user.profile_photo = photo_filename
    except InvalidImageError as e:
        return err(str(e))

    db.session.commit()
    return jsonify({"status": "ok", "user": user_to_dict(user)}), 200


# =============================================================
# 8. TANZANIA REGIONS (kwa dropdown ya Flutter)
# =============================================================

@api_bp.route("/regions", methods=["GET"])
def api_regions():
    return jsonify({"status": "ok", "regions": TANZANIA_REGIONS}), 200


_locations_cache = None


def _load_locations_data():
    """Soma static/js/tz_locations.js (Mkoa -> Wilaya -> [Kata]) na uigeuze
    kuwa Python dict, ukihifadhi kwenye cache ya module ili tusisome faili
    kutoka disk kwenye kila ombi. Faili hilo ni JS object literal ambalo ni
    JSON halali (funguo/thamani zote zina alama za nukuu mbili)."""
    global _locations_cache
    if _locations_cache is not None:
        return _locations_cache

    path = os.path.join(current_app.root_path, "static", "js", "tz_locations.js")
    try:
        with open(path, encoding="utf-8") as f:
            content = f.read()
        start = content.index("{")
        end = content.rindex("}") + 1
        import json
        _locations_cache = json.loads(content[start:end])
    except Exception as e:
        current_app.logger.error(f"[API] Imeshindikana kusoma tz_locations.js: {e}")
        _locations_cache = {}
    return _locations_cache


@api_bp.route("/locations", methods=["GET"])
def api_locations():
    """Inarudisha muundo KAMILI: {"Mkoa": {"Wilaya": ["Kata1", "Kata2", ...]}}
    - sawa kabisa na tz_locations.js inayotumika kwenye website. Flutter
    inapaswa kuomba hii MARA MOJA tu (mfano kwenye splash/fomu ya fundi) na
    kuihifadhi kwenye kumbukumbu (state) kwa dropdown zinazofuatana."""
    return jsonify({"status": "ok", "locations": _load_locations_data()}), 200


# =============================================================
# 9. CHAT (kati ya Mteja na Fundi, kwa ombi maalum lililokubaliwa)
# =============================================================

def _can_access_chat(user, service):
    """Mteja au Fundi husika wa ombi hili pekee ndio wenye ruhusa."""
    if user.role == "customer" and service.customer_id == user.id:
        return True
    if user.role == "mechanic" and user.mechanic_profile and service.mechanic_id == user.mechanic_profile.id:
        return True
    return False


def chat_message_to_dict(m):
    return {
        "id": m.id,
        "service_request_id": m.service_request_id,
        "sender_id": m.sender_id,
        "sender_name": m.sender.full_name if m.sender else None,
        "message": m.message,
        "created_at": m.created_at.isoformat() if m.created_at else None,
    }


@api_bp.route("/requests/<int:request_id>/messages", methods=["GET"])
@jwt_required()
def api_list_chat_messages(request_id):
    user, error = current_user_or_error()
    if error:
        return error

    service = ServiceRequest.query.get_or_404(request_id)
    if not _can_access_chat(user, service):
        return err("Huna ruhusa ya kuona mazungumzo haya.", 403)

    messages = ChatMessage.query.filter_by(service_request_id=request_id).order_by(ChatMessage.created_at.asc()).all()

    # Weka ujumbe wa mtu MWINGINE kama 'umesomwa' sasa kwa kuwa ameufungua.
    ChatMessage.query.filter(
        ChatMessage.service_request_id == request_id,
        ChatMessage.sender_id != user.id,
        ChatMessage.is_read == False,  # noqa: E712
    ).update({"is_read": True})
    db.session.commit()

    return jsonify({"status": "ok", "messages": [chat_message_to_dict(m) for m in messages]}), 200


@api_bp.route("/requests/<int:request_id>/messages", methods=["POST"])
@jwt_required()
def api_send_chat_message(request_id):
    user, error = current_user_or_error()
    if error:
        return error

    service = ServiceRequest.query.get_or_404(request_id)
    if not _can_access_chat(user, service):
        return err("Huna ruhusa ya kutuma ujumbe kwenye ombi hili.", 403)
    if service.status not in ("accepted", "completed"):
        return err("Mazungumzo yanapatikana tu baada ya ombi kukubaliwa.", 409)

    data = request.get_json(silent=True) or {}
    text = (data.get("message") or "").strip()
    if not text:
        return err("Ujumbe hauwezi kuwa tupu.")

    chat_message = ChatMessage(service_request_id=request_id, sender_id=user.id, message=text)
    db.session.add(chat_message)
    db.session.commit()

    # Mjulishe upande mwingine (Mteja au Fundi) kwa push notification.
    other_user = None
    if user.role == "customer" and service.mechanic and service.mechanic.user:
        other_user = service.mechanic.user
    elif user.role == "mechanic" and service.customer:
        other_user = service.customer

    if other_user:
        notify_bilingual(
            other_user,
            title_sw=f"Ujumbe Mpya kutoka {user.full_name}", title_en=f"New Message from {user.full_name}",
            body_sw=text if len(text) <= 100 else f"{text[:100]}...",
            body_en=text if len(text) <= 100 else f"{text[:100]}...",
            data={"type": "new_chat_message", "request_id": request_id, "url": "/chat"},
        )

    return jsonify({"status": "ok", "message": chat_message_to_dict(chat_message)}), 201


# =============================================================
# 10. ADMIN (login ya phone/password + kuidhinisha mafundi)
# =============================================================

def _require_admin():
    """Rudisha (user, None) kama ni admin sahihi, vinginevyo (None, error_response)."""
    user, error = current_user_or_error()
    if error:
        return None, error
    if user.role != "admin":
        return None, err("Huna ruhusa ya sehemu hii.", 403)
    return user, None


@api_bp.route("/auth/admin-login", methods=["POST"])
def api_admin_login():
    data = request.get_json(silent=True) or {}
    identifier = (data.get("identifier") or "").strip()
    password = data.get("password") or ""
    if not identifier or not password:
        return err("Namba ya simu/Email na password vinahitajika.")

    user = User.query.filter(
        db.or_(User.phone == identifier, User.email == identifier)
    ).first()

    if not user or user.role != "admin" or not user.password or not check_password_hash(user.password, password):
        return err("Namba ya simu/Email au password si sahihi.", 401)
    if user.status == "blocked":
        return err("Akaunti yako imezuiwa.", 403)

    access_token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=30))
    refresh_token = create_refresh_token(identity=str(user.id), expires_delta=timedelta(days=3650))
    return jsonify({
        "status": "ok",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": user_to_dict(user),
    }), 200


@api_bp.route("/admin/stats", methods=["GET"])
@jwt_required()
def api_admin_stats():
    admin, error = _require_admin()
    if error:
        return error
    return jsonify({
        "status": "ok",
        "stats": {
            "total_customers": User.query.filter_by(role="customer").count(),
            "total_mechanics": Mechanic.query.count(),
            "pending_mechanics": Mechanic.query.filter_by(verified="pending").count(),
            "approved_mechanics": Mechanic.query.filter_by(verified="approved").count(),
            "total_requests": ServiceRequest.query.count(),
        },
    }), 200


@api_bp.route("/admin/mechanics", methods=["GET"])
@jwt_required()
def api_admin_list_mechanics():
    admin, error = _require_admin()
    if error:
        return error
    status_filter = request.args.get("status", "pending")
    query = Mechanic.query
    if status_filter != "all":
        query = query.filter_by(verified=status_filter)
    mechanics = query.order_by(Mechanic.id.desc()).all()
    result = []
    for m in mechanics:
        d = mechanic_to_dict(m, include_avg=False)
        d["email"] = m.user.email if m.user else None
        d["id_document_type"] = m.id_document_type
        d["has_id_document"] = bool(m.id_document)
        result.append(d)
    return jsonify({"status": "ok", "mechanics": result}), 200


@api_bp.route("/admin/mechanics/<int:mechanic_id>/id-document", methods=["GET"])
@jwt_required()
def api_admin_id_document(mechanic_id):
    admin, error = _require_admin()
    if error:
        return error
    mechanic = Mechanic.query.get_or_404(mechanic_id)
    if not mechanic.id_document:
        return err("Hakuna kitambulisho kilichopakiwa.", 404)
    if _cloudinary_configured():
        import cloudinary.utils
        url = cloudinary.utils.private_download_url(mechanic.id_document, "jpg", resource_type="image", type="private")
        return redirect(url)
    folder = current_app.config.get("PRIVATE_UPLOAD_FOLDER") or "private_uploads"
    return send_from_directory(folder, mechanic.id_document)


@api_bp.route("/admin/mechanics/<int:mechanic_id>/approve", methods=["POST"])
@jwt_required()
def api_admin_approve_mechanic(mechanic_id):
    admin, error = _require_admin()
    if error:
        return error
    mechanic = Mechanic.query.get_or_404(mechanic_id)
    mechanic.verified = "approved"
    db.session.commit()
    if mechanic.user:
        notify_bilingual(
            mechanic.user,
            title_sw="Umeidhinishwa - GariFix", title_en="You're Approved - GariFix",
            body_sw="Hongera! Akaunti yako ya ufundi imeidhinishwa na Admin. Sasa unaweza kupokea maombi ya huduma.",
            body_en="Congratulations! Your mechanic account has been approved by Admin. You can now receive service requests.",
            data={"type": "mechanic_approved"},
        )
    return jsonify({"status": "ok"}), 200


@api_bp.route("/admin/mechanics/<int:mechanic_id>/reject", methods=["POST"])
@jwt_required()
def api_admin_reject_mechanic(mechanic_id):
    admin, error = _require_admin()
    if error:
        return error
    data = request.get_json(silent=True) or {}
    reason = (data.get("reason") or "").strip()
    mechanic = Mechanic.query.get_or_404(mechanic_id)
    mechanic.verified = "rejected"
    if hasattr(mechanic, "rejection_reason"):
        mechanic.rejection_reason = reason or None
    db.session.commit()
    if mechanic.user:
        notify_bilingual(
            mechanic.user,
            title_sw="Usajili Haukukubaliwa - GariFix", title_en="Registration Not Approved - GariFix",
            body_sw=reason or "Tafadhali wasiliana na admin kwa maelezo zaidi, au jaribu kusajili tena.",
            body_en=reason or "Please contact admin for more details, or try registering again.",
            data={"type": "mechanic_rejected"},
        )
    return jsonify({"status": "ok"}), 200


# =============================================================
# 11. ADMIN - usimamizi wa watumiaji na maombi
# =============================================================

def _user_admin_dict(u):
    return {
        "id": u.id,
        "full_name": u.full_name,
        "phone": u.phone,
        "email": u.email,
        "role": u.role,
        "status": u.status,
        "created_at": u.created_at.isoformat() if getattr(u, "created_at", None) else None,
    }


@api_bp.route("/admin/customers", methods=["GET"])
@jwt_required()
def api_admin_list_customers():
    admin, error = _require_admin()
    if error:
        return error
    status_filter = request.args.get("status", "all")
    query = User.query.filter_by(role="customer")
    if status_filter != "all":
        query = query.filter_by(status=status_filter)
    customers = query.order_by(User.id.desc()).all()
    return jsonify({"status": "ok", "customers": [_user_admin_dict(c) for c in customers]}), 200


@api_bp.route("/admin/requests", methods=["GET"])
@jwt_required()
def api_admin_list_requests():
    admin, error = _require_admin()
    if error:
        return error
    status_filter = request.args.get("status", "all")
    query = ServiceRequest.query
    if status_filter != "all":
        query = query.filter_by(status=status_filter)
    requests_list = query.order_by(ServiceRequest.created_at.desc()).limit(200).all()
    return jsonify({"status": "ok", "requests": [request_to_dict(r) for r in requests_list]}), 200


@api_bp.route("/admin/users/<int:user_id>/block", methods=["POST"])
@jwt_required()
def api_admin_block_user(user_id):
    admin, error = _require_admin()
    if error:
        return error
    target = User.query.get_or_404(user_id)
    if target.role == "admin":
        return err("Huwezi kumzuia Admin mwingine.", 403)
    target.status = "blocked"
    db.session.commit()
    return jsonify({"status": "ok"}), 200


@api_bp.route("/admin/users/<int:user_id>/unblock", methods=["POST"])
@jwt_required()
def api_admin_unblock_user(user_id):
    admin, error = _require_admin()
    if error:
        return error
    target = User.query.get_or_404(user_id)
    target.status = "active"
    db.session.commit()
    return jsonify({"status": "ok"}), 200


@api_bp.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@jwt_required()
def api_admin_delete_user(user_id):
    admin, error = _require_admin()
    if error:
        return error
    target = User.query.get_or_404(user_id)
    if target.role == "admin":
        return err("Huwezi kumfuta Admin mwingine.", 403)
    Notification.query.filter_by(user_id=target.id).delete()
    db.session.delete(target)
    db.session.commit()
    return jsonify({"status": "ok"}), 200
