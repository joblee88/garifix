import os
import uuid
import secrets
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, session, flash, url_for, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func, or_
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# 1. Import Config na extensions
from config import Config
from extensions import db
from notifications import send_notification
from mailer import send_verification_email, send_password_reset_email

# Initialize Flask App
app = Flask(__name__)

# ProxyFix - Render (kama majukwaa mengine mengi) inatumia "reverse proxy"
# kuficha HTTPS - bila hii, Flask inadhani kila ombi ni "HTTP" (siyo
# salama), na hivyo INAKATAA kuweka "session cookie" kwa kuwa tumeweka
# SESSION_COOKIE_SECURE=True kwenye production. Hii ilikuwa ikizuia
# Google OAuth 'state' isihifadhiwe kabisa, na kusababisha "Imeshindikana
# kuunganisha na Google" - bila kujali usanidi mwingine wowote ni sahihi.
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# 2. Pakia Configuration KWANZA kabla ya db.init_app
app.config.from_object(Config)

# --- USALAMA (Security) ---
# CSRF Protection: inazuia tovuti nyingine kumdanganya mtumiaji aliye-login
# kutuma fomu bila yeye kujua (Cross-Site Request Forgery)
csrf = CSRFProtect(app)

# Google Sign-In (OAuth 2.0) - "Jisajili/Ingia kwa Google". Client ID/Secret
# zinatoka Environment Variables (Render) - hazipaswi kamwe kuandikwa
# moja kwa moja hapa. Kama hazijawekwa bado, uwezo huu unajizima wenyewe
# (haitoi hitilafu) - vitufe vya "Google" vitajificha kwenye templates.
from authlib.integrations.flask_client import OAuth

oauth = OAuth(app)
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
GOOGLE_OAUTH_ENABLED = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)

if GOOGLE_OAUTH_ENABLED:
    oauth.register(
        name="google",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )
else:
    print("[Google OAuth] ONYO: GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET hazijawekwa - 'Ingia kwa Google' imezimwa kwa sasa.")

# Rate Limiting: inazuia mtu kujaribu password/usajili mara nyingi mfululizo
# (brute-force au spam). Routes nyeti (login, forgot-password) zina vikomo
# vyao MAALUM (tazama @limiter.limit juu yao). Kikomo cha JUMLA hapa chini
# ni "wavu wa usalama" tu (siyo kizuizi kikuu), hivyo kimewekwa juu ya
# kutosha kuruhusu matumizi ya kawaida ya App (kila "page load" ndani ya
# App hutuma FCM token + kupakia faili za CSS/JS + wakati mwingine
# kuangalia arifa - yote haya ni maombi halali, siyo matumizi mabaya).
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["3000 per day", "600 per hour"],
    storage_uri="memory://",
)


# Static files (CSS/JS/images) hazipaswi kuathiriwa na rate limiting kabisa -
# ukurasa mmoja pekee hupakia faili nyingi za static kwa wakati mmoja
limiter.exempt(app.view_functions["static"])


@app.after_request
def set_security_headers(response):
    """Ongeza 'security headers' za kawaida kwenye kila jibu (response)."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(self)"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def validate_image_upload(file_storage):
    """
    Thibitisha faili lililopakiwa ni PICHA HALISI (siyo faili la hatari
    lililobadilishwa jina liwe .jpg). Inarudisha (True, None) kama ni sahihi,
    au (False, "sababu") kama siyo picha halali.
    """
    if not file_storage or file_storage.filename == "":
        return True, None  # Hakuna faili - hiari, si kosa

    try:
        from PIL import Image
        file_storage.stream.seek(0)
        img = Image.open(file_storage.stream)
        img.verify()  # Inathibitisha ni picha halali bila kuiharibu
        file_storage.stream.seek(0)
        if img.format not in ("JPEG", "PNG", "GIF", "WEBP"):
            return False, "Aina ya picha isiyoruhusiwa. Tumia JPG, PNG, GIF au WEBP."
        return True, None
    except Exception:
        return False, "Faili hili si picha halali. Tafadhali pakia picha sahihi (JPG/PNG)."

# Mipangilio ya upload ya picha (PROFILE - ya wazi/public) - hii ni "fallback"
# ya ndani ya Render tu, itatumika PEKEE kama Cloudinary haijasanidiwa
# (angalia CLOUDINARY_CONFIGURED hapa chini) - kumbuka faili hizi HAZITADUMU
# baada ya deploy mpya kwenye Render.
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Mipangilio ya upload ya VITAMBULISHO vya mafundi (NIDA/Leseni/Kura) - PRIVATE,
# HAIKO ndani ya "static/" hivyo mtu HAWEZI kufikia moja kwa moja kwa URL -
# Admin pekee ndiye anaweza kuona (kupitia route iliyolindwa hapa chini).
PRIVATE_UPLOAD_FOLDER = os.path.join(app.root_path, "private_uploads", "id_documents")
app.config["PRIVATE_UPLOAD_FOLDER"] = PRIVATE_UPLOAD_FOLDER
os.makedirs(PRIVATE_UPLOAD_FOLDER, exist_ok=True)

# --- CLOUDINARY (Uhifadhi wa Picha wa KUDUMU na SALAMA) ---
# MUHIMU: Render (kama huduma nyingi za "cloud" za bure) hutumia hifadhi ya
# MUDA TU - faili zozote zilizohifadhiwa ndani ya app zinafutika kila deploy
# mpya. Cloudinary ni huduma ya NJE (bure, HAIHITAJI kadi ya benki) ambayo
# inahifadhi picha kwa kudumu, salama, na kwa uhakika zaidi.
#
# JINSI YA KUWEZESHA: Weka Environment Variable "CLOUDINARY_URL" (Render)
# yenye muundo: cloudinary://<api_key>:<api_secret>@<cloud_name>
# (Cloudinary console inakupa hii moja kwa moja baada ya kujisajili bure).
CLOUDINARY_CONFIGURED = bool(os.environ.get("CLOUDINARY_URL"))
if CLOUDINARY_CONFIGURED:
    import cloudinary
    import cloudinary.uploader
    import cloudinary.utils
    cloudinary.config(secure=True)
    print("[Storage] Cloudinary IMEWEZESHWA - picha zitahifadhiwa kwa kudumu na salama.")
else:
    print("[Storage] ONYO: CLOUDINARY_URL haijawekwa - picha zitahifadhiwa "
          "ndani ya Render TU na ZITAPOTEA kila deploy mpya! Weka "
          "CLOUDINARY_URL kwenye Environment Variables haraka iwezekanavyo.")

# 3. Unganisha Database na App
db.init_app(app)

# 4. Import models na uunde meza zote za SQLite kiatomati
with app.app_context():
    try:
        import models
        from models import User, Mechanic, ServiceRequest, Review, Notification
        db.create_all()
        print("Database ya SQLite imewezeshwa: Faili la garifix.db na meza zote zipo tayari!")
    except Exception as e:
        print(f"Kosa wakati wa kuunda meza: {e}")


@app.route("/health")
@csrf.exempt
@limiter.exempt
def health():
    return "GariFix Tanzania is running", 200


# Decorators za Ulinzi (Authorization)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Tafadhali ingia kwenye akaunti yako kwanza.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def safe_int(value, default=0):
    """Geuza thamani ya form kuwa integer kwa usalama (epuka hitilafu MySQL)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if session.get("role") not in roles:
                flash("Hauruhusiwi kufungua ukurasa huu.", "danger")
                return redirect(url_for("home"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# --- Uthibitisho wa Email na Reset Password (token salama, yenye muda) ---
def get_serializer():
    return URLSafeTimedSerializer(app.config["SECRET_KEY"])


def send_email_verification(user):
    """Tuma barua pepe ya uthibitisho kwa mtumiaji (customer au mechanic)."""
    if not user.email:
        return
    token = get_serializer().dumps(user.email, salt="email-verify-salt")
    verify_url = url_for("verify_email", token=token, _external=True)
    send_verification_email(user, verify_url)


class InvalidImageError(Exception):
    pass


def save_uploaded_image(file_storage, folder_hint="general", private=False):
    """
    Hifadhi picha KWA KUDUMU kwenye Cloudinary (kama imesanidiwa), au
    kwenye disk ya ndani ya Render kama "fallback" (ONYO: hii haitadumu).

    Inarudisha:
      - URL kamili (https://res.cloudinary.com/...) kama Cloudinary
        imewezeshwa na "private" ni False
      - "public_id" ya Cloudinary (kwa ku-generate signed URL baadaye)
        kama "private" ni True
      - jina la faili la ndani (uuid) kama Cloudinary haijasanidiwa
    """
    if not file_storage or file_storage.filename == "":
        return None

    is_valid, error_msg = validate_image_upload(file_storage)
    if not is_valid:
        raise InvalidImageError(error_msg)

    if CLOUDINARY_CONFIGURED:
        file_storage.stream.seek(0)
        upload_options = {
            "folder": f"garifix/{folder_hint}",
            "resource_type": "image",
            "overwrite": True,
            # --- UKANDAMIZAJI (COMPRESSION) WA KIOTOMATIKI ---
            # "quality: auto" - Cloudinary inachagua ubora bora zaidi
            # unaowezekana kwa ukubwa mdogo zaidi wa faili (algorithm yao
            # ya kisasa - haionekani tofauti kwa macho lakini inapunguza
            # MB kwa kiasi kikubwa).
            # "width/height/crop: limit" - kama picha ni kubwa kuliko
            # 1600x1600 pixels, inapunguzwa kiotomatiki (bila kuvuta
            # zilizo ndogo kuwa kubwa) - simu nyingi hupiga picha za
            # MB 5-15 ambazo ni kubwa mno kwa mahitaji ya wavuti.
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

    # --- FALLBACK: hifadhi ya ndani ya Render (haitadumu baada ya deploy) ---
    ext = os.path.splitext(secure_filename(file_storage.filename))[1]
    unique_name = f"{uuid.uuid4().hex}{ext}"
    target_folder = app.config["PRIVATE_UPLOAD_FOLDER"] if private else app.config["UPLOAD_FOLDER"]
    os.makedirs(target_folder, exist_ok=True)
    file_storage.save(os.path.join(target_folder, unique_name))
    return unique_name


def resolve_image_url(value, private=False):
    """
    Geuza thamani iliyohifadhiwa (kutoka save_uploaded_image) kuwa URL
    inayoweza kuonyeshwa kwenye <img src="...">. Inashughulikia hali zote
    tatu: Cloudinary URL kamili, Cloudinary public_id (private), au jina
    la faili la ndani la Render (fallback ya zamani).
    """
    if not value:
        return None
    if value.startswith("http://") or value.startswith("https://"):
        return value
    if private and CLOUDINARY_CONFIGURED:
        url = cloudinary.utils.private_download_url(value, "jpg", resource_type="image", type="private")
        return url
    # Fallback ya ndani (jina la faili tu)
    folder = "id_documents" if private else "uploads"
    return url_for("static", filename=f"{folder}/{value}") if not private else None


# Ruhusu templates kutumia resolve_image_url() moja kwa moja, mfano:
# {{ resolve_image_url(mechanic.profile_photo) }}
app.jinja_env.globals["resolve_image_url"] = resolve_image_url


# Context Processor - inagundua kama ukurasa unafunguliwa NDANI YA APP ya
# Android (kupitia User-Agent maalum tuliyoongeza kwenye WebView), ili
# templates ziweze kuficha vitu vya "website" visivyohitajika ndani ya app
# Context Processor - salamu ya wakati (asubuhi/mchana/usiku) kwa ajili ya
# topbar ya dashboard zote (Customer, Fundi, Muuzaji, Admin)
@app.context_processor
def inject_greeting():
    from datetime import datetime
    hour = datetime.now().hour
    if 5 <= hour < 12:
        greeting = "Habari za asubuhi"
    elif 12 <= hour < 18:
        greeting = "Habari za mchana"
    else:
        greeting = "Habari za usiku"
    return dict(time_greeting=greeting)


# (mfano footer - Bottom Navigation ya app tayari inatosha kwa urambazaji).
@app.context_processor
def inject_app_mode():
    ua = request.headers.get("User-Agent", "")
    # "Android" pekee (siyo alama yetu maalum ya "GariFixAndroidApp") -
    # inagundua MTUMIAJI YEYOTE wa simu ya Android (hata kwenye Chrome
    # ya kawaida, siyo lazima awe na app yetu tayari) - kwa ajili ya
    # kuonyesha kiungo cha "Pakua App" kwa hadhira sahihi TU.
    is_android_browser = "Android" in ua and "GariFixAndroidApp" not in ua
    apk_available = os.path.exists(os.path.join(app.static_folder, "downloads", "GariFix.apk"))
    return dict(
        is_app_mode="GariFixAndroidApp" in ua,
        is_android_browser=is_android_browser,
        apk_available=apk_available,
        google_oauth_enabled=GOOGLE_OAUTH_ENABLED,
    )


# Salamu ya wakati (Habari za Asubuhi/Mchana/Jioni/Usiku) - kwa saa za
# Afrika Mashariki (EAT, UTC+3), bila kujali server iko wapi duniani.
@app.context_processor
def inject_time_greeting():
    from datetime import datetime, timedelta
    eat_hour = (datetime.utcnow() + timedelta(hours=3)).hour
    if 5 <= eat_hour < 12:
        greeting = "Habari za Asubuhi"
    elif 12 <= eat_hour < 16:
        greeting = "Habari za Mchana"
    elif 16 <= eat_hour < 19:
        greeting = "Habari za Jioni"
    else:
        greeting = "Habari za Usiku"
    return dict(time_greeting=greeting)


# Context Processor kwa ajili ya taarifa za mtumiaji aliyeingia
@app.context_processor
def inject_user():
    if "user_id" in session:
        user = db.session.get(User, session["user_id"])
        notification_count = 0
        if user:
            # Idadi ya arifa ZISIZOSOMWA (unread) - sawa kwa role zote,
            # inatoka moja kwa moja kwenye jedwali la Notification.
            notification_count = Notification.query.filter_by(user_id=user.id, is_read=False).count()
        return dict(current_user=user, notification_count=notification_count)
    return dict(current_user=None, notification_count=0)


# Email Verification - INAWEZESHWA (enabled). Mteja/Fundi asiyethibitisha
# email yake anazuiliwa kufikia dashboard au ukurasa mwingine wowote wa
# ndani, na anaelekezwa moja kwa moja /verify-pending mpaka athibitishe.
# Barua pepe zinatumwa kupitia Brevo API (siyo SMTP) - inafanya kazi
# vizuri kwenye Render free tier. Uthibitisho wa FUNDI (Mechanic.verified)
# na Admin HAUATHIRIWI na hii - unaendelea kufanya kazi kama kawaida.
_EMAIL_VERIFICATION_EXEMPT_ENDPOINTS = {
    "verify_pending", "resend_verification", "verify_email",
    "logout", "static", "home", "login", "register_choice",
    "customer_register", "mechanic_register", "search_mechanics",
    "terms", "download_app", "app_home", "app_account",
    "forgot_password_email", "reset_password_email",
    "register_fcm_token", "notifications_dropdown",
}


@app.before_request
def enforce_email_verification():
    if "user_id" not in session:
        return None
    if request.endpoint in _EMAIL_VERIFICATION_EXEMPT_ENDPOINTS:
        return None
    user = db.session.get(User, session["user_id"])
    if not user or user.role not in ("customer", "mechanic"):
        return None
    if not user.email_verified:
        return redirect(url_for("verify_pending"))
    return None


@app.route("/download-app")
def download_app():
    """Kupakua APK ya Android moja kwa moja kutoka website. Inaangalia
    kwanza kama faili lipo (baada ya admin kuliweka kwenye
    static/downloads/GariFix.apk) - likiwa halipo bado, inaonyesha ujumbe
    wa maelezo badala ya '404 haieleweki'."""
    apk_path = os.path.join(app.static_folder, "downloads", "GariFix.apk")
    if not os.path.exists(apk_path):
        flash("APK bado haijapakiwa kwenye server. Tafadhali jaribu tena baadaye.", "warning")
        return redirect(url_for("home"))
    return send_from_directory(
        os.path.join(app.static_folder, "downloads"),
        "GariFix.apk",
        as_attachment=True,
        download_name="GariFix.apk"
    )


@app.route("/")
def home():
    from sqlalchemy import func

    top_mechanics_query = (
        db.session.query(
            Mechanic,
            func.avg(Review.rating).label("avg_rating"),
            func.count(Review.id).label("review_count")
        )
        .join(Review, Review.mechanic_id == Mechanic.id)
        .join(User, Mechanic.user_id == User.id)
        .filter(Mechanic.verified == "approved", User.status == "active")
        .group_by(Mechanic.id)
        .order_by(func.avg(Review.rating).desc(), func.count(Review.id).desc())
        .limit(6)
        .all()
    )
    top_mechanics = [
        {"mechanic": m, "avg_rating": round(float(avg_rating), 1), "review_count": review_count}
        for m, avg_rating, review_count in top_mechanics_query
    ]

    return render_template("home.html", top_mechanics=top_mechanics)


def notify_user(user, title, body, data=None):
    """
    Tuma arifa kwa mtumiaji - inafanya MAMBO MAWILI kila wakati:
      1. Inahifadhi rekodi ya Notification kwenye database (kwa ajili ya
         'dropdown' ya bell icon na kuhesabu 'unread' kwa usahihi)
      2. Inatuma PUSH notification halisi (FCM) kama app ya Android
         ime-fungwa (kupitia send_notification iliyokuwepo tayari)

    Tumia HII (notify_user) badala ya kuita send_notification() moja kwa
    moja popote kwenye app.py - inafanya kile kile cha zamani, ikiwa na
    ziada ya kuhifadhi kwenye database.
    """
    url = (data or {}).get("url")
    try:
        notif = Notification(user_id=user.id, title=title, body=body, url=url)
        db.session.add(notif)
        db.session.commit()
    except Exception as e:
        print(f"[Notification-DB-ERROR] Imeshindikana kuhifadhi arifa: {e}")
        db.session.rollback()

    send_notification(user, title=title, body=body, data=data)


def role_dashboard_url():
    """Rudisha URL sahihi ya dashboard kutegemea role ya mtumiaji aliye-login
    sasa (au None kama hakuna aliye-login)."""
    role = session.get("role")
    if role == "customer":
        return url_for("customer_dashboard")
    elif role == "mechanic":
        return url_for("mechanic_dashboard")
    elif role == "admin":
        return url_for("admin_dashboard", user_id=session.get("user_id"))
    return None


@app.route("/app-home")
def app_home():
    """Kwa ajili ya 'Home' tab ya Bottom Navigation ya App ya Android -
    inampeleka mtumiaji kwenye dashboard sahihi kama ame-login, au home
    page ya kawaida kama bado hajaingia."""
    dashboard_url = role_dashboard_url()
    if dashboard_url:
        return redirect(dashboard_url)
    return redirect(url_for("home"))


@app.route("/app-account")
def app_account():
    """Kwa ajili ya 'Akaunti' tab ya Bottom Navigation ya App ya Android -
    ikiwa mtumiaji tayari ame-login, inampeleka moja kwa moja kwenye
    ukurasa sahihi wa profile/akaunti yake (kutegemea role) - BILA
    kupitia /login kwanza (hii ilikuwa ikisababisha ombi la ziada kila
    wakati tab hii ilipobonyezwa, likichangia hitilafu ya '429 Too Many
    Requests' kwenye kikomo maalum cha /login). Kama bado hajaingia,
    ndipo inampeleka /login."""
    role = session.get("role")
    if role == "mechanic":
        return redirect(url_for("own_mechanic_profile"))
    elif role == "customer":
        return redirect(url_for("customer_dashboard"))
    elif role == "admin":
        return redirect(url_for("admin_dashboard", user_id=session.get("user_id")))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if request.method == "GET" and "user_id" in session:
        dashboard_url = role_dashboard_url()
        if dashboard_url:
            return redirect(dashboard_url)

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter(
            or_(User.phone == identifier, User.email == identifier)
        ).first()

        if user and check_password_hash(user.password, password):
            if user.status == "blocked":
                flash("Akaunti yako imezuiwa (blocked) na Admin. Wasiliana na msimamizi wa mfumo kwa maelezo zaidi.", "danger")
                return redirect(url_for("login"))

            if user.role == "mechanic":
                mechanic = Mechanic.query.filter_by(user_id=user.id).first()
                if mechanic:
                    if mechanic.verified == "pending":
                        flash("Akaunti yako bado inasubiri idhini (approval) ya Admin.", "warning")
                        return redirect(url_for("login"))
                    elif mechanic.verified == "rejected":
                        flash("Usajili wako umekataliwa na Admin.", "danger")
                        return redirect(url_for("login"))

            # "Remember Me" - ikiwa haijachaguliwa, session ni ya kawaida tu
            # (inaisha ukifunga browser); ikiwa imechaguliwa, inadumu siku 7
            # (kama tulivyosanidi kwenye PERMANENT_SESSION_LIFETIME)
            session.permanent = bool(request.form.get("remember_me"))
            session["user_id"] = user.id
            session["role"] = user.role

            if user.role == "admin":
                return redirect(url_for("admin_dashboard", user_id=user.id))
            elif user.role == "mechanic":
                return redirect(url_for("mechanic_dashboard"))
            else:
                return redirect(url_for("customer_dashboard"))

        flash("Namba ya simu/Email au nenosiri si sahihi.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Umetoka kwenye mfumo kikamilifu.", "info")
    return redirect(url_for("login"))


@app.route("/api/register-fcm-token", methods=["POST"])
@csrf.exempt
@limiter.exempt
def register_fcm_token():
    """App ya Android inatuma FCM token hapa baada ya mtumiaji ku-login,
    ili mfumo uweze kumtumia push notifications. Imetolewa kwenye ulinzi wa
    CSRF (@csrf.exempt) kwa sababu inaitwa kupitia JavaScript fetch() ya
    moja kwa moja kutoka Android WebView (siyo fomu ya kawaida yenye
    csrf_token).

    MUHIMU: HATUTUMII @login_required hapa kwa MAKUSUDI - route hiyo
    ingemrudisha (redirect) mtumiaji kwenda /login akiwa hajaingia, na
    kwa kuwa fetch() inafuata "redirects" kiotomatiki, hii ingesababisha
    ombi la ziada la GET /login KILA WAKATI app inapojaribu kutuma FCM
    token bila mtumiaji kuwa amelogin (mfano akiwa kwenye ukurasa wa
    /login wenyewe) - ikichanganyika na kikomo maalum cha route ya
    /login (rate limit), ilisababisha hitilafu ya "429 Too Many
    Requests". Badala yake, tunaangalia session WENYEWE hapa na
    kurudisha JSON error ya moja kwa moja (bila redirect yoyote) kama
    mtumiaji hajaingia."""
    if "user_id" not in session:
        return {"status": "error", "message": "Haujaingia (not logged in)"}, 401

    if request.is_json:
        token = (request.get_json(silent=True) or {}).get("fcm_token")
    else:
        token = request.form.get("fcm_token")

    user = db.session.get(User, session["user_id"])
    if token and user:
        user.fcm_token = token
        db.session.commit()
        return {"status": "ok"}, 200
    return {"status": "error", "message": "fcm_token haipo"}, 400


@app.route("/notifications/dropdown")
@limiter.exempt
@login_required
def notifications_dropdown():
    """Inarudisha HTML ndogo ya orodha ya arifa za hivi karibuni (kwa
    ndani ya 'dropdown' ya bell icon) - inaitwa kupitia AJAX kila
    dropdown inapofunguliwa, ili idadi ya 'unread' iwe sahihi kila wakati."""
    user_id = session["user_id"]
    notifications = (
        Notification.query.filter_by(user_id=user_id)
        .order_by(Notification.created_at.desc())
        .limit(10)
        .all()
    )
    return render_template("_notifications_dropdown.html", notifications=notifications)


@app.route("/notifications/<int:id>/open")
@login_required
def open_notification(id):
    """Akibonyeza arifa mahususi - inaitia alama 'imesomwa' (read) kisha
    inampeleka kwenye ukurasa husika (url iliyohifadhiwa)."""
    notif = Notification.query.get_or_404(id)
    if notif.user_id != session["user_id"]:
        flash("Huna ruhusa ya kuona arifa hii.", "danger")
        return redirect(url_for("home"))

    notif.is_read = True
    db.session.commit()

    return redirect(notif.url or url_for("home"))


@app.route("/notifications/mark-all-read", methods=["POST"])
@login_required
def mark_all_notifications_read():
    """Weka arifa ZOTE za mtumiaji huyu kuwa 'zimesomwa' kwa mara moja."""
    Notification.query.filter_by(user_id=session["user_id"], is_read=False).update({"is_read": True})
    db.session.commit()
    return redirect(request.referrer or url_for("home"))


@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def forgot_password():
    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        user = User.query.filter_by(phone=phone).first()

        if not user:
            flash("Hakuna akaunti yenye namba hii ya simu.", "danger")
            return redirect(url_for("forgot_password"))

        # Weka kitambulisho cha muda (session) kinachoruhusu ukurasa wa
        # reset-password kufanya kazi kwa dakika chache tu.
        session["reset_user_id"] = user.id
        flash(f"Umethibitishwa, {user.full_name}. Sasa weka password mpya.", "success")
        return redirect(url_for("reset_password"))

    return render_template("forgot_password.html")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    user_id = session.get("reset_user_id")
    if not user_id:
        flash("Tafadhali thibitisha namba yako ya simu kwanza.", "warning")
        return redirect(url_for("forgot_password"))

    user = db.session.get(User, user_id)
    if not user:
        session.pop("reset_user_id", None)
        flash("Tatizo limetokea, jaribu tena.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(password) < 6:
            flash("Password lazima iwe na urefu wa herufi 6 au zaidi.", "danger")
            return redirect(url_for("reset_password"))

        if password != confirm_password:
            flash("Password na Rudia Password hazifanani.", "danger")
            return redirect(url_for("reset_password"))

        user.password = generate_password_hash(password)
        db.session.commit()
        session.pop("reset_user_id", None)

        flash("Password yako imebadilishwa kikamilifu! Sasa unaweza kuingia.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", user=user)


@app.route("/verify-email/<token>")
def verify_email(token):
    try:
        email = get_serializer().loads(token, salt="email-verify-salt", max_age=86400)  # Saa 24
    except SignatureExpired:
        flash("Link ya uthibitisho imeisha muda (masaa 24). Bofya 'Tuma Tena' kupata mpya.", "warning")
        return redirect(url_for("login"))
    except BadSignature:
        flash("Link ya uthibitisho si sahihi.", "danger")
        return redirect(url_for("login"))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Akaunti haikupatikana.", "danger")
        return redirect(url_for("login"))

    user.email_verified = True
    db.session.commit()
    flash("Hongera! Email yako imethibitishwa kikamilifu.", "success")
    return redirect(url_for("verify_pending"))


@app.route("/verify-pending")
@login_required
def verify_pending():
    user = db.session.get(User, session["user_id"])
    if user.email_verified or user.role not in ("customer", "mechanic"):
        # Tayari amethibitishwa (au ni admin) - mpeleke moja kwa moja dashboard yake
        if user.role == "mechanic":
            return redirect(url_for("mechanic_dashboard"))
        elif user.role == "admin":
            return redirect(url_for("admin_dashboard", user_id=user.id))
        return redirect(url_for("customer_dashboard"))
    return render_template("verify_pending.html", user=user)


@app.route("/resend-verification")
@login_required
def resend_verification():
    user = db.session.get(User, session["user_id"])
    if not user.email:
        flash("Huna email iliyowekwa kwenye akaunti yako.", "warning")
    elif user.email_verified:
        flash("Email yako tayari imethibitishwa.", "info")
    else:
        send_email_verification(user)
        flash("Barua ya uthibitisho imetumwa tena. Tafadhali angalia email/spam yako.", "success")

    return redirect(url_for("verify_pending"))


@app.route("/forgot-password-email", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def forgot_password_email():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        user = User.query.filter_by(email=email).first()

        if user:
            token = get_serializer().dumps(user.email, salt="password-reset-salt")
            user.reset_token = token
            db.session.commit()
            reset_url = url_for("reset_password_email", token=token, _external=True)
            send_password_reset_email(user, reset_url)

        # Ujumbe uleule hata kama email haipo - kuzuia mtu kugundua ni email
        # zipi zimesajiliwa kwenye mfumo (email enumeration).
        flash("Kama email hiyo ipo kwenye mfumo wetu, tumekutumia link ya kubadilisha password. Angalia inbox/spam yako.", "info")
        return redirect(url_for("login"))

    return render_template("forgot_password_email.html")


@app.route("/reset-password-email/<token>", methods=["GET", "POST"])
def reset_password_email(token):
    try:
        email = get_serializer().loads(token, salt="password-reset-salt", max_age=3600)  # Saa 1
    except SignatureExpired:
        flash("Link ya kubadilisha password imeisha muda (saa 1). Omba mpya.", "warning")
        return redirect(url_for("forgot_password_email"))
    except BadSignature:
        flash("Link si sahihi.", "danger")
        return redirect(url_for("forgot_password_email"))

    user = User.query.filter_by(email=email).first()
    if not user or user.reset_token != token:
        flash("Link hii tayari imetumika au si sahihi. Omba mpya.", "danger")
        return redirect(url_for("forgot_password_email"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(password) < 6:
            flash("Password lazima iwe na urefu wa herufi 6 au zaidi.", "danger")
            return redirect(request.url)

        if password != confirm_password:
            flash("Password na Rudia Password hazifanani.", "danger")
            return redirect(request.url)

        user.password = generate_password_hash(password)
        user.reset_token = None
        db.session.commit()

        flash("Password yako imebadilishwa kikamilifu! Sasa unaweza kuingia.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password_email.html", user=user)


@app.route("/setup-migrate")
def setup_migrate():
    """
    Sawazisha (ALTER TABLE) database halisi na muundo wa sasa wa models.py.

    TATIZO INAYOSULUHISHWA: db.create_all() hutengeneza majedwali MAPYA
    yasiyokuwepo TU - haiongezi "column" mpya kwenye jedwali ambalo tayari
    lilikuwepo. Kwa hiyo ukiongeza uwanja mpya kwenye model (mfano
    Seller.business_type) baada ya database kuwa tayari imeshaundwa, database
    halisi haitakuwa nayo mpaka usawazishe kwa mkono - hapa ndipo route hii
    inasaidia.

    JINSI YA KUTUMIA (bila kuhitaji Shell):
        https://your-app.onrender.com/setup-migrate?key=ADMIN_SETUP_KEY

    Salama kuita mara nyingi kadri unavyotaka - haiathiri data iliyopo,
    inaongeza tu columns zinazokosekana (haifuti wala kubadilisha zilizopo).
    """
    setup_key = os.environ.get("ADMIN_SETUP_KEY")
    if not setup_key:
        return "Kipengele hiki hakijawezeshwa kwenye server hii.", 403

    provided_key = request.args.get("key")
    if provided_key != setup_key:
        return "Ufunguo (key) si sahihi.", 403

    from sqlalchemy import inspect, text
    from sqlalchemy import Enum as SAEnum
    import traceback

    try:
        db.create_all()

        inspector = inspect(db.engine)
        existing_tables = set(inspector.get_table_names())  # SWALI MOJA TU (round-trip 1)
        added = []
        enum_updated = []
        errors = []

        # LOOP MOJA TU kwa kila jedwali - inachukua taarifa za columns
        # MARA MOJA (siyo mara mbili), kisha inatumia taarifa hizo hizo
        # kwa kazi zote mbili: (1) kuongeza column mpya (2) kupanua ENUM
        # zilizopo. Hii inapunguza idadi ya "round-trips" kwenda database
        # ya mbali (Aiven) kwa kiasi kikubwa, ikizuia "timeout" kwenye
        # majedwali mengi.
        for table in db.metadata.sorted_tables:
            try:
                if table.name not in existing_tables:
                    continue
                db_columns = {c["name"]: c for c in inspector.get_columns(table.name)}
            except Exception as e:
                errors.append(f"{table.name} (soma columns): {e}")
                continue

            for column in table.columns:
                try:
                    if column.name not in db_columns:
                        # Column MPYA - haipo kabisa kwenye database halisi
                        col_type = column.type.compile(dialect=db.engine.dialect)
                        ddl = f"ALTER TABLE {table.name} ADD COLUMN `{column.name}` {col_type}"
                        with db.engine.begin() as conn:
                            conn.execute(text(ddl))
                        added.append(f"{table.name}.{column.name}")
                    elif isinstance(column.type, SAEnum):
                        # Column IPO tayari - angalia kama ni ENUM
                        # inayohitaji kupanuliwa (thamani mpya kwenye model
                        # ambazo hazipo database halisi)
                        model_values = set(column.type.enums)
                        db_values = set(getattr(db_columns[column.name]["type"], "enums", []) or [])
                        if model_values - db_values:
                            col_type_sql = column.type.compile(dialect=db.engine.dialect)
                            ddl = f"ALTER TABLE {table.name} MODIFY COLUMN `{column.name}` {col_type_sql}"
                            with db.engine.begin() as conn:
                                conn.execute(text(ddl))
                            enum_updated.append(f"{table.name}.{column.name}: {sorted(db_values)} -> {sorted(model_values)}")
                except Exception as e:
                    errors.append(f"{table.name}.{column.name}: {e}")

        html = "<h2>Matokeo ya Database Migration</h2>"
        if added:
            html += "<p><strong>Columns mpya zilizoongezwa:</strong></p><ul>"
            html += "".join(f"<li>{a}</li>" for a in added) + "</ul>"
        if enum_updated:
            html += "<p><strong>ENUM zilizopanuliwa (thamani mpya ziliongezwa):</strong></p><ul>"
            html += "".join(f"<li>{u}</li>" for u in enum_updated) + "</ul>"
        if not added and not enum_updated:
            html += "<p>Database tayari inalingana kikamilifu na models.py.</p>"
        if errors:
            html += "<p style='color:red'><strong>Hitilafu (kama zipo):</strong></p><ul>"
            html += "".join(f"<li>{e}</li>" for e in errors) + "</ul>"

        return html

    except Exception:
        tb = traceback.format_exc()
        return f"<h2>Hitilafu Isiyotarajiwa</h2><pre style='white-space:pre-wrap;color:red;'>{tb}</pre>", 500


def setup_admin():
    """
    Njia mbadala ya kutengeneza akaunti ya kwanza ya ADMIN bila kuhitaji
    ufikiaji wa 'Shell' (Render free tier mara nyingi haina Shell access,
    hivyo amri ya 'flask create-admin' haiwezi kutumika huko).

    JINSI YA KUTUMIA:
    1. Kwenye Render, weka Environment Variable: ADMIN_SETUP_KEY=weka-siri-ndefu-hapa
    2. Fungua: https://your-app.onrender.com/setup-admin?key=weka-siri-ndefu-hapa
    3. Jaza fomu kutengeneza akaunti ya admin

    Kama ADMIN_SETUP_KEY haijawekwa kabisa (haipo), ukurasa huu haufanyi kazi
    kabisa - hii inazuia mtu yeyote kutengeneza admin bila ruhusa.
    """
    setup_key = os.environ.get("ADMIN_SETUP_KEY")
    if not setup_key:
        flash("Kipengele hiki hakijawezeshwa kwenye server hii.", "danger")
        return redirect(url_for("login"))

    provided_key = request.args.get("key") or request.form.get("key")
    if provided_key != setup_key:
        flash("Ufunguo (key) si sahihi au haujawekwa kwenye URL (?key=...).", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        full_name = f"{first_name} {last_name}".strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not first_name or not last_name or not phone or not email:
            flash("Tafadhali jaza taarifa zote.", "danger")
            return redirect(url_for("setup_admin", key=setup_key))

        if password != confirm_password:
            flash("Password na Rudia Password hazifanani.", "danger")
            return redirect(url_for("setup_admin", key=setup_key))

        if User.query.filter(or_(User.phone == phone, User.email == email)).first():
            flash("Namba ya simu au email tayari inatumika.", "danger")
            return redirect(url_for("setup_admin", key=setup_key))

        admin = User(
            full_name=full_name,
            phone=phone,
            email=email,
            password=generate_password_hash(password),
            role="admin",
            status="active",
            email_verified=True
        )
        db.session.add(admin)
        db.session.commit()

        flash(f"Admin '{full_name}' ameundwa kikamilifu! Sasa unaweza kuingia kwa email au namba ya simu.", "success")
        return redirect(url_for("login"))

    return render_template("setup_admin.html", setup_key=setup_key)


# CUSTOMER ROUTES
@app.route("/terms")
def terms():
    return render_template("terms.html")


# --------------------------------------------------------------------
# GOOGLE OAUTH - Kumbuka Muhimu kuhusu WEBVIEW ya App:
# Google INAKATAA kufanya OAuth ndani ya WebView za app (sera yao ya
# usalama tangu 2016) - inafungua "browser ya nje" (Chrome ya kawaida)
# badala yake. Hii inamaanisha "session" (cookies) za WebView na za
# browser-ya-nje ni TOFAUTI KABISA - haziwezi kushirikiana moja kwa
# moja. Kwa hiyo, kwa mtumiaji anayetumia APP (tunatambua kwa
# User-Agent "GariFixAndroidApp"), badala ya kuweka session moja kwa
# moja kwenye callback (ambayo ingekuwa kwenye browser-ya-nje, isiyo na
# maana kwa WebView), tunatengeneza TOKEN FUPI YA MUDA (dakika 5) na
# kumpeleka kupitia "deep link" (garifix://auth-callback?token=X)
# ambayo App yenyewe (MainActivity.kt) inayo-intercept, kisha
# inaipakia ndani ya WebView kupitia /auth/google/complete?token=X -
# HAPO NDIYO session halisi ya WebView inawekwa.
# --------------------------------------------------------------------
_pending_app_google_logins = {}  # token -> {"expires": ts, ...data}
_PENDING_TOKEN_TTL_SECONDS = 300


def _cleanup_expired_google_tokens():
    now = datetime.utcnow().timestamp()
    expired = [t for t, d in _pending_app_google_logins.items() if d["expires"] < now]
    for t in expired:
        _pending_app_google_logins.pop(t, None)


@app.route("/auth/google/login")
def google_login():
    """Anzisha mchakato wa 'Ingia/Jisajili kwa Google'. ?role=customer au
    ?role=mechanic inaonyesha lengo (kwa usajili mpya - haiathiri watu
    wanaoingia kwa akaunti iliyopo tayari). Inatambua kama ombi limetoka
    ndani ya App yetu (User-Agent) na kuchagua 'callback' sahihi."""
    if not GOOGLE_OAUTH_ENABLED:
        flash("Kuingia kwa Google hakupatikani kwa sasa.", "warning")
        return redirect(url_for("login"))

    role = request.args.get("role", "customer")
    if role not in ("customer", "mechanic"):
        role = "customer"
    session["google_signup_role"] = role

    # MUHIMU: Kwa kuwa Google inalazimisha ombi hili lifunguke kwenye
    # BROWSER YA NJE (siyo WebView), kufikia hapa tayari kumefanyika
    # kwenye browser hiyo - User-Agent HAITAKUWA na alama ya app tena!
    # Kwa hiyo, App yenyewe (MainActivity.kt) inaongeza "?from_app=1"
    # kwenye URL KABLA ya kuifungua kwenye browser ya nje - hii ndiyo
    # inayosalimika hadi hapa (siyo User-Agent).
    is_from_app = request.args.get("from_app") == "1"
    callback_endpoint = "google_callback_app" if is_from_app else "google_callback"
    redirect_uri = url_for(callback_endpoint, _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


def _process_google_userinfo():
    """Kazi ya pamoja: chukua taarifa za mtumiaji kutoka Google baada ya
    authorize_access_token(). Inarudisha (email, full_name) au
    (None, None) kama imeshindikana."""
    try:
        token = oauth.google.authorize_access_token()
        user_info = token.get("userinfo") or oauth.google.userinfo()
    except Exception as e:
        app.logger.error(f"[Google OAuth] Hitilafu kwenye callback: {type(e).__name__}: {e}")
        return None, None

    email = (user_info or {}).get("email", "").strip().lower()
    full_name = (user_info or {}).get("name", "").strip()
    return email, full_name


@app.route("/auth/google/callback")
def google_callback():
    """Callback ya WEB ya kawaida (browser ya kompyuta/simu, SIYO app
    yetu) - inaendelea kutumia Flask session moja kwa moja, kwa kuwa
    ombi lote linatokea kwenye browser MOJA (hakuna 'handoff' kati ya
    WebView na browser nyingine)."""
    if not GOOGLE_OAUTH_ENABLED:
        return redirect(url_for("login"))

    email, full_name = _process_google_userinfo()
    if not email:
        flash("Imeshindikana kuunganisha na Google. Jaribu tena au tumia usajili wa kawaida.", "danger")
        return redirect(url_for("login"))

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        if not existing_user.email_verified:
            existing_user.email_verified = True
            db.session.commit()
        session.permanent = True
        session["user_id"] = existing_user.id
        session["role"] = existing_user.role
        dashboard_url = role_dashboard_url()
        return redirect(dashboard_url or url_for("home"))

    role = session.pop("google_signup_role", "customer")
    session["google_pending_email"] = email
    session["google_pending_name"] = full_name

    if role == "mechanic":
        return redirect(url_for("mechanic_register"))
    return redirect(url_for("customer_register"))


@app.route("/auth/google/callback/app")
def google_callback_app():
    """Callback MAALUM kwa App (inafikiwa na 'browser ya nje' baada ya
    Google - SIYO WebView). Kwa kuwa session hii ni ya browser-ya-nje
    (haina maana kwa WebView ya app), tunatengeneza token fupi ya muda
    na kumrudisha kwenye APP kupitia 'deep link' - App itapakia
    /auth/google/complete?token=X ndani ya WebView yake yenyewe ili
    kuweka session HALISI pale."""
    if not GOOGLE_OAUTH_ENABLED:
        return redirect(url_for("login"))

    email, full_name = _process_google_userinfo()
    if not email:
        # Bado tuko kwenye browser-ya-nje - onyesha ujumbe hapa, mtumiaji
        # atarudi appni mwenyewe
        flash("Imeshindikana kuunganisha na Google. Jaribu tena kwenye app.", "danger")
        return redirect(url_for("login"))

    _cleanup_expired_google_tokens()
    token = secrets.token_urlsafe(32)
    role = session.pop("google_signup_role", "customer")

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        _pending_app_google_logins[token] = {
            "expires": datetime.utcnow().timestamp() + _PENDING_TOKEN_TTL_SECONDS,
            "action": "login",
            "user_id": existing_user.id,
        }
    else:
        _pending_app_google_logins[token] = {
            "expires": datetime.utcnow().timestamp() + _PENDING_TOKEN_TTL_SECONDS,
            "action": "register",
            "email": email,
            "name": full_name,
            "role": role,
        }

    return redirect(f"garifix://auth-callback?token={token}")


@app.route("/auth/google/complete")
def google_complete():
    """App (MainActivity.kt) inapakia URL hii NDANI YA WEBVIEW yake
    baada ya kupokea 'deep link' - hapa ndipo session HALISI ya
    WebView inawekwa (tofauti na callback ya awali iliyokuwa kwenye
    browser-ya-nje)."""
    token = request.args.get("token", "")
    _cleanup_expired_google_tokens()
    data = _pending_app_google_logins.pop(token, None)

    if not data or data["expires"] < datetime.utcnow().timestamp():
        flash("Muda wa kuingia kwa Google umeisha. Jaribu tena.", "warning")
        return redirect(url_for("login"))

    if data["action"] == "login":
        user = db.session.get(User, data["user_id"])
        if not user:
            flash("Akaunti haikupatikana. Jaribu tena.", "danger")
            return redirect(url_for("login"))
        if not user.email_verified:
            user.email_verified = True
            db.session.commit()
        session.permanent = True
        session["user_id"] = user.id
        session["role"] = user.role
        dashboard_url = role_dashboard_url()
        return redirect(dashboard_url or url_for("home"))

    # action == "register"
    session["google_pending_email"] = data["email"]
    session["google_pending_name"] = data["name"]
    if data["role"] == "mechanic":
        return redirect(url_for("mechanic_register"))
    return redirect(url_for("customer_register"))


@app.route("/register")
def register_choice():
    """Ukurasa wa kuchagua: Nataka kujisajili kama Mteja au kama Fundi."""
    return render_template("register_choice.html")


@app.route("/customer/register", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def customer_register():
    # Kama anatoka kwenye "Jisajili kwa Google" - email/jina tayari
    # vimethibitishwa, password si lazima (tunatengeneza moja kwa siri)
    via_google = "google_pending_email" in session

    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        full_name = f"{first_name} {last_name}".strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if via_google:
            # Email haiwezi kubadilishwa (imefungwa) ikiwa inatoka Google
            email = session.get("google_pending_email", email)
            password = password or secrets.token_urlsafe(24)
            confirm_password = password

        if not first_name or not last_name:
            flash("Tafadhali jaza jina la kwanza na la mwisho.", "danger")
            return redirect(url_for("customer_register"))

        if not email:
            flash("Tafadhali weka email.", "danger")
            return redirect(url_for("customer_register"))

        if not request.form.get("agree_terms"):
            flash("Lazima ukubaliane na Vigezo na Masharti ili kuendelea.", "danger")
            return redirect(url_for("customer_register"))

        if not via_google and password != confirm_password:
            flash("Password na Rudia Password hazifanani.", "danger")
            return redirect(url_for("customer_register"))

        if User.query.filter_by(phone=phone).first():
            flash("Namba hii ya simu tayari imesajiliwa.", "danger")
            return redirect(url_for("customer_register"))

        if User.query.filter_by(email=email).first():
            flash("Barua pepe hii tayari imesajiliwa.", "danger")
            return redirect(url_for("customer_register"))

        hashed_password = generate_password_hash(password)
        try:
            photo_filename = save_uploaded_image(request.files.get("profile_photo"), folder_hint="profiles")
        except InvalidImageError as e:
            flash(str(e), "danger")
            return redirect(url_for("customer_register"))

        new_customer = User(
            full_name=full_name,
            phone=phone,
            email=email,
            password=hashed_password,
            role="customer",
            profile_photo=photo_filename,
            email_verified=via_google
        )
        db.session.add(new_customer)
        db.session.commit()

        if via_google:
            session.pop("google_pending_email", None)
            session.pop("google_pending_name", None)
            session.permanent = True
            session["user_id"] = new_customer.id
            session["role"] = new_customer.role
            flash("Usajili umefanikiwa kupitia Google! Karibu GariFix.", "success")
            return redirect(url_for("customer_dashboard"))

        send_email_verification(new_customer)

        flash("Usajili umefanikiwa! Sasa unaweza kuingia (login).", "success")
        return redirect(url_for("login"))

    return render_template(
        "customer_register.html",
        google_prefill_email=session.get("google_pending_email"),
        google_prefill_name=session.get("google_pending_name"),
    )


@app.route("/customer/dashboard")
@login_required
@role_required("customer")
def customer_dashboard():
    user = db.session.get(User, session["user_id"])
    requests = ServiceRequest.query.filter_by(customer_id=user.id).all()

    total_requests = len(requests)
    pending_requests = sum(1 for r in requests if r.status == "pending")
    accepted_requests = sum(1 for r in requests if r.status == "accepted")
    completed_requests = sum(1 for r in requests if r.status == "completed")

    return render_template(
        "customer_dashboard.html",
        user=user,
        requests=requests,
        total_requests=total_requests,
        pending_requests=pending_requests,
        accepted_requests=accepted_requests,
        completed_requests=completed_requests
    )


@app.route("/customer/requests")
@login_required
@role_required("customer")
def customer_requests():
    user_id = session["user_id"]
    requests = ServiceRequest.query.filter_by(customer_id=user_id).order_by(ServiceRequest.created_at.desc()).all()
    return render_template("customer_requests.html", requests=requests)


@app.route("/customer/reviews")
@login_required
@role_required("customer")
def customer_reviews():
    user_id = session["user_id"]
    reviews = Review.query.filter_by(customer_id=user_id).order_by(Review.created_at.desc()).all()
    return render_template("customer_reviews.html", reviews=reviews)


# MECHANIC ROUTES
@app.route("/mechanic/register", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def mechanic_register():
    via_google = "google_pending_email" in session

    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        full_name = f"{first_name} {last_name}".strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if via_google:
            email = session.get("google_pending_email", email)
            password = password or secrets.token_urlsafe(24)
            confirm_password = password

        garage_name = request.form.get("garage_name", "").strip()
        region = request.form.get("region", "").strip()
        district = request.form.get("district", "").strip()
        ward = request.form.get("ward", "").strip()
        street = request.form.get("street", "").strip()
        experience = safe_int(request.form.get("experience"), default=0)
        description = request.form.get("description", "").strip()
        specializations = request.form.getlist("specialization")
        specialization = ", ".join(specializations)
        id_document_type = request.form.get("id_document_type", "").strip()

        if not first_name or not last_name:
            flash("Tafadhali jaza jina la kwanza na la mwisho.", "danger")
            return redirect(url_for("mechanic_register"))

        if not email:
            flash("Tafadhali weka email.", "danger")
            return redirect(url_for("mechanic_register"))

        if not request.form.get("agree_terms"):
            flash("Lazima ukubaliane na Vigezo na Masharti ili kuendelea.", "danger")
            return redirect(url_for("mechanic_register"))

        if not region or not district or not ward or not street:
            flash("Tafadhali jaza eneo lako kamili (Mkoa, Wilaya, Kata na Mtaa).", "danger")
            return redirect(url_for("mechanic_register"))

        if not via_google and password != confirm_password:
            flash("Password na Rudia Password hazifanani.", "danger")
            return redirect(url_for("mechanic_register"))

        id_doc_file = request.files.get("id_document")
        if not id_doc_file or id_doc_file.filename == "":
            flash("Tafadhali ambatanisha kitambulisho (NIDA, Leseni ya Udereva, au Kadi ya Mpiga Kura).", "danger")
            return redirect(url_for("mechanic_register"))

        if not id_document_type:
            flash("Tafadhali chagua aina ya kitambulisho ulichoambatanisha.", "danger")
            return redirect(url_for("mechanic_register"))

        # Angalia kama tayari kuna akaunti na simu/email hii. Kama ni fundi
        # aliyekataliwa (rejected) HAPO AWALI, mruhusu "kuomba upya" (update
        # taarifa zake za zamani badala ya kumzuia kabisa) - vinginevyo
        # (pending/approved, au akaunti ya role tofauti) mzuie kama kawaida.
        existing_by_phone = User.query.filter_by(phone=phone).first()
        existing_by_email = User.query.filter_by(email=email).first()

        reapplying_user = None
        for existing in (existing_by_phone, existing_by_email):
            if existing and existing.role == "mechanic" and existing.mechanic_profile and existing.mechanic_profile.verified == "rejected":
                reapplying_user = existing
                break

        if not reapplying_user:
            if existing_by_phone:
                flash("Namba hii ya simu tayari imesajiliwa.", "danger")
                return redirect(url_for("mechanic_register"))
            if existing_by_email:
                flash("Barua pepe hii tayari imesajiliwa.", "danger")
                return redirect(url_for("mechanic_register"))
        else:
            # Hakikisha simu/email mpya (kama zimebadilika) hazitumiwi na
            # akaunti NYINGINE (siyo hii hii tunayoiboresha)
            if existing_by_phone and existing_by_phone.id != reapplying_user.id:
                flash("Namba hii ya simu tayari imesajiliwa na akaunti nyingine.", "danger")
                return redirect(url_for("mechanic_register"))
            if existing_by_email and existing_by_email.id != reapplying_user.id:
                flash("Barua pepe hii tayari imesajiliwa na akaunti nyingine.", "danger")
                return redirect(url_for("mechanic_register"))

        filename = None
        id_document_filename = None
        try:
            filename = save_uploaded_image(request.files.get("profile_photo"), folder_hint="profiles")
            id_document_filename = save_uploaded_image(id_doc_file, folder_hint="id_documents", private=True)
        except InvalidImageError as e:
            flash(str(e), "danger")
            return redirect(url_for("mechanic_register"))

        hashed_password = generate_password_hash(password)

        if reapplying_user:
            # KUOMBA UPYA - sasisha taarifa za zamani badala ya kuunda mpya
            new_user = reapplying_user
            new_user.full_name = full_name
            new_user.phone = phone
            new_user.email = email
            new_user.password = hashed_password
            new_user.status = "active"

            new_mechanic = new_user.mechanic_profile
            new_mechanic.garage_name = garage_name
            new_mechanic.region = region
            new_mechanic.district = district
            new_mechanic.ward = ward
            new_mechanic.street = street
            new_mechanic.specialization = specialization
            new_mechanic.experience = experience
            new_mechanic.description = description
            if filename:
                new_mechanic.profile_photo = filename
            new_mechanic.id_document_type = id_document_type
            if id_document_filename:
                new_mechanic.id_document = id_document_filename
            new_mechanic.verified = "pending"
            db.session.commit()
        else:
            new_user = User(
                full_name=full_name,
                phone=phone,
                email=email,
                password=hashed_password,
                role="mechanic",
                email_verified=via_google
            )
            db.session.add(new_user)
            db.session.commit()

            new_mechanic = Mechanic(
                user_id=new_user.id,
                garage_name=garage_name,
                region=region,
                district=district,
                ward=ward,
                street=street,
                specialization=specialization,
                experience=experience,
                description=description,
                profile_photo=filename,
                id_document_type=id_document_type,
                id_document=id_document_filename,
                verified="pending"
            )
            db.session.add(new_mechanic)
            db.session.commit()
            if not via_google:
                send_email_verification(new_user)

        # Arifisha ADMIN WOTE - fundi mpya (au anayeomba upya) anasubiri idhini
        for admin_user in User.query.filter_by(role="admin").all():
            notify_user(
                admin_user,
                title="Fundi Mpya Anasubiri Idhini - GariFix",
                body=f"{full_name} ({garage_name}) amejisajili na anasubiri uthibitisho wako.",
                data={"type": "mechanic_pending", "mechanic_id": new_mechanic.id, "url": "/admin/mechanics"}
            )

        if via_google:
            session.pop("google_pending_email", None)
            session.pop("google_pending_name", None)
            session.permanent = True
            session["user_id"] = new_user.id
            session["role"] = "mechanic"
            flash("Usajili umefanikiwa kupitia Google! Akaunti yako inasubiri uthibitisho wa Admin.", "success")
            return redirect(url_for("mechanic_dashboard"))

        flash("Usajili umefanikiwa! Akaunti yako inasubiri uthibitisho (verification) wa Admin baada ya kukagua kitambulisho chako - utaweza kuingia mara tu ukishaidhinishwa.", "success")
        return redirect(url_for("login"))

    return render_template(
        "mechanic_register.html",
        google_prefill_email=session.get("google_pending_email"),
        google_prefill_name=session.get("google_pending_name"),
    )


@app.route("/dashboard")
@login_required
@role_required("mechanic")
def mechanic_dashboard():
    user = db.session.get(User, session["user_id"])
    mechanic = Mechanic.query.filter_by(user_id=user.id).first_or_404()
    requests = ServiceRequest.query.filter_by(mechanic_id=mechanic.id).order_by(ServiceRequest.created_at.desc()).all()

    return render_template("dashboard.html", mechanic=mechanic, user=user, requests=requests)


@app.route("/mechanic/profile", methods=["GET", "POST"])
@login_required
@role_required("mechanic")
def own_mechanic_profile():
    user = db.session.get(User, session["user_id"])
    mechanic = Mechanic.query.filter_by(user_id=user.id).first_or_404()

    if request.method == "POST":
        mechanic.garage_name = request.form.get("garage_name", "").strip()
        mechanic.experience = safe_int(request.form.get("experience"), default=mechanic.experience or 0)
        mechanic.description = request.form.get("description", "").strip()

        photo = request.files.get("profile_photo")
        if photo and photo.filename != "":
            filename = secure_filename(photo.filename)
            photo.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            mechanic.profile_photo = filename

        db.session.commit()
        flash("Taarifa zako zimesasishwa!", "success")
        return redirect(url_for("own_mechanic_profile"))

    reviews = Review.query.filter_by(mechanic_id=mechanic.id).all()
    avg_rating = db.session.query(func.avg(Review.rating)).filter_by(mechanic_id=mechanic.id).scalar() or 0

    return render_template(
        "mechanic_profile.html",
        mechanic=mechanic,
        reviews=reviews,
        average_rating=avg_rating,
        review_count=len(reviews),
        is_owner=True
    )


@app.route("/mechanic/requests")
@login_required
@role_required("mechanic")
def own_mechanic_requests():
    user = db.session.get(User, session["user_id"])
    mechanic = Mechanic.query.filter_by(user_id=user.id).first_or_404()
    requests = ServiceRequest.query.filter_by(mechanic_id=mechanic.id).order_by(ServiceRequest.created_at.desc()).all()
    return render_template("mechanic_requests.html", requests=requests)


@app.route("/mechanic/reviews")
@login_required
@role_required("mechanic")
def mechanic_reviews():
    user = db.session.get(User, session["user_id"])
    mechanic = Mechanic.query.filter_by(user_id=user.id).first_or_404()
    reviews = Review.query.filter_by(mechanic_id=mechanic.id).order_by(Review.created_at.desc()).all()
    return render_template("mechanic_reviews.html", reviews=reviews)


@app.route("/accept-request/<int:id>", methods=["POST"])
@login_required
@role_required("mechanic")
def accept_request(id):
    user = db.session.get(User, session["user_id"])
    mechanic = Mechanic.query.filter_by(user_id=user.id).first()
    service = ServiceRequest.query.get_or_404(id)

    if mechanic and service.mechanic_id == mechanic.id:
        service.status = "accepted"
        db.session.commit()
        notify_user(
            service.customer,
            title="Fundi Amekubali Ombi Lako - GariFix",
            body=f"{mechanic.user.full_name} amekubali kukusaidia na {service.vehicle_model}. Anakuja!",
            data={"type": "request_accepted", "request_id": service.id, "url": "/customer/requests"}
        )
        flash("Umekubali ombi hili la huduma.", "success")
    else:
        flash("Hauruhusiwi kutenda kitendo hiki.", "danger")

    return redirect(url_for("mechanic_dashboard"))


@app.route("/reject-request/<int:id>", methods=["POST"])
@login_required
@role_required("mechanic")
def reject_request(id):
    """Fundi anakataa ombi la huduma - mteja anapata arifa kwamba fundi
    huyu hawezi kushughulikia tatizo lake kwa muda huo, ili aweze
    kutafuta fundi mwingine."""
    user = db.session.get(User, session["user_id"])
    mechanic = Mechanic.query.filter_by(user_id=user.id).first()
    service = ServiceRequest.query.get_or_404(id)

    if mechanic and service.mechanic_id == mechanic.id and service.status == "pending":
        service.status = "rejected"
        db.session.commit()
        notify_user(
            service.customer,
            title="Fundi Hawezi Kukusaidia kwa Sasa - GariFix",
            body=f"{mechanic.user.full_name} hawezi kushughulikia tatizo la {service.vehicle_model} kwa muda huu. Tafadhali tafuta fundi mwingine.",
            data={"type": "request_rejected", "request_id": service.id, "url": "/customer/requests"}
        )
        flash("Umekataa ombi hili. Mteja amejulishwa.", "warning")
    else:
        flash("Hauruhusiwi kutenda kitendo hiki.", "danger")

    return redirect(url_for("mechanic_dashboard"))


@app.route("/complete-request/<int:id>", methods=["POST"])
@login_required
def complete_request(id):
    user = db.session.get(User, session["user_id"])
    service_request = ServiceRequest.query.get_or_404(id)

    if user.role == "admin":
        service_request.status = "completed"
        db.session.commit()
        flash("Huduma imewekwa kama Imekamilika.", "success")
        return redirect(url_for("admin_requests"))

    if user.role == "customer" and service_request.customer_id == user.id:
        if service_request.status != "accepted":
            flash("Huduma hii haiko tayari kuthibitishwa kuwa imekamilika.", "warning")
            return redirect(url_for("customer_requests"))
        service_request.status = "completed"
        db.session.commit()
        if service_request.mechanic:
            notify_user(
                service_request.mechanic.user,
                title="Huduma Imethibitishwa Kukamilika - GariFix",
                body=f"{user.full_name} amethibitisha kuwa kazi ya {service_request.vehicle_model} imekamilika. Ahsante!",
                data={"type": "request_completed", "request_id": service_request.id, "url": "/mechanic/requests"}
            )
        flash("Hongera! Umethibitisha kuwa huduma imekamilika. Tafadhali mpe fundi rating.", "success")
        if service_request.mechanic:
            return redirect(url_for("add_review", mechanic_id=service_request.mechanic.id))
        return redirect(url_for("customer_requests"))

    flash("Hauruhusiwi kubadilisha taarifa hii.", "danger")
    return redirect(url_for("home"))




# SEARCH & PUBLIC PROFILES
@app.route("/search/mechanics", methods=["GET", "POST"])
@login_required
@role_required("customer")
def search_mechanics():
    mechanics = []
    ratings = {}

    if request.method == "POST":
        region = request.form.get("region", "").strip()
        district = request.form.get("district", "").strip()
        specialization = request.form.get("specialization", "").strip()

        query = Mechanic.query.filter(Mechanic.verified == "approved")

        if region:
            query = query.filter(Mechanic.region.ilike(f"%{region}%"))
        if district:
            query = query.filter(Mechanic.district.ilike(f"%{district}%"))
        if specialization:
            query = query.filter(Mechanic.specialization.ilike(f"%{specialization}%"))

        mechanics = query.all()

        for mech in mechanics:
            avg = db.session.query(func.avg(Review.rating)).filter_by(mechanic_id=mech.id).scalar()
            cnt = Review.query.filter_by(mechanic_id=mech.id).count()
            ratings[mech.id] = {
                "average": round(avg, 1) if avg else 0,
                "count": cnt
            }

    return render_template("search_mechanics.html", mechanics=mechanics, ratings=ratings)


@app.route("/mechanic/<int:mechanic_id>")
def mechanic_profile(mechanic_id):
    mechanic = Mechanic.query.get_or_404(mechanic_id)
    reviews = Review.query.filter_by(mechanic_id=mechanic_id).order_by(Review.created_at.desc()).all()
    avg_rating = db.session.query(func.avg(Review.rating)).filter_by(mechanic_id=mechanic_id).scalar() or 0

    return render_template(
        "mechanic_profile_public.html",
        mechanic=mechanic,
        reviews=reviews,
        average_rating=avg_rating,
        review_count=len(reviews),
        is_owner=False
    )


@app.route("/request-service/<int:mechanic_id>", methods=["GET", "POST"])
@login_required
@role_required("customer")
def request_service(mechanic_id):
    mechanic = Mechanic.query.get_or_404(mechanic_id)

    if request.method == "POST":
        vehicle_model = request.form.get("vehicle_model", "").strip()
        problem_description = request.form.get("problem_description", "").strip()

        req_region = request.form.get("req_region", "").strip()
        req_district = request.form.get("req_district", "").strip()
        req_ward = request.form.get("req_ward", "").strip()
        req_street = request.form.get("req_street", "").strip()

        full_location = f"{req_region}, {req_district}, Kata ya {req_ward} ({req_street})"

        new_request = ServiceRequest(
            customer_id=session["user_id"],
            mechanic_id=mechanic.id,
            vehicle_model=vehicle_model,
            problem_description=problem_description,
            location=full_location
        )
        db.session.add(new_request)
        db.session.commit()

        notify_user(
            mechanic.user,
            title="Ombi Jipya la Huduma - GariFix",
            body=f"Mteja {session.get('user_id') and db.session.get(User, session['user_id']).full_name} ana tatizo la {vehicle_model}. Bofya kuona zaidi.",
            data={"type": "new_request", "request_id": new_request.id, "url": "/mechanic/requests"}
        )

        flash("Ombi lako limetumwa kwa fundi kikamilifu!", "success")
        return redirect(url_for("customer_requests"))

    return render_template("request_service.html", mechanic=mechanic)


@app.route("/review/<int:mechanic_id>", methods=["GET", "POST"])
@login_required
@role_required("customer")
def add_review(mechanic_id):
    mechanic = Mechanic.query.get_or_404(mechanic_id)

    if request.method == "POST":
        rating = request.form.get("rating")
        comment = request.form.get("comment", "").strip()

        review = Review(
            customer_id=session["user_id"],
            mechanic_id=mechanic.id,
            rating=int(rating),
            comment=comment
        )
        db.session.add(review)
        db.session.commit()

        notify_user(
            mechanic.user,
            title="Umepata Review Mpya - GariFix",
            body=f"{db.session.get(User, session['user_id']).full_name} amekupa rating ya {rating}/5.",
            data={"type": "new_review", "mechanic_id": mechanic.id, "url": "/mechanic/reviews"}
        )

        flash("Maoni yako yamehifadhiwa!", "success")
        return redirect(url_for("mechanic_profile", mechanic_id=mechanic.id))

    return render_template("review.html", mechanic=mechanic)


# ADMIN ROUTES
@app.route("/admin/dashboard/<int:user_id>")
@login_required
@role_required("admin")
def admin_dashboard(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("Mtumiaji hajapatikana.", "danger")
        return redirect(url_for("home"))

    total_mechanics = Mechanic.query.count()
    approved_mechanics = Mechanic.query.filter_by(verified="approved").count()
    total_customers = User.query.filter_by(role="customer").count()
    total_requests = ServiceRequest.query.count()

    pending_requests = ServiceRequest.query.filter_by(status="pending").count()
    accepted_requests = ServiceRequest.query.filter_by(status="accepted").count()
    completed_requests = ServiceRequest.query.filter_by(status="completed").count()

    return render_template(
        "admin_dashboard.html",
        user=user,
        total_mechanics=total_mechanics,
        approved_mechanics=approved_mechanics,
        total_customers=total_customers,
        total_requests=total_requests,
        pending_requests=pending_requests,
        accepted_requests=accepted_requests,
        completed_requests=completed_requests
    )


@app.route("/admin/mechanics")
@login_required
@role_required("admin")
def admin_mechanics():
    mechanics = Mechanic.query.all()
    return render_template("admin_mechanics.html", mechanics=mechanics)


@app.route("/admin/id-document/<int:mechanic_id>")
@login_required
@role_required("admin")
def view_id_document(mechanic_id):
    """Onesha kitambulisho cha fundi (NIDA/Leseni/Kura) - Admin PEKEE anaweza
    kufikia. Kama Cloudinary imesanidiwa, inatengeneza "signed URL" ya muda
    (dakika 10) na kumpeleka huko moja kwa moja; vinginevyo (fallback ya
    zamani) inatoa faili kutoka Render moja kwa moja."""
    mechanic = Mechanic.query.get_or_404(mechanic_id)
    if not mechanic.id_document:
        flash("Fundi huyu hajapakia kitambulisho.", "warning")
        return redirect(url_for("admin_mechanic_detail", id=mechanic_id))

    if mechanic.id_document.startswith("http"):
        # Data ya zamani kabla ya "private" kuwezeshwa - URL ya moja kwa moja
        return redirect(mechanic.id_document)

    if CLOUDINARY_CONFIGURED:
        url = cloudinary.utils.private_download_url(
            mechanic.id_document, "jpg", resource_type="image", type="private"
        )
        return redirect(url)

    return send_from_directory(app.config["PRIVATE_UPLOAD_FOLDER"], mechanic.id_document)


@app.route("/admin/approve-mechanic/<int:id>", methods=["POST"])
@login_required
@role_required("admin")
def approve_mechanic(id):
    mechanic = Mechanic.query.get_or_404(id)
    mechanic.verified = "approved"
    db.session.commit()
    notify_user(
        mechanic.user,
        title="Umeidhinishwa - GariFix",
        body="Hongera! Akaunti yako ya ufundi imeidhinishwa na Admin. Sasa unaweza kupokea maombi ya huduma.",
        data={"type": "mechanic_approved", "url": "/dashboard"}
    )
    flash("Fundi ameidhinishwa!", "success")
    return redirect(url_for("admin_mechanics"))


@app.route("/admin/reject-mechanic/<int:id>", methods=["POST"])
@login_required
@role_required("admin")
def reject_mechanic(id):
    mechanic = Mechanic.query.get_or_404(id)
    reason = request.form.get("reason", "").strip()
    mechanic.verified = "rejected"
    db.session.commit()

    body = f"Ombi lako la kuwa fundi ({mechanic.garage_name}) limekataliwa."
    if reason:
        body += f" Sababu: {reason}"
    notify_user(
        mechanic.user,
        title="Ombi Limekataliwa - GariFix",
        body=body,
        data={"type": "mechanic_rejected", "url": "/mechanic/profile"}
    )

    flash("Fundi amekataliwa.", "danger")
    return redirect(url_for("admin_mechanics"))


@app.route("/admin/customers")
@login_required
@role_required("admin")
def admin_customers():
    customers = User.query.filter_by(role="customer").all()
    return render_template("admin_customers.html", customers=customers)


@app.route("/admin/customer/<int:id>")
@login_required
@role_required("admin")
def admin_customer_detail(id):
    customer = User.query.filter_by(id=id, role="customer").first_or_404()
    requests = ServiceRequest.query.filter_by(customer_id=customer.id).order_by(ServiceRequest.created_at.desc()).all()
    reviews = Review.query.filter_by(customer_id=customer.id).order_by(Review.created_at.desc()).all()
    return render_template("admin_customer_detail.html", customer=customer, requests=requests, reviews=reviews)


@app.route("/admin/mechanic/<int:id>")
@login_required
@role_required("admin")
def admin_mechanic_detail(id):
    mechanic = Mechanic.query.get_or_404(id)
    requests = ServiceRequest.query.filter_by(mechanic_id=mechanic.id).order_by(ServiceRequest.created_at.desc()).all()
    reviews = Review.query.filter_by(mechanic_id=mechanic.id).order_by(Review.created_at.desc()).all()
    avg_rating = db.session.query(func.avg(Review.rating)).filter_by(mechanic_id=mechanic.id).scalar() or 0
    return render_template("admin_mechanic_detail.html", mechanic=mechanic, requests=requests, reviews=reviews, average_rating=avg_rating)


@app.route("/admin/block-user/<int:id>", methods=["POST"])
@login_required
@role_required("admin")
def block_user(id):
    user = User.query.get_or_404(id)
    if user.role == "admin":
        flash("Huwezi ku-block akaunti ya admin.", "danger")
    else:
        user.status = "blocked"
        db.session.commit()
        flash(f"{user.full_name} ame-blockiwa - hataweza kuingia kwenye mfumo tena.", "warning")
    return redirect(request.referrer or url_for("admin_customers"))


@app.route("/admin/unblock-user/<int:id>", methods=["POST"])
@login_required
@role_required("admin")
def unblock_user(id):
    user = User.query.get_or_404(id)
    user.status = "active"
    db.session.commit()
    flash(f"{user.full_name} ame-unblockiwa - anaweza kuingia tena.", "success")
    return redirect(request.referrer or url_for("admin_customers"))


@app.route("/admin/delete-user/<int:id>", methods=["POST"])
@login_required
@role_required("admin")
def delete_user(id):
    user = User.query.get_or_404(id)

    if user.role == "admin":
        flash("Huwezi kufuta akaunti ya admin.", "danger")
        return redirect(request.referrer or url_for("admin_customers"))

    name = user.full_name
    role = user.role
    # Futa kwanza Notifications za mtumiaji huyu - vinginevyo MySQL
    # inakataa kufuta (foreign key constraint).
    Notification.query.filter_by(user_id=user.id).delete()

    db.session.delete(user)
    db.session.commit()

    flash(f"Akaunti ya {name} imefutwa kabisa kwenye mfumo.", "success")
    if role == "mechanic":
        return redirect(url_for("admin_mechanics"))
    return redirect(url_for("admin_customers"))


@app.route("/admin/requests")
@login_required
@role_required("admin")
def admin_requests():
    requests = ServiceRequest.query.order_by(ServiceRequest.created_at.desc()).all()
    return render_template("admin_requests.html", requests=requests)


@app.route("/admin/cancel-request/<int:id>", methods=["POST"])
@login_required
@role_required("admin")
def cancel_request(id):
    service = ServiceRequest.query.get_or_404(id)
    service.status = "cancelled"
    db.session.commit()
    flash("Ombi limefutwa.", "warning")
    return redirect(url_for("admin_requests"))


@app.route("/admin/reviews")
@login_required
@role_required("admin")
def admin_reviews():
    reviews = Review.query.order_by(Review.created_at.desc()).all()
    return render_template("admin_reviews.html", reviews=reviews)


@app.cli.command("create-admin")
def create_admin():
    """
    Tengeneza akaunti ya ADMIN kutoka terminal.
    Matumizi: flask create-admin
    (Kwenye Render: fungua "Shell" ya service yako kisha andika amri hiyo hiyo)
    """
    import getpass

    print("=== Kuunda akaunti ya Admin - GariFix ===")
    full_name = input("Jina kamili: ").strip()
    phone = input("Namba ya simu (itatumika kuingia): ").strip()
    email = input("Barua pepe (hiari, bonyeza Enter kuruka): ").strip() or None
    password = getpass.getpass("Password: ").strip()

    if not full_name or not phone or not password:
        print("Jina, namba ya simu na password ni lazima. Imesitishwa.")
        return

    if User.query.filter_by(phone=phone).first():
        print(f"Hitilafu: Namba ya simu '{phone}' tayari inatumika.")
        return

    admin = User(
        full_name=full_name,
        phone=phone,
        email=email,
        password=generate_password_hash(password),
        role="admin",
        status="active",
        email_verified=True,
    )
    db.session.add(admin)
    db.session.commit()
    print(f"\nAdmin '{full_name}' ameundwa! Ingia kwa namba: {phone}")


if __name__ == "__main__":
    app.run(debug=True)