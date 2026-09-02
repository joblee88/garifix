import os
import uuid
from functools import wraps
from flask import Flask, render_template, request, redirect, session, flash, url_for, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func, or_
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

# 1. Import Config na extensions
from config import Config
from extensions import db
from notifications import send_notification
from mailer import send_verification_email, send_password_reset_email

# Initialize Flask App
app = Flask(__name__)

# 2. Pakia Configuration KWANZA kabla ya db.init_app
app.config.from_object(Config)

# Mipangilio ya upload ya picha (PROFILE - ya wazi/public)
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Mipangilio ya upload ya VITAMBULISHO vya mafundi (NIDA/Leseni/Kura) - PRIVATE,
# HAIKO ndani ya "static/" hivyo mtu HAWEZI kufikia moja kwa moja kwa URL -
# Admin pekee ndiye anaweza kuona (kupitia route iliyolindwa hapa chini).
PRIVATE_UPLOAD_FOLDER = os.path.join(app.root_path, "private_uploads", "id_documents")
app.config["PRIVATE_UPLOAD_FOLDER"] = PRIVATE_UPLOAD_FOLDER
os.makedirs(PRIVATE_UPLOAD_FOLDER, exist_ok=True)

# 3. Unganisha Database na App
db.init_app(app)

# 4. Import models na uunde meza zote za SQLite kiatomati
with app.app_context():
    try:
        import models
        from models import User, Mechanic, ServiceRequest, Review, Seller, Product, SellerReview
        db.create_all()
        print("Database ya SQLite imewezeshwa: Faili la garifix.db na meza zote zipo tayari!")
    except Exception as e:
        print(f"Kosa wakati wa kuunda meza: {e}")


@app.route("/health")
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


def save_uploaded_image(file_storage, folder):
    """Hifadhi picha kwa jina la kipekee (uuid) ili kuepuka mgongano wa majina."""
    if not file_storage or file_storage.filename == "":
        return None
    ext = os.path.splitext(secure_filename(file_storage.filename))[1]
    unique_name = f"{uuid.uuid4().hex}{ext}"
    os.makedirs(folder, exist_ok=True)
    file_storage.save(os.path.join(folder, unique_name))
    return unique_name


# Context Processor kwa ajili ya taarifa za mtumiaji aliyeingia
@app.context_processor
def inject_user():
    if "user_id" in session:
        user = db.session.get(User, session["user_id"])
        return dict(current_user=user)
    return dict(current_user=None)


# KUMBUKA: Hitaji la "email verification" (kuzuia dashboard kabla ya
# kuthibitisha email) LIMEZIMWA kwa sasa - barua pepe hazikuwa zinatumwa
# kwa uhakika kupitia Render free tier (bandari za SMTP zimezuiwa na
# Render). Msimbo wa verify_email/resend_verification bado upo tayari
# kutumika baadaye ukisha sanidi Brevo API kikamilifu - ona mailer.py.
#
# Uthibitisho wa FUNDI (Mechanic.verified na Seller.verified) na Admin
# HAUATHIRIWI na hii - unaendelea kufanya kazi kama kawaida.


@app.route("/")
def home():
    total_mechanics = db.session.query(Mechanic).count()
    approved_mechanics = db.session.query(Mechanic).filter_by(verified="approved").count()
    total_customers = db.session.query(User).filter_by(role="customer").count()
    total_requests = db.session.query(ServiceRequest).count()

    return render_template(
        "home.html",
        total_mechanics=total_mechanics,
        approved_mechanics=approved_mechanics,
        total_customers=total_customers,
        total_requests=total_requests
    )


@app.route("/login", methods=["GET", "POST"])
def login():
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

            if user.role == "seller":
                seller = Seller.query.filter_by(user_id=user.id).first()
                if seller:
                    if seller.verified == "pending":
                        flash("Akaunti yako bado inasubiri idhini (approval) ya Admin.", "warning")
                        return redirect(url_for("login"))
                    elif seller.verified == "rejected":
                        flash("Usajili wako umekataliwa na Admin.", "danger")
                        return redirect(url_for("login"))

            session["user_id"] = user.id
            session["role"] = user.role

            flash("Karibu tena GariFix!", "success")
            if user.role == "admin":
                return redirect(url_for("admin_dashboard", user_id=user.id))
            elif user.role == "mechanic":
                return redirect(url_for("mechanic_dashboard"))
            elif user.role == "seller":
                return redirect(url_for("seller_dashboard"))
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
@login_required
def register_fcm_token():
    """App ya Android inatuma FCM token hapa baada ya mtumiaji ku-login,
    ili mfumo uweze kumtumia push notifications."""
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


@app.route("/forgot-password", methods=["GET", "POST"])
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


@app.route("/setup-admin", methods=["GET", "POST"])
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


@app.route("/register")
def register_choice():
    """Ukurasa wa kuchagua: Nataka kujisajili kama Mteja au kama Fundi."""
    return render_template("register_choice.html")


@app.route("/customer/register", methods=["GET", "POST"])
def customer_register():
    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        full_name = f"{first_name} {last_name}".strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not first_name or not last_name:
            flash("Tafadhali jaza jina la kwanza na la mwisho.", "danger")
            return redirect(url_for("customer_register"))

        if not email:
            flash("Tafadhali weka email.", "danger")
            return redirect(url_for("customer_register"))

        if not request.form.get("agree_terms"):
            flash("Lazima ukubaliane na Vigezo na Masharti ili kuendelea.", "danger")
            return redirect(url_for("customer_register"))

        if password != confirm_password:
            flash("Password na Rudia Password hazifanani.", "danger")
            return redirect(url_for("customer_register"))

        if User.query.filter_by(phone=phone).first():
            flash("Namba hii ya simu tayari imesajiliwa.", "danger")
            return redirect(url_for("customer_register"))

        if User.query.filter_by(email=email).first():
            flash("Barua pepe hii tayari imesajiliwa.", "danger")
            return redirect(url_for("customer_register"))

        hashed_password = generate_password_hash(password)
        new_customer = User(
            full_name=full_name,
            phone=phone,
            email=email,
            password=hashed_password,
            role="customer"
        )
        db.session.add(new_customer)
        db.session.commit()

        send_email_verification(new_customer)

        flash("Usajili umefanikiwa! Tumekutumia email ya uthibitisho - tafadhali ithibitishe, kisha ingia.", "success")
        return redirect(url_for("login"))

    return render_template("customer_register.html")


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
def mechanic_register():
    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        full_name = f"{first_name} {last_name}".strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

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

        if password != confirm_password:
            flash("Password na Rudia Password hazifanani.", "danger")
            return redirect(url_for("mechanic_register"))

        id_doc_file = request.files.get("id_document")
        if not id_doc_file or id_doc_file.filename == "":
            flash("Tafadhali ambatanisha kitambulisho (NIDA, Leseni ya Udereva, au Kadi ya Mpiga Kura).", "danger")
            return redirect(url_for("mechanic_register"))

        if not id_document_type:
            flash("Tafadhali chagua aina ya kitambulisho ulichoambatanisha.", "danger")
            return redirect(url_for("mechanic_register"))

        if User.query.filter_by(phone=phone).first():
            flash("Namba hii ya simu tayari imesajiliwa.", "danger")
            return redirect(url_for("mechanic_register"))

        if User.query.filter_by(email=email).first():
            flash("Barua pepe hii tayari imesajiliwa.", "danger")
            return redirect(url_for("mechanic_register"))

        filename = save_uploaded_image(request.files.get("profile_photo"), app.config["UPLOAD_FOLDER"])
        id_document_filename = save_uploaded_image(id_doc_file, app.config["PRIVATE_UPLOAD_FOLDER"])

        hashed_password = generate_password_hash(password)
        new_user = User(
            full_name=full_name,
            phone=phone,
            email=email,
            password=hashed_password,
            role="mechanic"
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

        send_email_verification(new_user)

        flash("Usajili umefanikiwa! Tumekutumia email ya uthibitisho. Akaunti yako pia inasubiri uthibitisho wa Admin (baada ya kukagua kitambulisho chako).", "success")
        return redirect(url_for("login"))

    return render_template("mechanic_register.html")


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


@app.route("/accept-request/<int:id>")
@login_required
@role_required("mechanic")
def accept_request(id):
    user = db.session.get(User, session["user_id"])
    mechanic = Mechanic.query.filter_by(user_id=user.id).first()
    service = ServiceRequest.query.get_or_404(id)

    if mechanic and service.mechanic_id == mechanic.id:
        service.status = "accepted"
        db.session.commit()
        send_notification(
            service.customer,
            title="Fundi Amekubali Ombi Lako - GariFix",
            body=f"{mechanic.user.full_name} amekubali kukusaidia na {service.vehicle_model}. Anakuja!",
            data={"type": "request_accepted", "request_id": service.id}
        )
        flash("Umekubali ombi hili la huduma.", "success")
    else:
        flash("Hauruhusiwi kutenda kitendo hiki.", "danger")

    return redirect(url_for("mechanic_dashboard"))


@app.route("/complete-request/<int:id>")
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
            send_notification(
                service_request.mechanic.user,
                title="Huduma Imethibitishwa Kukamilika - GariFix",
                body=f"{user.full_name} amethibitisha kuwa kazi ya {service_request.vehicle_model} imekamilika. Ahsante!",
                data={"type": "request_completed", "request_id": service_request.id}
            )
        flash("Hongera! Umethibitisha kuwa huduma imekamilika.", "success")
        return redirect(url_for("customer_requests"))

    flash("Hauruhusiwi kubadilisha taarifa hii.", "danger")
    return redirect(url_for("home"))


# =====================================================================
# SELLER ROUTES (Wauzaji wa Spea za Magari na Lubricants)
# =====================================================================
@app.route("/seller/register", methods=["GET", "POST"])
def seller_register():
    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        full_name = f"{first_name} {last_name}".strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        shop_name = request.form.get("shop_name", "").strip()
        region = request.form.get("region", "").strip()
        district = request.form.get("district", "").strip()
        ward = request.form.get("ward", "").strip()
        street = request.form.get("street", "").strip()
        description = request.form.get("description", "").strip()
        business_types = request.form.getlist("business_type")
        business_type = ", ".join(business_types)

        if not first_name or not last_name:
            flash("Tafadhali jaza jina la kwanza na la mwisho.", "danger")
            return redirect(url_for("seller_register"))

        if not email:
            flash("Tafadhali weka email.", "danger")
            return redirect(url_for("seller_register"))

        if not shop_name:
            flash("Tafadhali weka jina la duka lako.", "danger")
            return redirect(url_for("seller_register"))

        if not business_types:
            flash("Tafadhali chagua unauza nini (Spea za Magari na/au Mafuta/Lubricants).", "danger")
            return redirect(url_for("seller_register"))

        if not request.form.get("agree_terms"):
            flash("Lazima ukubaliane na Vigezo na Masharti ili kuendelea.", "danger")
            return redirect(url_for("seller_register"))

        if password != confirm_password:
            flash("Password na Rudia Password hazifanani.", "danger")
            return redirect(url_for("seller_register"))

        if User.query.filter_by(phone=phone).first():
            flash("Namba hii ya simu tayari imesajiliwa.", "danger")
            return redirect(url_for("seller_register"))

        if User.query.filter_by(email=email).first():
            flash("Barua pepe hii tayari imesajiliwa.", "danger")
            return redirect(url_for("seller_register"))

        shop_photo_filename = save_uploaded_image(request.files.get("shop_photo"), app.config["UPLOAD_FOLDER"])

        new_user = User(
            full_name=full_name,
            phone=phone,
            email=email,
            password=generate_password_hash(password),
            role="seller"
        )
        db.session.add(new_user)
        db.session.commit()

        new_seller = Seller(
            user_id=new_user.id,
            shop_name=shop_name,
            region=region,
            district=district,
            ward=ward,
            street=street,
            description=description,
            shop_photo=shop_photo_filename,
            business_type=business_type,
            verified="pending"
        )
        db.session.add(new_seller)
        db.session.commit()

        flash("Usajili umefanikiwa! Akaunti yako inasubiri idhini ya Admin kabla ya kuanza kuonekana kwa wateja.", "success")
        return redirect(url_for("login"))

    return render_template("seller_register.html")


@app.route("/seller/dashboard")
@login_required
@role_required("seller")
def seller_dashboard():
    user = db.session.get(User, session["user_id"])
    seller = Seller.query.filter_by(user_id=user.id).first_or_404()
    products = Product.query.filter_by(seller_id=seller.id).order_by(Product.created_at.desc()).all()
    reviews = SellerReview.query.filter_by(seller_id=seller.id).order_by(SellerReview.created_at.desc()).all()
    avg_rating = db.session.query(func.avg(SellerReview.rating)).filter_by(seller_id=seller.id).scalar() or 0

    return render_template(
        "seller_dashboard.html",
        seller=seller, user=user, products=products,
        reviews=reviews, average_rating=avg_rating
    )


@app.route("/seller/profile", methods=["GET", "POST"])
@login_required
@role_required("seller")
def own_seller_profile():
    user = db.session.get(User, session["user_id"])
    seller = Seller.query.filter_by(user_id=user.id).first_or_404()

    if request.method == "POST":
        seller.shop_name = request.form.get("shop_name", "").strip()
        seller.region = request.form.get("region", "").strip()
        seller.district = request.form.get("district", "").strip()
        seller.ward = request.form.get("ward", "").strip()
        seller.street = request.form.get("street", "").strip()
        seller.description = request.form.get("description", "").strip()
        seller.business_type = ", ".join(request.form.getlist("business_type"))

        photo = save_uploaded_image(request.files.get("shop_photo"), app.config["UPLOAD_FOLDER"])
        if photo:
            seller.shop_photo = photo

        db.session.commit()
        flash("Taarifa za duka lako zimesasishwa!", "success")
        return redirect(url_for("own_seller_profile"))

    return render_template("seller_profile_edit.html", seller=seller)


@app.route("/seller/products")
@login_required
@role_required("seller")
def seller_products():
    user = db.session.get(User, session["user_id"])
    seller = Seller.query.filter_by(user_id=user.id).first_or_404()
    products = Product.query.filter_by(seller_id=seller.id).order_by(Product.created_at.desc()).all()
    return render_template("seller_products.html", seller=seller, products=products)


@app.route("/seller/products/add", methods=["GET", "POST"])
@login_required
@role_required("seller")
def add_product():
    user = db.session.get(User, session["user_id"])
    seller = Seller.query.filter_by(user_id=user.id).first_or_404()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        category = request.form.get("category", "").strip()
        price = request.form.get("price", "").strip()
        description = request.form.get("description", "").strip()

        if not name or not price:
            flash("Tafadhali jaza jina na bei ya bidhaa.", "danger")
            return redirect(url_for("add_product"))

        try:
            price_value = float(price)
        except ValueError:
            flash("Bei siyo namba sahihi.", "danger")
            return redirect(url_for("add_product"))

        photo_filename = save_uploaded_image(request.files.get("photo"), app.config["UPLOAD_FOLDER"])

        product = Product(
            seller_id=seller.id,
            name=name,
            category=category,
            price=price_value,
            description=description,
            photo=photo_filename
        )
        db.session.add(product)
        db.session.commit()

        flash("Bidhaa imeongezwa kikamilifu!", "success")
        return redirect(url_for("seller_products"))

    return render_template("product_form.html", product=None)


@app.route("/seller/products/edit/<int:id>", methods=["GET", "POST"])
@login_required
@role_required("seller")
def edit_product(id):
    user = db.session.get(User, session["user_id"])
    seller = Seller.query.filter_by(user_id=user.id).first_or_404()
    product = Product.query.get_or_404(id)

    if product.seller_id != seller.id:
        flash("Hauruhusiwi kuhariri bidhaa hii.", "danger")
        return redirect(url_for("seller_products"))

    if request.method == "POST":
        product.name = request.form.get("name", "").strip()
        product.category = request.form.get("category", "").strip()
        product.description = request.form.get("description", "").strip()

        price = request.form.get("price", "").strip()
        try:
            product.price = float(price)
        except ValueError:
            flash("Bei siyo namba sahihi.", "danger")
            return redirect(url_for("edit_product", id=id))

        photo_filename = save_uploaded_image(request.files.get("photo"), app.config["UPLOAD_FOLDER"])
        if photo_filename:
            product.photo = photo_filename

        db.session.commit()
        flash("Bidhaa imesasishwa kikamilifu!", "success")
        return redirect(url_for("seller_products"))

    return render_template("product_form.html", product=product)


@app.route("/seller/products/delete/<int:id>")
@login_required
@role_required("seller")
def delete_product(id):
    user = db.session.get(User, session["user_id"])
    seller = Seller.query.filter_by(user_id=user.id).first_or_404()
    product = Product.query.get_or_404(id)

    if product.seller_id != seller.id:
        flash("Hauruhusiwi kufuta bidhaa hii.", "danger")
        return redirect(url_for("seller_products"))

    db.session.delete(product)
    db.session.commit()
    flash("Bidhaa imefutwa.", "success")
    return redirect(url_for("seller_products"))


@app.route("/sellers")
@login_required
@role_required("customer")
def sellers_list():
    """Ukurasa wa umma - wateja wanavinjari wauzaji wote walioidhinishwa."""
    region = request.args.get("region", "").strip()
    query = Seller.query.join(User).filter(Seller.verified == "approved", User.status == "active")
    if region:
        query = query.filter(Seller.region == region)
    sellers = query.order_by(Seller.created_at.desc()).all()
    return render_template("sellers_list.html", sellers=sellers, selected_region=region)


@app.route("/seller/<int:seller_id>")
@login_required
@role_required("customer")
def seller_profile(seller_id):
    """Profile ya muuzaji - customer aliyeingia pekee anaweza kuona (sawa na search_mechanics)."""
    seller = Seller.query.get_or_404(seller_id)

    if seller.verified != "approved" or seller.user.status != "active":
        flash("Duka hili halipatikani kwa sasa.", "warning")
        return redirect(url_for("sellers_list"))

    products = Product.query.filter_by(seller_id=seller.id).order_by(Product.created_at.desc()).all()
    reviews = SellerReview.query.filter_by(seller_id=seller.id).order_by(SellerReview.created_at.desc()).all()
    avg_rating = db.session.query(func.avg(SellerReview.rating)).filter_by(seller_id=seller.id).scalar() or 0

    return render_template(
        "seller_public_profile.html",
        seller=seller, products=products, reviews=reviews,
        average_rating=avg_rating, review_count=len(reviews)
    )


@app.route("/seller/review/<int:seller_id>", methods=["GET", "POST"])
@login_required
@role_required("customer")
def add_seller_review(seller_id):
    seller = Seller.query.get_or_404(seller_id)

    if request.method == "POST":
        rating = request.form.get("rating")
        comment = request.form.get("comment", "").strip()

        review = SellerReview(
            customer_id=session["user_id"],
            seller_id=seller.id,
            rating=int(rating),
            comment=comment
        )
        db.session.add(review)
        db.session.commit()

        send_notification(
            seller.user,
            title="Umepata Review Mpya - GariFix",
            body=f"Umepata rating ya {rating}/5 kwenye duka lako.",
            data={"type": "seller_review", "seller_id": seller.id}
        )

        flash("Maoni yako yamehifadhiwa!", "success")
        return redirect(url_for("seller_profile", seller_id=seller.id))

    return render_template("seller_review.html", seller=seller)


@app.route("/admin/sellers")
@login_required
@role_required("admin")
def admin_sellers():
    sellers = Seller.query.all()
    return render_template("admin_sellers.html", sellers=sellers)


@app.route("/admin/seller/<int:id>")
@login_required
@role_required("admin")
def admin_seller_detail(id):
    seller = Seller.query.get_or_404(id)
    products = Product.query.filter_by(seller_id=seller.id).order_by(Product.created_at.desc()).all()
    reviews = SellerReview.query.filter_by(seller_id=seller.id).order_by(SellerReview.created_at.desc()).all()
    avg_rating = db.session.query(func.avg(SellerReview.rating)).filter_by(seller_id=seller.id).scalar() or 0
    return render_template(
        "admin_seller_detail.html",
        seller=seller, products=products, reviews=reviews, average_rating=avg_rating
    )


@app.route("/admin/approve-seller/<int:id>")
@login_required
@role_required("admin")
def approve_seller(id):
    seller = Seller.query.get_or_404(id)
    seller.verified = "approved"
    db.session.commit()
    send_notification(
        seller.user,
        title="Umeidhinishwa - GariFix",
        body="Hongera! Duka lako limeidhinishwa na Admin, sasa linaonekana kwa wateja.",
        data={"type": "seller_approved"}
    )
    flash(f"Duka la {seller.shop_name} limeidhinishwa.", "success")
    return redirect(url_for("admin_sellers"))


@app.route("/admin/reject-seller/<int:id>")
@login_required
@role_required("admin")
def reject_seller(id):
    seller = Seller.query.get_or_404(id)
    seller.verified = "rejected"
    db.session.commit()
    flash(f"Duka la {seller.shop_name} limekataliwa.", "warning")
    return redirect(url_for("admin_sellers"))


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

        send_notification(
            mechanic.user,
            title="Ombi Jipya la Huduma - GariFix",
            body=f"Mteja {session.get('user_id') and db.session.get(User, session['user_id']).full_name} ana tatizo la {vehicle_model}. Bofya kuona zaidi.",
            data={"type": "new_request", "request_id": new_request.id}
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

        send_notification(
            mechanic.user,
            title="Umepata Review Mpya - GariFix",
            body=f"{db.session.get(User, session['user_id']).full_name} amekupa rating ya {rating}/5.",
            data={"type": "new_review", "mechanic_id": mechanic.id}
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
    total_sellers = Seller.query.count()
    approved_sellers = Seller.query.filter_by(verified="approved").count()
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
        total_sellers=total_sellers,
        approved_sellers=approved_sellers,
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
    kufikia (faili haliko chini ya /static/ hivyo halifikiki na mtu mwingine)."""
    mechanic = Mechanic.query.get_or_404(mechanic_id)
    if not mechanic.id_document:
        flash("Fundi huyu hajapakia kitambulisho.", "warning")
        return redirect(url_for("admin_mechanic_detail", id=mechanic_id))
    return send_from_directory(app.config["PRIVATE_UPLOAD_FOLDER"], mechanic.id_document)


@app.route("/admin/approve-mechanic/<int:id>")
@login_required
@role_required("admin")
def approve_mechanic(id):
    mechanic = Mechanic.query.get_or_404(id)
    mechanic.verified = "approved"
    db.session.commit()
    send_notification(
        mechanic.user,
        title="Umeidhinishwa - GariFix",
        body="Hongera! Akaunti yako ya ufundi imeidhinishwa na Admin. Sasa unaweza kupokea maombi ya huduma.",
        data={"type": "mechanic_approved"}
    )
    flash("Fundi ameidhinishwa!", "success")
    return redirect(url_for("admin_mechanics"))


@app.route("/admin/reject-mechanic/<int:id>")
@login_required
@role_required("admin")
def reject_mechanic(id):
    mechanic = Mechanic.query.get_or_404(id)
    mechanic.verified = "rejected"
    db.session.commit()
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


@app.route("/admin/block-user/<int:id>")
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


@app.route("/admin/unblock-user/<int:id>")
@login_required
@role_required("admin")
def unblock_user(id):
    user = User.query.get_or_404(id)
    user.status = "active"
    db.session.commit()
    flash(f"{user.full_name} ame-unblockiwa - anaweza kuingia tena.", "success")
    return redirect(request.referrer or url_for("admin_customers"))


@app.route("/admin/delete-user/<int:id>")
@login_required
@role_required("admin")
def delete_user(id):
    user = User.query.get_or_404(id)

    if user.role == "admin":
        flash("Huwezi kufuta akaunti ya admin.", "danger")
        return redirect(request.referrer or url_for("admin_customers"))

    name = user.full_name
    role = user.role
    db.session.delete(user)
    db.session.commit()

    flash(f"Akaunti ya {name} imefutwa kabisa kwenye mfumo.", "success")
    if role == "mechanic":
        return redirect(url_for("admin_mechanics"))
    elif role == "seller":
        return redirect(url_for("admin_sellers"))
    return redirect(url_for("admin_customers"))


@app.route("/admin/requests")
@login_required
@role_required("admin")
def admin_requests():
    requests = ServiceRequest.query.order_by(ServiceRequest.created_at.desc()).all()
    return render_template("admin_requests.html", requests=requests)


@app.route("/admin/cancel-request/<int:id>")
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