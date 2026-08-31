import os
from functools import wraps
from flask import Flask, render_template, request, redirect, session, flash, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func

# 1. Import Config na extensions
from config import Config
from extensions import db

# Initialize Flask App
app = Flask(__name__)

# 2. Pakia Configuration KWANZA kabla ya db.init_app
app.config.from_object(Config)

# Mipangilio ya upload ya picha
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 3. Unganisha Database na App
db.init_app(app)

# 4. Import models na uunde meza zote za SQLite kiatomati
with app.app_context():
    try:
        import models
        from models import User, Mechanic, ServiceRequest, Review
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


# Context Processor kwa ajili ya taarifa za mtumiaji aliyeingia
@app.context_processor
def inject_user():
    if "user_id" in session:
        user = db.session.get(User, session["user_id"])
        return dict(current_user=user)
    return dict(current_user=None)


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
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(phone=phone).first()

        if user and check_password_hash(user.password, password):
            if user.role == "mechanic":
                mechanic = Mechanic.query.filter_by(user_id=user.id).first()
                if mechanic:
                    if mechanic.verified == "pending":
                        flash("Akaunti yako bado inasubiri idhini (approval) ya Admin.", "warning")
                        return redirect(url_for("login"))
                    elif mechanic.verified == "rejected":
                        flash("Usajili wako umekataliwa na Admin.", "danger")
                        return redirect(url_for("login"))

            session["user_id"] = user.id
            session["role"] = user.role

            flash("Karibu tena GariFix!", "success")
            if user.role == "admin":
                return redirect(url_for("admin_dashboard", user_id=user.id))
            elif user.role == "mechanic":
                return redirect(url_for("mechanic_dashboard"))
            else:
                return redirect(url_for("customer_dashboard"))

        flash("Namba ya simu au nenosiri si sahihi.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Umetoka kwenye mfumo kikamilifu.", "info")
    return redirect(url_for("login"))


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


# CUSTOMER ROUTES
@app.route("/customer/register", methods=["GET", "POST"])
def customer_register():
    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        full_name = f"{first_name} {last_name}".strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip() or None
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not first_name or not last_name:
            flash("Tafadhali jaza jina la kwanza na la mwisho.", "danger")
            return redirect(url_for("customer_register"))

        if password != confirm_password:
            flash("Password na Rudia Password hazifanani.", "danger")
            return redirect(url_for("customer_register"))

        if User.query.filter_by(phone=phone).first():
            flash("Namba hii ya simu tayari imesajiliwa.", "danger")
            return redirect(url_for("customer_register"))

        if email and User.query.filter_by(email=email).first():
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

        flash("Usajili umefanikiwa! Ingia sasa.", "success")
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
        email = request.form.get("email", "").strip() or None
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

        if not first_name or not last_name:
            flash("Tafadhali jaza jina la kwanza na la mwisho.", "danger")
            return redirect(url_for("mechanic_register"))

        if password != confirm_password:
            flash("Password na Rudia Password hazifanani.", "danger")
            return redirect(url_for("mechanic_register"))

        if User.query.filter_by(phone=phone).first():
            flash("Namba hii ya simu tayari imesajiliwa.", "danger")
            return redirect(url_for("mechanic_register"))

        if email and User.query.filter_by(email=email).first():
            flash("Barua pepe hii tayari imesajiliwa.", "danger")
            return redirect(url_for("mechanic_register"))

        filename = None
        photo = request.files.get("profile_photo")
        if photo and photo.filename != "":
            filename = secure_filename(photo.filename)
            photo.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

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
            verified="pending"
        )
        db.session.add(new_mechanic)
        db.session.commit()

        flash("Usajili umefanikiwa! Subiri uthibitisho kutoka kwa Admin.", "success")
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
        flash("Hongera! Umethibitisha kuwa huduma imekamilika.", "success")
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


@app.route("/admin/approve-mechanic/<int:id>")
@login_required
@role_required("admin")
def approve_mechanic(id):
    mechanic = Mechanic.query.get_or_404(id)
    mechanic.verified = "approved"
    db.session.commit()
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
    )
    db.session.add(admin)
    db.session.commit()
    print(f"\nAdmin '{full_name}' ameundwa! Ingia kwa namba: {phone}")


if __name__ == "__main__":
    app.run(debug=True)