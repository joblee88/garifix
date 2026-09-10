from extensions import db

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False, index=True)
    email = db.Column(db.String(100), unique=True, nullable=True, index=True)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="customer")  # customer, mechanic, admin
    status = db.Column(db.String(20), default="active")
    fcm_token = db.Column(db.String(255), nullable=True)  # Token ya Firebase Cloud Messaging (App ya Android)
    profile_photo = db.Column(db.String(255), nullable=True)  # Picha ya wasifu (customer hasa)
    username = db.Column(db.String(50), unique=True, nullable=True, index=True)  # Jina la kuonekana kwenye profile (hiari)
    registered_via_google = db.Column(db.Boolean, default=False)  # Alijisajili kwa Google (password ni ya siri/random)

    # --- Uthibitisho wa Email (Email Verification) ---
    email_verified = db.Column(db.Boolean, default=False, nullable=False)

    # --- Reset Password kwa Email (token yenye muda wa kuisha) ---
    reset_token = db.Column(db.String(255), nullable=True, index=True)

    created_at = db.Column(db.DateTime, server_default=db.func.now())

    # Relationships
    mechanic_profile = db.relationship("Mechanic", backref="user", uselist=False, cascade="all, delete-orphan")
    service_requests = db.relationship("ServiceRequest", backref="customer", foreign_keys="ServiceRequest.customer_id", cascade="all, delete-orphan")
    reviews_written = db.relationship("Review", backref="customer", foreign_keys="Review.customer_id", cascade="all, delete-orphan")


class Mechanic(db.Model):
    __tablename__ = "mechanics"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    garage_name = db.Column(db.String(100))
    region = db.Column(db.String(100), nullable=False, index=True)
    district = db.Column(db.String(100), nullable=False, index=True)
    ward = db.Column(db.String(100))
    street = db.Column(db.String(100))
    specialization = db.Column(db.String(255), nullable=False)
    experience = db.Column(db.Integer)
    description = db.Column(db.Text)
    latitude = db.Column(db.Numeric(10, 8))
    longitude = db.Column(db.Numeric(11, 8))
    verified = db.Column(db.Enum("pending", "approved", "rejected"), default="pending", index=True)
    rejection_reason = db.Column(db.Text, nullable=True)  # sababu ya Admin kukataa (ikiwa verified="rejected")
    profile_photo = db.Column(db.String(255))

    # --- Kitambulisho cha Fundi (kwa ukaguzi wa Admin) ---
    id_document_type = db.Column(db.String(30), nullable=True)   # "NIDA", "Leseni", "Kadi ya Mpiga Kura"
    id_document = db.Column(db.String(255), nullable=True)       # jina la faili lililopakiwa

    created_at = db.Column(db.DateTime, server_default=db.func.now())

    # Relationships
    service_requests = db.relationship("ServiceRequest", backref="mechanic", foreign_keys="ServiceRequest.mechanic_id", cascade="all, delete-orphan")
    reviews = db.relationship("Review", backref="mechanic", foreign_keys="Review.mechanic_id", lazy=True, cascade="all, delete-orphan")


class ServiceRequest(db.Model):
    __tablename__ = "service_requests"

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    mechanic_id = db.Column(db.Integer, db.ForeignKey("mechanics.id"), nullable=True)
    vehicle_model = db.Column(db.String(100), nullable=False)
    problem_description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Enum("pending", "accepted", "completed", "cancelled", "rejected"), default="pending", index=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class Review(db.Model):
    __tablename__ = "reviews"

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    mechanic_id = db.Column(db.Integer, db.ForeignKey("mechanics.id"), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class Notification(db.Model):
    """Arifa za ndani ya mfumo (in-app) - zinaonekana kwenye 'dropdown' ya
    bell icon. Kila push notification (FCM) inayotumwa pia inahifadhi rekodi
    hapa, ili mtumiaji aone historia yake na tuweze kuhesabu 'ambazo bado
    hazijasomwa' (unread) kwa usahihi."""
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text)
    url = db.Column(db.String(255))  # ukurasa wa kufungua akibonyeza
    is_read = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    user = db.relationship("User", foreign_keys=[user_id])

class PageVisit(db.Model):
    """Kumbukumbu ya wageni waliotembelea website - moja kwa kila
    'session' (siyo kila 'page load', ili kuepuka kuhesabu mtu mmoja
    mara nyingi). Mkoa (region) unatambuliwa kwa kutumia huduma ya
    'geo-IP' ya nje (bila malipo) - ikiwa haiwezekani kujua (mfano IP
    ya ndani wakati wa majaribio), region inabaki 'Haijulikani'."""
    __tablename__ = "page_visits"

    id = db.Column(db.Integer, primary_key=True)
    region = db.Column(db.String(100), default="Haijulikani", index=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
