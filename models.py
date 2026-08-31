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
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    # Relationships
    mechanic_profile = db.relationship("Mechanic", backref="user", uselist=False, cascade="all, delete-orphan")
    service_requests = db.relationship("ServiceRequest", backref="customer", foreign_keys="ServiceRequest.customer_id")
    reviews_written = db.relationship("Review", backref="customer", foreign_keys="Review.customer_id")


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
    profile_photo = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    # Relationships
    service_requests = db.relationship("ServiceRequest", backref="mechanic", foreign_keys="ServiceRequest.mechanic_id")
    reviews = db.relationship("Review", backref="mechanic", foreign_keys="Review.mechanic_id", lazy=True)


class ServiceRequest(db.Model):
    __tablename__ = "service_requests"

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    mechanic_id = db.Column(db.Integer, db.ForeignKey("mechanics.id"), nullable=True)
    vehicle_model = db.Column(db.String(100), nullable=False)
    problem_description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Enum("pending", "accepted", "completed", "cancelled"), default="pending", index=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class Review(db.Model):
    __tablename__ = "reviews"

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    mechanic_id = db.Column(db.Integer, db.ForeignKey("mechanics.id"), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, server_default=db.func.now())