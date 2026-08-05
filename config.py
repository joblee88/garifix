import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "garifix_secret_key_2026_prod")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", 
        "mysql+pymysql://root:12345Six@localhost/garifix_tanzania"
    )
    # Fix Render/Heroku postgres database prefix issue if applicable
    if SQLALCHEMY_DATABASE_URI.startswith("postgres://"):
        SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace("postgres://", "postgresql://", 1)
        
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload limit