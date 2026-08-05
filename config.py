import os

class Config:
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "garifix_secret_key_2026_prod"
    )

    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")

    if SQLALCHEMY_DATABASE_URI is None:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set"
        )

    # Fix old postgres URL format
    if SQLALCHEMY_DATABASE_URI.startswith("postgres://"):
        SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace(
            "postgres://",
            "postgresql://",
            1
        )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAX_CONTENT_LENGTH = 16 * 1024 * 1024