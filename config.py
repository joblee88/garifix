import os


class Config:
    # Key ya siri kwa ajili ya session za mfumo
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'garifix-secret-key-tanzania-2026'

    # --- Database ---
    # Kwa PRODUCTION (mf. Render): weka environment variable "DATABASE_URL"
    # (Render huitoa yenyewe ukitumia MySQL/Postgres add-on).
    # Kwa LOCAL DEVELOPMENT: ikiwa DATABASE_URL haipo, mfumo utatumia
    # SQLite (faili la garifix.db) moja kwa moja bila usanidi wowote wa ziada.
    _database_url = os.environ.get('DATABASE_URL')

    if _database_url:
        # Baadhi ya watoa huduma (Render/Heroku) hutoa URL zenye "postgres://"
        # ambazo SQLAlchemy ya sasa hazielewi - lazima ziwe "postgresql://"
        if _database_url.startswith('postgres://'):
            _database_url = _database_url.replace('postgres://', 'postgresql://', 1)
        # Kama URL ni ya MySQL lakini haina dereva (driver) maalum,
        # tumia PyMySQL (ndiyo driver iliyopo kwenye requirements.txt)
        elif _database_url.startswith('mysql://'):
            _database_url = _database_url.replace('mysql://', 'mysql+pymysql://', 1)

        SQLALCHEMY_DATABASE_URI = _database_url
    else:
        SQLALCHEMY_DATABASE_URI = 'sqlite:///garifix.db'

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Kikomo cha ukubwa wa faili linaloweza kupakiwa (16 MB) - kwa picha za mafundi
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
