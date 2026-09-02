import os
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode


class Config:
    # Key ya siri kwa ajili ya session za mfumo
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'garifix-secret-key-tanzania-2026'

    # --- Database ---
    # Kwa PRODUCTION (mf. Render): weka environment variable "DATABASE_URL"
    # (mfano URL kutoka Aiven MySQL, Render Postgres, n.k).
    # Kwa LOCAL DEVELOPMENT: ikiwa DATABASE_URL haipo, mfumo utatumia
    # SQLite (faili la garifix.db) moja kwa moja bila usanidi wowote wa ziada.
    _database_url = os.environ.get('DATABASE_URL')

    SQLALCHEMY_ENGINE_OPTIONS = {}

    if _database_url:
        # Baadhi ya watoa huduma (Render/Heroku) hutoa URL zenye "postgres://"
        # ambazo SQLAlchemy ya sasa hazielewi - lazima ziwe "postgresql://"
        if _database_url.startswith('postgres://'):
            _database_url = _database_url.replace('postgres://', 'postgresql://', 1)
            SQLALCHEMY_DATABASE_URI = _database_url

        elif _database_url.startswith('mysql://') or _database_url.startswith('mysql+pymysql://'):
            _database_url = _database_url.replace('mysql://', 'mysql+pymysql://', 1)

            # MUHIMU: Watoa huduma wa MySQL wanaosimamiwa (Aiven, PlanetScale,
            # TiDB Cloud n.k) mara nyingi hutoa URL yenye "?ssl-mode=REQUIRED"
            # kwenye mwisho. PyMySQL HAITAMBUI parameter hiyo kwa jina hilo
            # ("ssl-mode") - inasababisha hitilafu:
            #   TypeError: Connection.__init__() got an unexpected keyword
            #   argument 'ssl-mode'
            #
            # Suluhisho: TOA query parameters zote kwenye URL (SQLAlchemy
            # ingezijaribu kuzipitisha moja kwa moja kwa PyMySQL vibaya), na
            # badala yake weka SSL kwa njia sahihi kupitia "connect_args".
            parsed = urlparse(_database_url)
            clean_url = urlunparse(parsed._replace(query=""))
            SQLALCHEMY_DATABASE_URI = clean_url

            try:
                import certifi
                SQLALCHEMY_ENGINE_OPTIONS = {
                    "connect_args": {"ssl": {"ca": certifi.where()}},
                    "pool_pre_ping": True,
                    "pool_recycle": 280,
                }
            except ImportError:
                # certifi haijasakinishwa - washa TLS bila cheti maalum
                # (bado inafanya kazi kwa Aiven kwa sababu wanahitaji tu
                # muunganisho uliosimbwa, siyo uthibitisho mkali wa cheti)
                SQLALCHEMY_ENGINE_OPTIONS = {
                    "connect_args": {"ssl": {"ssl_verify_cert": False, "ssl_verify_identity": False}},
                    "pool_pre_ping": True,
                    "pool_recycle": 280,
                }
        else:
            SQLALCHEMY_DATABASE_URI = _database_url
    else:
        SQLALCHEMY_DATABASE_URI = 'sqlite:///garifix.db'

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Kikomo cha ukubwa wa faili linaloweza kupakiwa (16 MB) - kwa picha za mafundi
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
