# config.py
import os
import secrets
from dotenv import load_dotenv

# Load environment variables from .env file (must be in project root)
load_dotenv()

class Config:
    # ────────────────────────────────────────────────
    # Flask Core Settings
    # ────────────────────────────────────────────────
    # Use .env value or generate a strong random key (64 hex chars = 256 bits)
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)

    # Print generated key in development so you can copy-paste into .env
    if not os.getenv("FLASK_SECRET_KEY"):
        print(f"[CONFIG] Generated SECRET_KEY (add to .env): {SECRET_KEY}")

    # ────────────────────────────────────────────────
    # Database Configuration
    # ────────────────────────────────────────────────
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_NAME = os.getenv("DB_NAME", "cybexplore_bac")  # your chosen DB name
    DB_PORT = os.getenv("DB_PORT", "3306")

    SQLALCHEMY_DATABASE_URI = (
        f"mysql+mysqlconnector://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_recycle": 3600}  # Helps with long-running sessions

    # ────────────────────────────────────────────────
    # File Uploads (for profile photos, listings, etc.)
    # ────────────────────────────────────────────────
    UPLOAD_FOLDER = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "static", "uploads"
    )
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload size

    # Create upload folder automatically if it doesn't exist
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    # ────────────────────────────────────────────────
    # Monitor / Admin Dashboard (your private access only)
    # ────────────────────────────────────────────────
    MONITOR_USERNAME = os.getenv("MONITOR_USERNAME", "cybadmin")
    MONITOR_PASSWORD = os.getenv("MONITOR_PASSWORD")  # MUST be set in .env

    # Optional: IP whitelist for extra protection (comma-separated IPs)
    MONITOR_ALLOWED_IPS = os.getenv("MONITOR_ALLOWED_IPS", "").split(",")

    # ────────────────────────────────────────────────
    # Session & Security Settings
    # ────────────────────────────────────────────────
    SESSION_COOKIE_SAMESITE = "Lax"  # Can be changed to None for testing CSRF
    SESSION_COOKIE_SECURE = False    # Set to True in production (HTTPS)
    PERMANENT_SESSION_LIFETIME = 3600 * 24 * 7  # 7 days for remember-me

    # ────────────────────────────────────────────────
    # Application Info (used in templates, emails, etc.)
    # ────────────────────────────────────────────────
    APP_NAME = "CybExplore Broken Access Control Lab"
    APP_VERSION = "1.0.0-teaser"
    CREATOR_NAME = "Nurudeen O.A"  # Change to your real name
    CREATOR_BRAND = "CybExplore"
    CREATOR_WEBSITE = "https://cybexplore.org"
    CREATOR_EMAIL = "info@cybexplore.org"  # Update this

    # Debug / Development settings
    DEBUG = os.getenv("FLASK_DEBUG", "True").lower() == "true"


# Optional: Development-specific overrides (when DEBUG=True)
class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = True


# Optional: Production overrides (when DEBUG=False)
class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    SQLALCHEMY_ECHO = False


# How to use in app.py:
# app.config.from_object('config.Config')
# or: app.config.from_object('config.DevelopmentConfig' if os.getenv('FLASK_ENV') == 'development' else 'config.ProductionConfig')
