import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()

@dataclass(frozen=True)
class Settings:
    app_name: str = "SafeCheck API"
    app_version: str = "0.1.0"
    database_url: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///./safecheck.db",
    )
    cors_origins: tuple[str, ...] = tuple(
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:3000",
        ).split(",")
        if origin.strip()
    )
    # Where the browser is redirected back to after the Gmail OAuth
    # consent flow completes (app.api.email's connect/callback route).
    # Not the same as GMAIL_REDIRECT_URI, which is Google's callback URL
    # (pointing at our own backend) -- this is the frontend page users
    # land on afterward.
    frontend_url: str = os.getenv("FRONTEND_URL", "http://localhost:3000")
    google_client_id: str = os.getenv("GOOGLE_CLIENT_ID", "")
    google_client_secret: str = os.getenv("GOOGLE_CLIENT_SECRET", "")
    gmail_redirect_uri: str = os.getenv(
        "GMAIL_REDIRECT_URI", "http://localhost:8000/v1/email/connect/callback"
    )

settings = Settings()
