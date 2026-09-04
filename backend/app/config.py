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

settings = Settings()
