"""SQLite persistence layer, used for storing connected Gmail accounts.

This is the first real database usage in the project -- SQLAlchemy and
aiosqlite were already pinned in requirements.txt in earlier phases but
unused until now. Only one table exists today (GmailAccount); the risk
engine and analyzers remain stateless per-request and do not touch this
database.

Async engine (aiosqlite driver) is used since the rest of the app is
async (FastAPI route handlers, httpx-based provider adapters). The
SQLite file path comes from settings.database_url, matching the existing
DATABASE_URL env var already documented in .env.example since Phase 1.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, String, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.config import settings


class Base(DeclarativeBase):
    pass


class GmailAccount(Base):
    """A single connected Gmail account.

    Single-user design: this project has no login/auth system of its
    own, so there is exactly one row at a time (id=1, enforced by always
    upserting rather than inserting a new row per connect). Storing more
    than one connected account is out of scope for this phase.

    refresh_token is a long-lived credential equivalent to a password
    for read access to this Gmail account. It is stored here in plain
    text in a local SQLite file that is gitignored (see .gitignore's
    *.db exclusion) -- acceptable for a local hackathon demo, NOT
    acceptable for a deployed multi-user product without proper secret
    encryption at rest.
    """

    __tablename__ = "gmail_accounts"

    id: Mapped[int] = mapped_column(primary_key=True)
    email_address: Mapped[str] = mapped_column(String, nullable=False)
    refresh_token: Mapped[str] = mapped_column(String, nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    connected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )


# Convert the sync-style "sqlite:///./safecheck.db" URL (as documented in
# .env.example since Phase 1) into the aiosqlite driver form SQLAlchemy's
# async engine requires.
def _to_async_url(database_url: str) -> str:
    if database_url.startswith("sqlite:///"):
        return database_url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
    return database_url


_engine = create_async_engine(_to_async_url(settings.database_url))
_SessionLocal = async_sessionmaker(_engine, expire_on_commit=False)


async def init_db() -> None:
    """Create tables if they don't exist yet. Called once at app startup."""
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_gmail_account() -> GmailAccount | None:
    async with _SessionLocal() as session:
        result = await session.execute(select(GmailAccount).where(GmailAccount.id == 1))
        return result.scalar_one_or_none()


async def upsert_gmail_account(email_address: str, refresh_token: str) -> None:
    """Insert or replace the single connected Gmail account (id=1).

    A fresh OAuth connect always replaces any previously stored account
    rather than erroring -- reconnecting (e.g. after revoking access, or
    switching Google accounts) should just work.
    """
    async with _SessionLocal() as session:
        existing = await session.get(GmailAccount, 1)
        if existing is not None:
            existing.email_address = email_address
            existing.refresh_token = refresh_token
            existing.last_checked_at = None
        else:
            session.add(
                GmailAccount(
                    id=1,
                    email_address=email_address,
                    refresh_token=refresh_token,
                )
            )
        await session.commit()


async def update_last_checked_at(when: datetime) -> None:
    async with _SessionLocal() as session:
        existing = await session.get(GmailAccount, 1)
        if existing is not None:
            existing.last_checked_at = when
            await session.commit()
