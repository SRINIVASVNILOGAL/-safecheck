"""Local SQLite persistence for the connected Gmail account and warning audit."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, Integer, String, Text, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.config import settings


class Base(DeclarativeBase):
    pass


class GmailAccount(Base):
    """One local-demo Gmail account; refresh tokens are plaintext only locally."""
    __tablename__ = "gmail_accounts"
    id: Mapped[int] = mapped_column(primary_key=True)
    email_address: Mapped[str] = mapped_column(String, nullable=False)
    refresh_token: Mapped[str] = mapped_column(String, nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    connected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class WarningCampaign(Base):
    """Persisted reviewable warning draft and confirmation/idempotency state."""
    __tablename__ = "warning_campaigns"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    gmail_message_id: Mapped[str] = mapped_column(String, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_band: Mapped[str] = mapped_column(String, nullable=False)
    recipients_json: Mapped[str] = mapped_column(Text, nullable=False)
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="DRAFT")
    idempotency_key: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WarningDelivery(Base):
    __tablename__ = "warning_deliveries"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    campaign_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    recipient: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="PENDING")
    gmail_message_id: Mapped[str | None] = mapped_column(String, nullable=True)
    error: Mapped[str | None] = mapped_column(String, nullable=True)
    attempted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RecoveryReport(Base):
    """Persisted reviewable fraud-report draft (Analyze -> identify org ->
    find official contact -> generate email -> user reviews -> user sends).
    Distinct from WarningCampaign: a WarningCampaign warns the account
    owner's own contacts about a possibly compromised account; a
    RecoveryReport reports a received fraud attempt to the impersonated
    or relevant organization/authority.
    """
    __tablename__ = "recovery_reports"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    case_id: Mapped[str] = mapped_column(String, nullable=False)
    org_key: Mapped[str] = mapped_column(String, nullable=False)
    org_display_name: Mapped[str] = mapped_column(String, nullable=False)
    recipient_email: Mapped[str | None] = mapped_column(String, nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_band: Mapped[str] = mapped_column(String, nullable=False)
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="DRAFT")
    idempotency_key: Mapped[str | None] = mapped_column(String, nullable=True)
    gmail_message_id: Mapped[str | None] = mapped_column(String, nullable=True)
    error: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


def _to_async_url(database_url: str) -> str:
    return database_url.replace("sqlite:///", "sqlite+aiosqlite:///", 1) if database_url.startswith("sqlite:///") else database_url


_engine = create_async_engine(_to_async_url(settings.database_url))
_SessionLocal = async_sessionmaker(_engine, expire_on_commit=False)


async def init_db() -> None:
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_gmail_account() -> GmailAccount | None:
    async with _SessionLocal() as session:
        return await session.get(GmailAccount, 1)


async def upsert_gmail_account(email_address: str, refresh_token: str) -> None:
    async with _SessionLocal() as session:
        account = await session.get(GmailAccount, 1)
        if account:
            account.email_address, account.refresh_token, account.last_checked_at = email_address, refresh_token, None
        else:
            session.add(GmailAccount(id=1, email_address=email_address, refresh_token=refresh_token))
        await session.commit()


async def update_last_checked_at(when: datetime) -> None:
    async with _SessionLocal() as session:
        account = await session.get(GmailAccount, 1)
        if account:
            account.last_checked_at = when
            await session.commit()


async def create_warning_campaign(*, gmail_message_id: str, risk_score: int, risk_band: str, recipients: list[str], subject: str, body: str) -> WarningCampaign:
    campaign = WarningCampaign(id=f"warning_{uuid4().hex}", gmail_message_id=gmail_message_id, risk_score=risk_score, risk_band=risk_band, recipients_json=json.dumps(recipients), subject=subject, body=body)
    async with _SessionLocal() as session:
        session.add(campaign)
        session.add_all(WarningDelivery(campaign_id=campaign.id, recipient=recipient) for recipient in recipients)
        await session.commit()
    return campaign


async def get_warning_campaign(campaign_id: str) -> tuple[WarningCampaign | None, list[WarningDelivery]]:
    async with _SessionLocal() as session:
        campaign = await session.get(WarningCampaign, campaign_id)
        if campaign is None:
            return None, []
        deliveries = list((await session.execute(select(WarningDelivery).where(WarningDelivery.campaign_id == campaign_id))).scalars())
        return campaign, deliveries


async def claim_warning_campaign(campaign_id: str, *, idempotency_key: str, subject: str, body: str) -> tuple[WarningCampaign | None, bool]:
    """Atomically make a DRAFT sendable; duplicate same-key confirms are no-ops."""
    async with _SessionLocal() as session:
        campaign = await session.get(WarningCampaign, campaign_id)
        if campaign is None:
            return None, False
        if campaign.idempotency_key:
            return campaign, campaign.idempotency_key == idempotency_key
        if campaign.status != "DRAFT":
            return campaign, False
        campaign.idempotency_key, campaign.subject, campaign.body = idempotency_key, subject, body
        campaign.status, campaign.confirmed_at = "SENDING", datetime.now(timezone.utc)
        await session.commit()
        return campaign, True


async def record_warning_delivery(delivery_id: int, *, status: str, gmail_message_id: str | None = None, error: str | None = None) -> None:
    async with _SessionLocal() as session:
        delivery = await session.get(WarningDelivery, delivery_id)
        if delivery:
            delivery.status, delivery.gmail_message_id, delivery.error, delivery.attempted_at = status, gmail_message_id, error, datetime.now(timezone.utc)
            await session.commit()


async def finish_warning_campaign(campaign_id: str) -> None:
    async with _SessionLocal() as session:
        campaign = await session.get(WarningCampaign, campaign_id)
        if campaign:
            deliveries = list((await session.execute(select(WarningDelivery).where(WarningDelivery.campaign_id == campaign_id))).scalars())
            campaign.status = "SENT" if deliveries and all(item.status == "SENT" for item in deliveries) else "PARTIAL_OR_FAILED"
            await session.commit()


async def create_recovery_report(
    *,
    case_id: str,
    org_key: str,
    org_display_name: str,
    recipient_email: str | None,
    risk_score: int,
    risk_band: str,
    subject: str,
    body: str,
) -> RecoveryReport:
    report = RecoveryReport(
        id=f"recovery_{uuid4().hex}",
        case_id=case_id,
        org_key=org_key,
        org_display_name=org_display_name,
        recipient_email=recipient_email,
        risk_score=risk_score,
        risk_band=risk_band,
        subject=subject,
        body=body,
    )
    async with _SessionLocal() as session:
        session.add(report)
        await session.commit()
    return report


async def get_recovery_report(report_id: str) -> RecoveryReport | None:
    async with _SessionLocal() as session:
        return await session.get(RecoveryReport, report_id)


async def claim_recovery_report(report_id: str, *, idempotency_key: str, subject: str, body: str) -> tuple[RecoveryReport | None, bool]:
    """Atomically make a DRAFT sendable; duplicate same-key confirms are no-ops.

    Mirrors claim_warning_campaign's semantics exactly.
    """
    async with _SessionLocal() as session:
        report = await session.get(RecoveryReport, report_id)
        if report is None:
            return None, False
        if report.idempotency_key:
            return report, report.idempotency_key == idempotency_key
        if report.status != "DRAFT":
            return report, False
        report.idempotency_key, report.subject, report.body = idempotency_key, subject, body
        report.status, report.confirmed_at = "SENDING", datetime.now(timezone.utc)
        await session.commit()
        return report, True


async def finish_recovery_report(report_id: str, *, status: str, gmail_message_id: str | None = None, error: str | None = None) -> None:
    async with _SessionLocal() as session:
        report = await session.get(RecoveryReport, report_id)
        if report:
            report.status, report.gmail_message_id, report.error = status, gmail_message_id, error
            await session.commit()
