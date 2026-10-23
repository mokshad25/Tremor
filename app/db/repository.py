"""
TREMOR — Database repository (async CRUD operations).

Owner: Varad (pipeline integration)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.models import AlertRecord, Base, DeliveryRecord

if TYPE_CHECKING:
    from app.core.alerts import Alert


class Database:
    """Async database manager — creates engine, session factory, and tables."""

    def __init__(self, url: str) -> None:
        self.engine = create_async_engine(url, echo=False)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)

    async def init(self) -> None:
        """Create all tables."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def close(self) -> None:
        """Dispose engine connections."""
        await self.engine.dispose()


class AlertRepository:
    """CRUD operations for alerts."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def save(self, alert: Alert) -> None:
        """Persist an alert (insert or update)."""
        async with self._db.session_factory() as session:
            record = AlertRecord(
                id=alert.id,
                incident_id=alert.incident_id,
                service=alert.service,
                signal_type=alert.signal_type.value,
                status=alert.status.value,
                severity=alert.severity,
                reason=alert.reason,
                value=alert.value,
                baseline=alert.baseline,
                z_score=alert.z_score,
                lines=alert.lines,
                errors=alert.errors,
                template_id=alert.template_id,
                explanation=alert.explanation,
                timeline=[{"ts": t.ts, "status": t.status.value, "reason": t.reason} for t in alert.timeline],
                samples=alert.samples,
                created_at=datetime.fromtimestamp(alert.created_at, tz=timezone.utc) if alert.created_at else datetime.now(timezone.utc),
                updated_at=datetime.fromtimestamp(alert.updated_at, tz=timezone.utc) if alert.updated_at else datetime.now(timezone.utc),
            )
            await session.merge(record)
            await session.commit()

    async def get(self, alert_id: str) -> AlertRecord | None:
        """Get a single alert by ID."""
        async with self._db.session_factory() as session:
            return await session.get(AlertRecord, alert_id)

    async def list_alerts(
        self,
        service: str | None = None,
        signal_type: str | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AlertRecord]:
        """List alerts with optional filters."""
        async with self._db.session_factory() as session:
            stmt = select(AlertRecord).order_by(AlertRecord.created_at.desc())
            if service:
                stmt = stmt.where(AlertRecord.service == service)
            if signal_type:
                stmt = stmt.where(AlertRecord.signal_type == signal_type)
            if status:
                stmt = stmt.where(AlertRecord.status == status)
            stmt = stmt.limit(limit).offset(offset)
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def count(
        self,
        service: str | None = None,
        signal_type: str | None = None,
        status: str | None = None,
    ) -> int:
        """Count alerts matching the filters."""
        async with self._db.session_factory() as session:
            from sqlalchemy import func as sqlfunc
            stmt = select(sqlfunc.count(AlertRecord.id))
            if service:
                stmt = stmt.where(AlertRecord.service == service)
            if signal_type:
                stmt = stmt.where(AlertRecord.signal_type == signal_type)
            if status:
                stmt = stmt.where(AlertRecord.status == status)
            result = await session.execute(stmt)
            return result.scalar_one()
