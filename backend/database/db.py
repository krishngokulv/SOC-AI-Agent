"""Database manager for async SQLite operations."""

import json
from datetime import datetime, timedelta
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import select, func, desc, and_
from .models import Base, Investigation, IOCRecord, EnrichmentCache
from config import config


class DatabaseManager:
    """Manages async database connections and operations."""

    def __init__(self, database_url: Optional[str] = None):
        self.database_url = database_url or config.DATABASE_URL
        self.engine = create_async_engine(self.database_url, echo=False)
        self.async_session = async_sessionmaker(self.engine, class_=AsyncSession, expire_on_commit=False)

    async def init_db(self) -> None:
        """Create all tables if they don't exist."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def close(self) -> None:
        """Close the database engine."""
        await self.engine.dispose()

    # --- Investigation Operations ---

    async def create_investigation(self, alert_id: str, raw_alert: str, alert_type: str) -> Investigation:
        """Create a new investigation record."""
        async with self.async_session() as session:
            inv = Investigation(
                alert_id=alert_id,
                raw_alert=raw_alert,
                alert_type=alert_type,
                timestamp=datetime.utcnow(),
            )
            session.add(inv)
            await session.commit()
            await session.refresh(inv)
            return inv

    async def update_investigation(
        self,
        alert_id: str,
        verdict: Optional[str] = None,
        confidence: Optional[float] = None,
        reasoning: Optional[str] = None,
        mitre_techniques: Optional[list] = None,
        report_path_html: Optional[str] = None,
        report_path_pdf: Optional[str] = None,
        investigation_data: Optional[dict] = None,
    ) -> Optional[Investigation]:
        """Update an existing investigation."""
        async with self.async_session() as session:
            result = await session.execute(
                select(Investigation).where(Investigation.alert_id == alert_id)
            )
            inv = result.scalar_one_or_none()
            if not inv:
                return None

            if verdict is not None:
                inv.verdict = verdict
            if confidence is not None:
                inv.confidence = confidence
            if reasoning is not None:
                inv.reasoning = reasoning
            if mitre_techniques is not None:
                inv.set_mitre_techniques(mitre_techniques)
            if report_path_html is not None:
                inv.report_path_html = report_path_html
            if report_path_pdf is not None:
                inv.report_path_pdf = report_path_pdf
            if investigation_data is not None:
                inv.investigation_data = json.dumps(investigation_data, default=str)
            inv.completed_at = datetime.utcnow()

            await session.commit()
            await session.refresh(inv)
            return inv

    async def get_investigation(self, alert_id: str) -> Optional[Investigation]:
        """Get a single investigation by alert_id."""
        async with self.async_session() as session:
            result = await session.execute(
                select(Investigation).where(Investigation.alert_id == alert_id)
            )
            inv = result.scalar_one_or_none()
            if inv:
                await session.refresh(inv, ["iocs"])
            return inv

    async def get_investigation_by_db_id(self, db_id: int) -> Optional[Investigation]:
        """Get a single investigation by database ID."""
        async with self.async_session() as session:
            result = await session.execute(
                select(Investigation).where(Investigation.id == db_id)
            )
            inv = result.scalar_one_or_none()
            if inv:
                await session.refresh(inv, ["iocs"])
            return inv

    async def list_investigations(
        self,
        limit: int = 50,
        offset: int = 0,
        verdict_filter: Optional[str] = None,
        alert_type_filter: Optional[str] = None,
    ) -> tuple[List[Investigation], int]:
        """List investigations with pagination and filtering."""
        async with self.async_session() as session:
            query = select(Investigation)
            count_query = select(func.count(Investigation.id))

            if verdict_filter:
                query = query.where(Investigation.verdict == verdict_filter)
                count_query = count_query.where(Investigation.verdict == verdict_filter)
            if alert_type_filter:
                query = query.where(Investigation.alert_type == alert_type_filter)
                count_query = count_query.where(Investigation.alert_type == alert_type_filter)

            total_result = await session.execute(count_query)
            total = total_result.scalar()

            query = query.order_by(desc(Investigation.timestamp)).limit(limit).offset(offset)
            result = await session.execute(query)
            investigations = result.scalars().all()

            for inv in investigations:
                await session.refresh(inv, ["iocs"])

            return investigations, total

    async def find_related_investigations(self, ioc_values: List[str]) -> List[dict]:
        """Find investigations containing any of the given IOC values."""
        if not ioc_values:
            return []

        async with self.async_session() as session:
            result = await session.execute(
                select(IOCRecord).where(IOCRecord.value.in_(ioc_values))
            )
            ioc_records = result.scalars().all()

            inv_ids = set()
            related = []
            for record in ioc_records:
                if record.investigation_id not in inv_ids:
                    inv_ids.add(record.investigation_id)
                    inv_result = await session.execute(
                        select(Investigation).where(Investigation.id == record.investigation_id)
                    )
                    inv = inv_result.scalar_one_or_none()
                    if inv:
                        related.append({
                            "investigation_id": inv.id,
                            "alert_id": inv.alert_id,
                            "alert_type": inv.alert_type,
                            "verdict": inv.verdict,
                            "confidence": inv.confidence,
                            "timestamp": inv.timestamp.isoformat() if inv.timestamp else None,
                            "matching_ioc": record.value,
                        })

            return related

    # --- IOC Operations ---

    async def save_iocs(self, investigation_id: int, iocs: List[dict]) -> None:
        """Save IOC records for an investigation, updating times_seen if existing."""
        async with self.async_session() as session:
            for ioc_data in iocs:
                # Check if this IOC value has been seen before
                result = await session.execute(
                    select(IOCRecord).where(
                        and_(
                            IOCRecord.value == ioc_data["value"],
                            IOCRecord.ioc_type == ioc_data["type"],
                        )
                    ).order_by(IOCRecord.first_seen).limit(1)
                )
                existing = result.scalar_one_or_none()

                record = IOCRecord(
                    investigation_id=investigation_id,
                    ioc_type=ioc_data["type"],
                    value=ioc_data["value"],
                    risk_score=ioc_data.get("risk_score", 0.0),
                    enrichment_data=json.dumps(ioc_data.get("enrichment_data", {}), default=str),
                    first_seen=existing.first_seen if existing else datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    times_seen=(existing.times_seen + 1) if existing else 1,
                )
                session.add(record)

            await session.commit()

    async def list_iocs(
        self,
        limit: int = 100,
        offset: int = 0,
        search: Optional[str] = None,
        ioc_type: Optional[str] = None,
    ) -> tuple[List[IOCRecord], int]:
        """List IOCs with pagination and search."""
        async with self.async_session() as session:
            query = select(IOCRecord)
            count_query = select(func.count(IOCRecord.id))

            if search:
                query = query.where(IOCRecord.value.contains(search))
                count_query = count_query.where(IOCRecord.value.contains(search))
            if ioc_type:
                query = query.where(IOCRecord.ioc_type == ioc_type)
                count_query = count_query.where(IOCRecord.ioc_type == ioc_type)

            total_result = await session.execute(count_query)
            total = total_result.scalar()

            query = query.order_by(desc(IOCRecord.last_seen)).limit(limit).offset(offset)
            result = await session.execute(query)
            records = result.scalars().all()

            return records, total

    async def get_ioc_details(self, ioc_value: str) -> List[IOCRecord]:
        """Get all records for a specific IOC value."""
        async with self.async_session() as session:
            result = await session.execute(
                select(IOCRecord).where(IOCRecord.value == ioc_value).order_by(desc(IOCRecord.last_seen))
            )
            return result.scalars().all()

    # --- Cache Operations ---

    async def get_cached_enrichment(self, ioc_value: str, ioc_type: str, source: str) -> Optional[dict]:
        """Get cached enrichment result if fresh (within TTL)."""
        async with self.async_session() as session:
            cutoff = datetime.utcnow() - timedelta(seconds=config.CACHE_TTL)
            result = await session.execute(
                select(EnrichmentCache).where(
                    and_(
                        EnrichmentCache.ioc_value == ioc_value,
                        EnrichmentCache.ioc_type == ioc_type,
                        EnrichmentCache.source == source,
                        EnrichmentCache.cached_at >= cutoff,
                    )
                ).order_by(desc(EnrichmentCache.cached_at)).limit(1)
            )
            cache = result.scalar_one_or_none()
            if cache:
                return cache.get_response()
            return None

    async def save_enrichment_cache(self, ioc_value: str, ioc_type: str, source: str, response: dict) -> None:
        """Save an enrichment result to cache."""
        async with self.async_session() as session:
            cache = EnrichmentCache(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                source=source,
                response=json.dumps(response, default=str),
                cached_at=datetime.utcnow(),
            )
            session.add(cache)
            await session.commit()

    # --- Stats Operations ---

    async def get_stats(self) -> dict:
        """Get dashboard statistics."""
        async with self.async_session() as session:
            total = (await session.execute(select(func.count(Investigation.id)))).scalar() or 0

            tp = (await session.execute(
                select(func.count(Investigation.id)).where(Investigation.verdict == "TRUE_POSITIVE")
            )).scalar() or 0

            fp = (await session.execute(
                select(func.count(Investigation.id)).where(Investigation.verdict == "FALSE_POSITIVE")
            )).scalar() or 0

            esc = (await session.execute(
                select(func.count(Investigation.id)).where(Investigation.verdict == "NEEDS_ESCALATION")
            )).scalar() or 0

            unique_iocs = (await session.execute(
                select(func.count(func.distinct(IOCRecord.value)))
            )).scalar() or 0

            avg_confidence = (await session.execute(
                select(func.avg(Investigation.confidence)).where(Investigation.confidence.isnot(None))
            )).scalar() or 0

            # Top IOCs
            top_iocs_query = (
                select(IOCRecord.value, IOCRecord.ioc_type, func.max(IOCRecord.risk_score).label("max_risk"), func.count(IOCRecord.id).label("cnt"))
                .group_by(IOCRecord.value, IOCRecord.ioc_type)
                .order_by(desc("cnt"))
                .limit(10)
            )
            top_iocs_result = await session.execute(top_iocs_query)
            top_iocs = [
                {"value": row[0], "type": row[1], "risk_score": row[2], "count": row[3]}
                for row in top_iocs_result.all()
            ]

            # Recent investigations
            recent_result = await session.execute(
                select(Investigation).order_by(desc(Investigation.timestamp)).limit(10)
            )
            recent = [inv.to_dict() for inv in recent_result.scalars().all()]

            return {
                "total_investigations": total,
                "true_positives": tp,
                "false_positives": fp,
                "needs_escalation": esc,
                "unique_iocs": unique_iocs,
                "avg_confidence": round(float(avg_confidence), 1),
                "top_iocs": top_iocs,
                "recent_investigations": recent,
            }

    async def get_mitre_heatmap(self) -> dict:
        """Get MITRE ATT&CK technique frequency data."""
        async with self.async_session() as session:
            result = await session.execute(
                select(Investigation.mitre_techniques).where(Investigation.mitre_techniques.isnot(None))
            )
            rows = result.scalars().all()

            technique_counts: dict = {}
            for row in rows:
                try:
                    techniques = json.loads(row)
                    for tech in techniques:
                        tid = tech.get("technique_id", "")
                        if tid:
                            if tid not in technique_counts:
                                technique_counts[tid] = {
                                    "technique_id": tid,
                                    "name": tech.get("name", ""),
                                    "tactic": tech.get("tactic", ""),
                                    "count": 0,
                                }
                            technique_counts[tid]["count"] += 1
                except (json.JSONDecodeError, TypeError):
                    continue

            return {
                "techniques": sorted(technique_counts.values(), key=lambda x: x["count"], reverse=True)
            }


# Global database instance
_db: Optional[DatabaseManager] = None


async def get_db() -> DatabaseManager:
    """Get or create the global database manager."""
    global _db
    if _db is None:
        _db = DatabaseManager()
        await _db.init_db()
    return _db
