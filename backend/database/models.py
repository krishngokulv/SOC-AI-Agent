"""SQLAlchemy ORM models for the SOC-AI-Agent database."""

import json
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Text, DateTime, Boolean, ForeignKey, Index
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """Base class for all database models."""
    pass


class Investigation(Base):
    """Stores complete investigation records."""

    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(36), unique=True, nullable=False, index=True)
    raw_alert = Column(Text, nullable=False)
    alert_type = Column(String(50), nullable=False)
    verdict = Column(String(20), nullable=True)
    confidence = Column(Float, nullable=True)
    reasoning = Column(Text, nullable=True)
    mitre_techniques = Column(Text, nullable=True)  # JSON string
    report_path_html = Column(String(500), nullable=True)
    report_path_pdf = Column(String(500), nullable=True)
    investigation_data = Column(Text, nullable=True)  # Full investigation JSON
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    iocs = relationship("IOCRecord", back_populates="investigation", cascade="all, delete-orphan")

    def get_mitre_techniques(self) -> list:
        """Deserialize MITRE techniques from JSON."""
        if self.mitre_techniques:
            try:
                return json.loads(self.mitre_techniques)
            except json.JSONDecodeError:
                return []
        return []

    def set_mitre_techniques(self, techniques: list) -> None:
        """Serialize MITRE techniques to JSON."""
        self.mitre_techniques = json.dumps(techniques)

    def get_investigation_data(self) -> dict:
        """Deserialize full investigation data."""
        if self.investigation_data:
            try:
                return json.loads(self.investigation_data)
            except json.JSONDecodeError:
                return {}
        return {}

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "raw_alert": self.raw_alert[:500] if self.raw_alert else None,
            "alert_type": self.alert_type,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "mitre_techniques": self.get_mitre_techniques(),
            "report_path_html": self.report_path_html,
            "report_path_pdf": self.report_path_pdf,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "ioc_count": len(self.iocs) if self.iocs else 0,
        }

    def to_detail_dict(self) -> dict:
        """Serialize with full investigation data."""
        base = self.to_dict()
        base["raw_alert"] = self.raw_alert
        base["investigation_data"] = self.get_investigation_data()
        base["iocs"] = [ioc.to_dict() for ioc in self.iocs] if self.iocs else []
        return base


class IOCRecord(Base):
    """Stores IOC records linked to investigations."""

    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"), nullable=False, index=True)
    ioc_type = Column(String(30), nullable=False)
    value = Column(String(500), nullable=False, index=True)
    risk_score = Column(Float, default=0.0)
    enrichment_data = Column(Text, nullable=True)  # JSON string
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    times_seen = Column(Integer, default=1)

    # Relationships
    investigation = relationship("Investigation", back_populates="iocs")

    __table_args__ = (
        Index("idx_ioc_value_type", "value", "ioc_type"),
    )

    def get_enrichment_data(self) -> dict:
        """Deserialize enrichment data."""
        if self.enrichment_data:
            try:
                return json.loads(self.enrichment_data)
            except json.JSONDecodeError:
                return {}
        return {}

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "type": self.ioc_type,
            "value": self.value,
            "risk_score": self.risk_score,
            "enrichment_data": self.get_enrichment_data(),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "times_seen": self.times_seen,
        }


class EnrichmentCache(Base):
    """Caches enrichment API responses to avoid redundant calls."""

    __tablename__ = "enrichment_cache"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_value = Column(String(500), nullable=False, index=True)
    ioc_type = Column(String(30), nullable=False)
    source = Column(String(50), nullable=False)
    response = Column(Text, nullable=True)  # JSON string
    cached_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("idx_cache_lookup", "ioc_value", "ioc_type", "source"),
    )

    def get_response(self) -> dict:
        """Deserialize cached response."""
        if self.response:
            try:
                return json.loads(self.response)
            except json.JSONDecodeError:
                return {}
        return {}

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "id": self.id,
            "ioc_value": self.ioc_value,
            "ioc_type": self.ioc_type,
            "source": self.source,
            "response": self.get_response(),
            "cached_at": self.cached_at.isoformat() if self.cached_at else None,
        }
