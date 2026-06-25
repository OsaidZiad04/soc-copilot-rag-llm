from .minirag_base import SQLAlchemyBase
from sqlalchemy import Column, Integer, String, Float, Text, DateTime, func, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
import uuid


class ThreatAnalysis(SQLAlchemyBase):
    __tablename__ = "threat_analyses"

    analysis_id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_uuid = Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False)
    input_text = Column(Text, nullable=False)
    input_type = Column(String(50), server_default="alert")
    title = Column(String(500), nullable=True)
    threat_type = Column(String(200), nullable=True)
    risk_level = Column(String(20), server_default="info")
    risk_score = Column(Float, server_default="0.0")
    confidence = Column(Float, server_default="0.0")
    analysis_result = Column(JSONB, nullable=False)
    mitre_techniques = Column(JSONB, nullable=True)
    iocs = Column(JSONB, nullable=True)
    detection_rules = Column(JSONB, nullable=True)
    investigation_id = Column(UUID(as_uuid=True), nullable=True)
    analyst_feedback = Column(String(20), nullable=True)
    analyst_notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), nullable=True)

    __table_args__ = (
        Index("ix_analysis_risk_level", risk_level),
        Index("ix_analysis_input_type", input_type),
        Index("ix_analysis_created_at", created_at),
    )
