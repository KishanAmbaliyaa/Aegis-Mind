from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field

from sqlalchemy import Column, Integer, String, Float, Boolean, Text, DateTime, JSON
from sqlalchemy.orm import declarative_base

Base = declarative_base()

# ==========================================
# Pydantic Schemas for Validation & LLM
# ==========================================

class SeverityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MitreDetail(BaseModel):
    id: Optional[List[str]] = Field(default_factory=list)
    tactic: Optional[List[str]] = Field(default_factory=list)
    technique: Optional[List[str]] = Field(default_factory=list)


class RuleDetail(BaseModel):
    id: Optional[str] = "unknown"
    level: Optional[int] = 1
    description: Optional[str] = "No description provided"
    mitre: Optional[MitreDetail] = None


class AlertPayload(BaseModel):
    """
    Standardized SIEM alert ingestion schema (Wazuh, Splunk, Elastic, honeypots).
    """
    timestamp: Optional[str] = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_ip: str = Field(..., description="Source IP address of the potential attacker")
    rule: Optional[RuleDetail] = None
    location: Optional[str] = None
    data: Optional[Dict[str, Any]] = Field(default_factory=dict)
    agent: Optional[Dict[str, Any]] = Field(default_factory=dict)
    manager: Optional[Dict[str, Any]] = Field(default_factory=dict)


class TriageReport(BaseModel):
    """
    Structured Gemini LLM response schema for autonomous SOC triage.
    """
    severity: SeverityEnum = Field(
        description="Assessed severity level of the incident: LOW, MEDIUM, HIGH, or CRITICAL"
    )
    confidence_score: float = Field(
        description="Confidence score between 0.0 and 1.0 based on log clarity and intel"
    )
    is_false_positive: bool = Field(
        description="Whether this incident appears to be benign activity, scanner noise, or false positive"
    )
    attack_vector_summary: str = Field(
        description="Concise 2-3 sentence executive breakdown of the attack behavior and vector"
    )
    mitre_tactic: str = Field(
        description="Primary MITRE ATT&CK Tactic (e.g., Credential Access, Initial Access)"
    )
    mitre_technique_id: str = Field(
        description="Primary MITRE ATT&CK Technique ID (e.g., T1110, T1190)"
    )
    mitre_technique_name: str = Field(
        description="Primary MITRE ATT&CK Technique Name (e.g., Brute Force, Exploit Public-Facing Application)"
    )
    recommended_containment: str = Field(
        description="Specific, immediate technical containment action for firewall or EDR"
    )
    auto_containment_recommended: bool = Field(
        description="True if confidence is high (>0.85) and immediate blocking is warranted"
    )
    analyst_guidance: str = Field(
        description="Follow-up investigation guidance and hunting tips for Tier 2/3 analysts"
    )


class ContainmentActionRequest(BaseModel):
    incident_uuid: str
    action: str = Field(..., description="Action to perform: BLOCK_IP, ISOLATE_HOST, FALSE_POSITIVE")
    analyst_notes: Optional[str] = "Action executed via analyst dashboard/API"


# ==========================================
# SQLAlchemy ORM Models for Persistence
# ==========================================

class IncidentRecord(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_uuid = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()), index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    rule_id = Column(String(64), nullable=True)
    rule_description = Column(String(255), nullable=True)
    
    # Threat Intel & Triage Details
    intel_data = Column(JSON, nullable=True)
    severity = Column(String(16), nullable=False, default="MEDIUM", index=True)
    confidence_score = Column(Float, nullable=False, default=0.5)
    is_false_positive = Column(Boolean, nullable=False, default=False)
    
    # MITRE ATT&CK
    mitre_tactic = Column(String(128), nullable=True)
    mitre_technique_id = Column(String(32), nullable=True, index=True)
    mitre_technique_name = Column(String(128), nullable=True)
    
    # Summaries & Containment
    attack_summary = Column(Text, nullable=True)
    recommended_containment = Column(Text, nullable=True)
    analyst_guidance = Column(Text, nullable=True)
    auto_containment_recommended = Column(Boolean, default=False)
    
    # Lifecycle & SOAR Status
    status = Column(String(32), nullable=False, default="TRIAGED", index=True)  # TRIAGED, CONTAINED, FALSE_POSITIVE
    action_audit_log = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
