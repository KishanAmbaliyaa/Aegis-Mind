import logging
from typing import List, Optional, Dict, Any
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from config import settings
from models import Base, IncidentRecord

logger = logging.getLogger("AegisMind.Database")

# Setup SQLAlchemy engine (SQLite by default, compatible with PostgreSQL)
connect_args = {"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
engine = create_engine(settings.DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionFactory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db_session = scoped_session(SessionFactory)


def init_db():
    """Create all tables in the database if they do not exist."""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("[+] Database initialized successfully.")
    except Exception as e:
        logger.error(f"[!] Error initializing database: {e}")


def save_incident(
    incident_uuid: str,
    source_ip: str,
    rule_id: Optional[str],
    rule_description: Optional[str],
    intel_data: Dict[str, Any],
    triage: Dict[str, Any]
) -> Optional[IncidentRecord]:
    """Persist a triaged incident to the database."""
    session = db_session()
    try:
        record = IncidentRecord(
            incident_uuid=incident_uuid,
            source_ip=source_ip,
            rule_id=rule_id,
            rule_description=rule_description,
            intel_data=intel_data,
            severity=triage.get("severity", "MEDIUM"),
            confidence_score=triage.get("confidence_score", 0.5),
            is_false_positive=triage.get("is_false_positive", False),
            mitre_tactic=triage.get("mitre_tactic"),
            mitre_technique_id=triage.get("mitre_technique_id"),
            mitre_technique_name=triage.get("mitre_technique_name"),
            attack_summary=triage.get("attack_vector_summary"),
            recommended_containment=triage.get("recommended_containment"),
            analyst_guidance=triage.get("analyst_guidance"),
            auto_containment_recommended=triage.get("auto_containment_recommended", False),
            status="TRIAGED"
        )
        session.add(record)
        session.commit()
        session.refresh(record)
        return record
    except Exception as e:
        session.rollback()
        logger.error(f"[!] Failed to save incident to DB: {e}")
        return None
    finally:
        session.close()


def get_recent_incidents(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve the most recent triaged incidents."""
    session = db_session()
    try:
        records = (
            session.query(IncidentRecord)
            .order_by(IncidentRecord.created_at.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "incident_uuid": r.incident_uuid,
                "source_ip": r.source_ip,
                "severity": r.severity,
                "confidence_score": r.confidence_score,
                "is_false_positive": r.is_false_positive,
                "mitre_technique_id": r.mitre_technique_id,
                "mitre_technique_name": r.mitre_technique_name,
                "attack_summary": r.attack_summary,
                "recommended_containment": r.recommended_containment,
                "status": r.status,
                "created_at": r.created_at.isoformat() if r.created_at else None
            }
            for r in records
        ]
    except Exception as e:
        logger.error(f"[!] Failed to query incidents: {e}")
        return []
    finally:
        session.close()


def update_incident_status(incident_uuid: str, status: str, action_log: str) -> bool:
    """Update incident status upon analyst containment or review."""
    session = db_session()
    try:
        record = session.query(IncidentRecord).filter_by(incident_uuid=incident_uuid).first()
        if not record:
            return False
        record.status = status
        record.action_audit_log = action_log
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        logger.error(f"[!] Failed to update incident status: {e}")
        return False
    finally:
        session.close()
