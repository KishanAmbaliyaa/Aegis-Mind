import hmac
import hashlib
import uuid
import logging
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pydantic import ValidationError

from config import settings
from models import AlertPayload, ContainmentActionRequest
from database import init_db, save_incident, get_recent_incidents, update_incident_status
from threat_intel import enrich_ip, ti_cache
from llm_analyzer import generate_triage_report
from notifier import send_notification

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
)
logger = logging.getLogger("AegisMind.Server")

# Initialize Flask Application
app = Flask(__name__)

# Initialize Rate Limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[settings.RATE_LIMIT_DEFAULT],
    storage_uri="memory://"
)

# Background Task Worker Pool for Asynchronous SOAR Processing
worker_pool = ThreadPoolExecutor(max_workers=10, thread_name_prefix="AegisWorker")


def verify_hmac_signature(raw_body: bytes, signature_header: str) -> bool:
    """Verifies HMAC-SHA256 signature for incoming SIEM webhook payloads."""
    if not settings.WEBHOOK_SECRET:
        return True  # If no secret configured, open simulation mode

    if not signature_header:
        return not settings.REQUIRE_HMAC

    try:
        # Expected header format: sha256=<hex> or raw hex
        expected_prefix = "sha256="
        received_hex = signature_header[len(expected_prefix):] if signature_header.startswith(expected_prefix) else signature_header

        computed_hmac = hmac.new(
            key=settings.WEBHOOK_SECRET.encode("utf-8"),
            msg=raw_body,
            digestmod=hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(computed_hmac, received_hex)
    except Exception as e:
        logger.error(f"[!] Error verifying HMAC signature: {e}")
        return False


def _process_alert_pipeline(incident_uuid: str, raw_alert_dict: dict):
    """
    Asynchronous SOAR Pipeline:
    1. Threat Intel Enrichment (with TTL Cache)
    2. LLM Triage & MITRE ATT&CK Mapping
    3. Persistence to Incident Database
    4. Notification Dispatch (Slack/Discord)
    """
    try:
        source_ip = raw_alert_dict.get("source_ip", "Unknown")
        rule_data = raw_alert_dict.get("rule") or {}
        rule_id = rule_data.get("id")
        rule_desc = rule_data.get("description")

        logger.info(f"[*] [Task {incident_uuid}] Starting pipeline for IP: {source_ip}")

        # 1. Threat Intel Enrichment
        intel_data = enrich_ip(source_ip)
        logger.info(f"[*] [Task {incident_uuid}] TI Enriched (cached={intel_data.get('cached')})")

        # 2. LLM Autonomous Triage
        triage_report = generate_triage_report(raw_alert_dict, intel_data)
        logger.info(f"[*] [Task {incident_uuid}] LLM Triage completed: {triage_report.severity.value}")

        # 3. Save to Incident Database
        triage_dict = triage_report.model_dump()
        save_incident(
            incident_uuid=incident_uuid,
            source_ip=source_ip,
            rule_id=rule_id,
            rule_description=rule_desc,
            intel_data=intel_data,
            triage=triage_dict
        )

        # 4. Dispatch Alert Notification
        send_notification(
            report=triage_report,
            incident_uuid=incident_uuid,
            source_ip=source_ip,
            intel_data=intel_data
        )

        logger.info(f"[+] [Task {incident_uuid}] Pipeline completed successfully.")

    except Exception as e:
        logger.exception(f"[!] [Task {incident_uuid}] Unhandled exception in triage pipeline: {e}")


# ==========================================
# REST API Endpoints
# ==========================================

@app.route("/healthz", methods=["GET"])
def health_check():
    """System health check and cache performance telemetry."""
    return jsonify({
        "status": "healthy",
        "service": "Aegis-Mind SOAR",
        "version": "2.0.0",
        "cache": {
            "entries_cached": len(ti_cache),
            "max_size": ti_cache.maxsize,
            "ttl_seconds": ti_cache.ttl
        }
    }), 200


@app.route("/api/alert", methods=["POST"])
@limiter.limit(settings.RATE_LIMIT_DEFAULT)
def receive_alert():
    """
    High-performance Ingestion Endpoint:
    - Validates HMAC signature
    - Validates payload against Pydantic schema
    - Spawns asynchronous worker task
    - Returns 202 Accepted immediately (<20ms)
    """
    raw_body = request.get_data()
    sig_header = request.headers.get("X-Aegis-Signature") or request.headers.get("X-Hub-Signature-256", "")

    # 1. HMAC Signature Verification
    if settings.REQUIRE_HMAC and not verify_hmac_signature(raw_body, sig_header):
        logger.warning(f"[!] Unauthorized webhook alert received from {request.remote_addr} (Invalid HMAC)")
        return jsonify({"error": "Invalid or missing HMAC signature"}), 401

    # 2. Payload Validation via Pydantic
    try:
        json_data = request.get_json(force=True, silent=False)
        validated_alert = AlertPayload.model_validate(json_data)
    except ValidationError as ve:
        logger.warning(f"[!] Malformed alert payload rejected: {ve.errors()}")
        return jsonify({"error": "Schema validation failed", "details": ve.errors()}), 400
    except Exception as e:
        return jsonify({"error": f"Invalid JSON payload: {str(e)}"}), 400

    incident_uuid = str(uuid.uuid4())

    # 3. Hand-off to background worker thread (non-blocking)
    worker_pool.submit(_process_alert_pipeline, incident_uuid, validated_alert.model_dump())

    # 4. Immediate acknowledgment
    return jsonify({
        "status": "accepted",
        "incident_uuid": incident_uuid,
        "message": "Alert queued for autonomous triage and threat intel enrichment"
    }), 202


@app.route("/api/incidents", methods=["GET"])
def list_incidents():
    """Retrieves recent triaged incidents from persistent storage."""
    limit = request.args.get("limit", default=25, type=int)
    incidents = get_recent_incidents(limit=min(limit, 100))
    return jsonify({
        "count": len(incidents),
        "incidents": incidents
    }), 200


@app.route("/api/action/contain", methods=["POST"])
def execute_containment():
    """
    Analyst Containment Action Endpoint (SOAR Execution):
    Allows analysts to trigger automated containment (e.g., Firewall IP block) or mark false positives.
    """
    try:
        req_data = request.get_json(force=True)
        action_req = ContainmentActionRequest.model_validate(req_data)
    except Exception as e:
        return jsonify({"error": f"Invalid containment request: {str(e)}"}), 400

    action = action_req.action.upper()
    valid_actions = ["BLOCK_IP", "ISOLATE_HOST", "FALSE_POSITIVE"]
    if action not in valid_actions:
        return jsonify({"error": f"Invalid action. Supported: {valid_actions}"}), 400

    # In production, this invokes Palo Alto, Fortinet, AWS WAF, or CrowdStrike API
    action_log = f"Action '{action}' executed by analyst. Notes: {action_req.analyst_notes}"
    success = update_incident_status(action_req.incident_uuid, status=action, action_log=action_log)

    if not success:
        return jsonify({"error": f"Incident {action_req.incident_uuid} not found"}), 404

    logger.info(f"[+] [SOAR Action] Incident {action_req.incident_uuid} marked as {action}")
    return jsonify({
        "status": "success",
        "incident_uuid": action_req.incident_uuid,
        "action": action,
        "message": f"Containment action {action} logged and applied successfully"
    }), 200


# Initialize Database on Module Load
init_db()

if __name__ == "__main__":
    logger.info(f"[*] Starting Aegis-Mind SOAR on {settings.HOST}:{settings.PORT} (Debug={settings.DEBUG})")
    app.run(host=settings.HOST, port=settings.PORT, debug=settings.DEBUG)
