import json
import logging
from datetime import datetime
from sqlalchemy import desc, func

from database.base import Base
from database.connection import engine, SessionLocal, get_db_session, init_db
import models

logger = logging.getLogger(__name__)

def add_scan_record(scan_type: str, input_data: str, risk_level: str, result_json: dict = None, raw_detail: str = "", user_id: int = None):
    """
    Persists scan records to the corresponding MySQL table according to scan_type,
    associated with user_id if provided.
    ACID compliant via get_db_session context manager.
    """
    result_json = result_json or {}
    scan_id = None

    with get_db_session() as session:
        if scan_type == 'website':
            rec = models.WebsiteScan(
                user_id=user_id,
                url=input_data,
                domain=input_data.replace('http://', '').replace('https://', '').split('/')[0],
                risk_level=risk_level,
                phishing_score=result_json.get('phishing_score', 50),
                ssl_valid=result_json.get('ssl_valid', False),
                malware_found=result_json.get('malware_found', False),
                domain_age=result_json.get('domain_age', 'Unknown'),
                reputation=result_json.get('reputation', 'Neutral'),
                explanation_markdown=raw_detail,
                result_json=result_json
            )
            session.add(rec)
            session.flush()
            scan_id = rec.id

        elif scan_type == 'email':
            rec = models.EmailScan(
                user_id=user_id,
                sender=input_data,
                body_snippet=result_json.get('body_snippet', input_data),
                risk_level=risk_level,
                phishing_score=result_json.get('phishing_score', 50),
                urgency=result_json.get('urgency', 'Medium'),
                suspicious_links=result_json.get('suspicious_links', 0),
                spoofed_domain=result_json.get('spoofed_domain', False),
                spf_check=result_json.get('spf_check', 'Neutral'),
                explanation_markdown=raw_detail,
                result_json=result_json
            )
            session.add(rec)
            session.flush()
            scan_id = rec.id

        elif scan_type == 'image':
            rec = models.ImageScan(
                user_id=user_id,
                filename=input_data,
                risk_level=risk_level,
                ai_confidence=float(result_json.get('ai_confidence', 50.0)),
                fingerprints=result_json.get('fingerprints', 'Unknown'),
                jpeg_artifacts=result_json.get('jpeg_artifacts', 'Unknown'),
                explanation_markdown=raw_detail,
                result_json=result_json
            )
            session.add(rec)
            session.flush()
            scan_id = rec.id

        elif scan_type == 'password':
            rec = models.PasswordScan(
                user_id=user_id,
                masked_password=input_data,
                risk_level=risk_level,
                entropy=float(result_json.get('entropy', 0.0)),
                pwned_count=result_json.get('pwned_count', 0),
                has_uppercase=result_json.get('has_uppercase', False),
                has_lowercase=result_json.get('has_lowercase', False),
                has_digit=result_json.get('has_digit', False),
                has_special=result_json.get('has_special', False),
                explanation_markdown=raw_detail,
                result_json=result_json
            )
            session.add(rec)
            session.flush()
            scan_id = rec.id

        elif scan_type == 'profile':
            rec = models.SecurityAudit(
                user_id=user_id,
                overall_score=result_json.get('overall_score', 100),
                risk_level=risk_level,
                questionnaire_json=result_json,
                advisor_markdown=raw_detail
            )
            session.add(rec)
            session.flush()
            scan_id = rec.id

        # Also store printable report entry
        report = models.AIReport(
            user_id=user_id,
            scan_type=scan_type,
            scan_id=scan_id,
            title=f"CyberShield Security Report: {scan_type.upper()} audit ({risk_level})",
            summary=f"Audit scan executed for target '{input_data}' resulting in classification {risk_level}.",
            report_content=raw_detail,
            risk_level=risk_level
        )
        session.add(report)

    return scan_id

def get_dashboard_stats(user_id: int = None) -> dict:
    """
    Computes dashboard telemetry metrics and compiles the recent scanning audit history.
    """
    with get_db_session() as session:
        # Collect counts across tables
        w_query = session.query(models.WebsiteScan)
        e_query = session.query(models.EmailScan)
        i_query = session.query(models.ImageScan)
        p_query = session.query(models.PasswordScan)
        s_query = session.query(models.SecurityAudit)

        if user_id:
            w_query = w_query.filter_by(user_id=user_id)
            e_query = e_query.filter_by(user_id=user_id)
            i_query = i_query.filter_by(user_id=user_id)
            p_query = p_query.filter_by(user_id=user_id)
            s_query = s_query.filter_by(user_id=user_id)

        w_scans = w_query.all()
        e_scans = e_query.all()
        i_scans = i_query.all()
        p_scans = p_query.all()
        s_audits = s_query.all()

        total_scans = len(w_scans) + len(e_scans) + len(i_scans) + len(p_scans) + len(s_audits)

        # Categorize risk counts
        all_items = []
        for item in w_scans:
            all_items.append({
                'id': item.id,
                'scan_type': 'website',
                'input_data': item.domain or item.url,
                'risk_level': item.risk_level,
                'created_at': item.created_at,
                'raw_detail': item.explanation_markdown
            })
        for item in e_scans:
            all_items.append({
                'id': item.id,
                'scan_type': 'email',
                'input_data': item.sender,
                'risk_level': item.risk_level,
                'created_at': item.created_at,
                'raw_detail': item.explanation_markdown
            })
        for item in i_scans:
            all_items.append({
                'id': item.id,
                'scan_type': 'image',
                'input_data': item.filename,
                'risk_level': item.risk_level,
                'created_at': item.created_at,
                'raw_detail': item.explanation_markdown
            })
        for item in p_scans:
            all_items.append({
                'id': item.id,
                'scan_type': 'password',
                'input_data': item.masked_password,
                'risk_level': item.risk_level,
                'created_at': item.created_at,
                'raw_detail': item.explanation_markdown
            })
        for item in s_audits:
            all_items.append({
                'id': item.id,
                'scan_type': 'profile',
                'input_data': item.title,
                'risk_level': item.risk_level,
                'created_at': item.created_at,
                'raw_detail': item.advisor_markdown
            })

        # Sort combined scans by timestamp descending
        all_items.sort(key=lambda x: x['created_at'], reverse=True)

        safe_count = sum(1 for item in all_items if item['risk_level'].lower() in ['safe', 'strong', 'clean'])
        suspicious_count = sum(1 for item in all_items if item['risk_level'].lower() in ['suspicious', 'medium', 'vulnerable'])
        malicious_count = sum(1 for item in all_items if item['risk_level'].lower() in ['malicious', 'weak', 'critical'])

        threats_blocked = suspicious_count + malicious_count

        # Compute integrity index / security score
        if total_scans == 0:
            security_score = 98
        else:
            security_score = max(10, min(100, int(100 - (malicious_count * 15 + suspicious_count * 5))))

        recent_scans = []
        for item in all_items[:15]:
            recent_scans.append({
                'id': item['id'],
                'scan_type': item['scan_type'],
                'input_data': item['input_data'],
                'risk_level': item['risk_level'],
                'timestamp': item['created_at'].strftime("%Y-%m-%d %H:%M:%S")
            })

        return {
            'total_scans': total_scans,
            'threats_blocked': threats_blocked,
            'security_score': security_score,
            'safe_count': safe_count,
            'suspicious_count': suspicious_count,
            'malicious_count': malicious_count,
            'scan_types': {
                'website': len(w_scans),
                'email': len(e_scans),
                'image': len(i_scans),
                'password': len(p_scans),
                'profile': len(s_audits)
            },
            'recent_scans': recent_scans
        }

def get_scan_by_id(scan_id: int, scan_type: str = None) -> dict:
    """
    Retrieves printable report details for a specific report or scan ID.

    Resolves the AIReport entry by its linked scan_id (preferred) or by its
    own id (fallback), then joins the underlying scan table so the returned
    dictionary contains every field the printable report template needs:
    input_data, result_json, raw_detail, timestamp, scan_type, risk_level.

    Args:
        scan_id: The report id OR the underlying scan record id.
        scan_type: Optional scan_type used to disambiguate when multiple
            AIReport entries share the same numeric scan id.

    Returns:
        A dictionary of report details, or None if not found.
    """
    with get_db_session() as session:
        # Prefer exact scan_id match; use scan_type to disambiguate if given.
        query = session.query(models.AIReport).filter(models.AIReport.scan_id == scan_id)
        if scan_type:
            query = query.filter(models.AIReport.scan_type == scan_type)
        report = query.first()

        if report is None:
            report = session.query(models.AIReport).filter(models.AIReport.id == scan_id).first()
        if report is None:
            return None

        scan_type = report.scan_type or ""
        linked_scan_id = report.scan_id or report.id

        input_data = report.title or ""
        result_json: dict = {}
        raw_detail = report.report_content or ""
        timestamp = report.created_at.strftime("%Y-%m-%d %H:%M:%S")

        # ---- Join the underlying scan record for full report data ----
        if scan_type == 'website':
            rec = session.query(models.WebsiteScan).filter_by(id=linked_scan_id).first()
            if rec:
                input_data = rec.url or rec.domain or input_data
                result_json = rec.result_json or {}
                raw_detail = rec.explanation_markdown or raw_detail
                timestamp = rec.created_at.strftime("%Y-%m-%d %H:%M:%S")
        elif scan_type == 'email':
            rec = session.query(models.EmailScan).filter_by(id=linked_scan_id).first()
            if rec:
                input_data = rec.sender or input_data
                result_json = rec.result_json or {}
                raw_detail = rec.explanation_markdown or raw_detail
                timestamp = rec.created_at.strftime("%Y-%m-%d %H:%M:%S")
        elif scan_type == 'image':
            rec = session.query(models.ImageScan).filter_by(id=linked_scan_id).first()
            if rec:
                input_data = rec.filename or input_data
                result_json = rec.result_json or {}
                raw_detail = rec.explanation_markdown or raw_detail
                timestamp = rec.created_at.strftime("%Y-%m-%d %H:%M:%S")
        elif scan_type == 'password':
            rec = session.query(models.PasswordScan).filter_by(id=linked_scan_id).first()
            if rec:
                input_data = rec.masked_password or input_data
                result_json = rec.result_json or {}
                raw_detail = rec.explanation_markdown or raw_detail
                timestamp = rec.created_at.strftime("%Y-%m-%d %H:%M:%S")
        elif scan_type == 'profile':
            rec = session.query(models.SecurityAudit).filter_by(id=linked_scan_id).first()
            if rec:
                input_data = rec.title or input_data
                result_json = rec.questionnaire_json or {}
                raw_detail = rec.advisor_markdown or raw_detail
                timestamp = rec.created_at.strftime("%Y-%m-%d %H:%M:%S")

        return {
            'id': report.id,
            'scan_id': linked_scan_id,
            'scan_type': scan_type,
            'title': report.title,
            'summary': report.summary,
            'risk_level': report.risk_level,
            'input_data': input_data,
            'result_json': result_json,
            'raw_detail': raw_detail,
            'explanation_markdown': raw_detail,
            'timestamp': timestamp,
            'created_at': timestamp
        }

def clear_db_history(user_id: int = None):
    """
    Clears recorded audit scans in a single transaction.
    """
    with get_db_session() as session:
        if user_id:
            session.query(models.WebsiteScan).filter_by(user_id=user_id).delete()
            session.query(models.EmailScan).filter_by(user_id=user_id).delete()
            session.query(models.ImageScan).filter_by(user_id=user_id).delete()
            session.query(models.PasswordScan).filter_by(user_id=user_id).delete()
            session.query(models.SecurityAudit).filter_by(user_id=user_id).delete()
            session.query(models.AIReport).filter_by(user_id=user_id).delete()
        else:
            session.query(models.WebsiteScan).delete()
            session.query(models.EmailScan).delete()
            session.query(models.ImageScan).delete()
            session.query(models.PasswordScan).delete()
            session.query(models.SecurityAudit).delete()
            session.query(models.AIReport).delete()

__all__ = [
    "Base",
    "engine",
    "SessionLocal",
    "get_db_session",
    "init_db",
    "add_scan_record",
    "get_dashboard_stats",
    "get_scan_by_id",
    "clear_db_history"
]