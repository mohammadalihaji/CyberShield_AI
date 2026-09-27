import os
import json
import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, g
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Database and Services
import database
import gemini_service
from auth.password_service import PasswordService
from auth.jwt_service import JWTService
from auth.decorators import get_current_user
from repositories.user_repository import UserRepository
from ml.inference.website_analyzer import WebsiteSecurityAnalyzer

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'cybershield-secret-key-1337')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Set logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize DB tables on start
database.init_db()

@app.before_request
def load_logged_in_user():
    """
    Attaches current authenticated user to Flask g object for request context.
    """
    g.user = get_current_user()

# ==============================================================================
# Authentication Endpoints
# ==============================================================================

@app.route('/api/auth/register', methods=['POST'])
def register():
    """
    User Registration Endpoint.
    Stores new user entity in MySQL database.
    """
    try:
        data = request.get_json() or {}
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()

        if not username or not email or not password:
            return jsonify({"success": False, "error": "Username, email, and password are required."}), 400

        if len(password) < 6:
            return jsonify({"success": False, "error": "Password must be at least 6 characters long."}), 400

        # Check existing user
        existing_user = UserRepository.get_by_username_or_email(username) or UserRepository.get_by_username_or_email(email)
        if existing_user:
            return jsonify({"success": False, "error": "Username or email is already registered."}), 400

        # Create user record
        user = UserRepository.create_user(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name
        )

        # Set session and generate token
        session['user_id'] = user.id
        token = JWTService.generate_token(user.id, user.username, user.email)

        return jsonify({
            "success": True,
            "message": "Account created successfully.",
            "token": token,
            "user": {
                "id": user.id,
                "uuid": user.uuid,
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name
            }
        })

    except Exception as e:
        logger.error(f"Error during registration: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """
    User Login Endpoint.
    Validates password hash and logs audit entry.
    """
    try:
        data = request.get_json() or {}
        identifier = data.get('identifier', '').strip()
        password = data.get('password', '')

        if not identifier or not password:
            return jsonify({"success": False, "error": "Username/Email and password are required."}), 400

        user = UserRepository.get_by_username_or_email(identifier)
        ip_address = request.remote_addr

        if not user:
            UserRepository.record_login_attempt(identifier, 'FAILED', ip_address=ip_address, failure_reason="User not found")
            return jsonify({"success": False, "error": "Invalid username or password."}), 401

        if not PasswordService.verify_password(password, user.password_hash):
            UserRepository.record_login_attempt(identifier, 'FAILED', user_id=user.id, ip_address=ip_address, failure_reason="Invalid password")
            return jsonify({"success": False, "error": "Invalid username or password."}), 401

        # Successful Login
        UserRepository.update_last_login(user.id)
        UserRepository.record_login_attempt(identifier, 'SUCCESS', user_id=user.id, ip_address=ip_address)

        session['user_id'] = user.id
        token = JWTService.generate_token(user.id, user.username, user.email)

        return jsonify({
            "success": True,
            "message": "Logged in successfully.",
            "token": token,
            "user": {
                "id": user.id,
                "uuid": user.uuid,
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name
            }
        })

    except Exception as e:
        logger.error(f"Error during login: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """
    User Logout Endpoint.
    """
    session.pop('user_id', None)
    return jsonify({"success": True, "message": "Logged out successfully."})

@app.route('/api/auth/me', methods=['GET'])
def get_me():
    """
    Fetches active user details and session state.
    """
    user = g.user
    if not user:
        return jsonify({"success": False, "authenticated": False})
    
    return jsonify({
        "success": True,
        "authenticated": True,
        "user": {
            "id": user.id,
            "uuid": user.uuid,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name
        }
    })

# ==============================================================================
# Dashboard & Telemetry Endpoints
# ==============================================================================

@app.route('/')
def landing():
    """
    Landing Page. Renders the platform introduction with Sign In / Sign Up buttons.
    """
    user_id = g.user.id if g.user else None
    stats = database.get_dashboard_stats(user_id=user_id)
    return render_template('landing.html', stats=stats, current_user=g.user)

@app.route('/dashboard')
def dashboard():
    """
    Dashboard Main Page. Requires authentication. Renders threat telemetry dash.
    """
    if not g.user:
        return redirect(url_for('landing'))
    user_id = g.user.id
    stats = database.get_dashboard_stats(user_id=user_id)
    return render_template('index.html', stats=stats, current_user=g.user)

@app.route('/profile')
def profile():
    """
    User Profile Page. Requires authentication. Shows account details and stats.
    """
    if not g.user:
        return redirect(url_for('landing'))
    user_id = g.user.id
    stats = database.get_dashboard_stats(user_id=user_id)
    return render_template('profile.html', stats=stats, current_user=g.user)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """
    Exposes aggregate log metrics and charts indices.
    """
    try:
        user_id = g.user.id if g.user else None
        stats = database.get_dashboard_stats(user_id=user_id)
        return jsonify({"success": True, "stats": stats})
    except Exception as e:
        logger.error(f"Error compiling dashboard stats: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# ==============================================================================
# Security Audit Endpoints (Data Persisted to MySQL)
# ==============================================================================

@app.route('/api/check-website', methods=['POST'])
def check_website():
    """
    Website Security Checker.
    Executes ML-based static and multi-model analysis (URL + Page + DOM + Evidence).
    Persists result into database maintaining backward compatibility.
    """
    try:
        data = request.get_json() or {}
        url = data.get('url', '').strip()
        if not url:
            return jsonify({"success": False, "error": "URL parameter is missing or empty."}), 400
            
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        analyzer = WebsiteSecurityAnalyzer()
        result = analyzer.analyze(url)

        # Handle pre-training / unready model state
        if result.get("status") == "MODEL_NOT_READY":
            return jsonify({
                "success": False,
                "status": "MODEL_NOT_READY",
                "error": result.get("error"),
                "result": result
            }), 200

        if not result.get("success"):
            return jsonify({"success": False, "error": result.get("error", "Website analysis failed.")}), 400

        user_id = g.user.id if g.user else None

        # Save to DB
        scan_id = database.add_scan_record(
            scan_type='website',
            input_data=url,
            risk_level=result.get('risk_level', 'Suspicious'),
            result_json={
                'phishing_score': result.get('phishing_score', 0),
                'trusted_probability': result.get('trusted_probability', 0.0),
                'phishing_probability': result.get('phishing_probability', 0.0),
                'ssl_valid': result.get('ssl_valid', False),
                'malware_found': result.get('malware_found', False),
                'domain_age': result.get('domain_age'),
                'reputation': result.get('reputation'),
                'page_analysis_available': result.get('page_analysis_available', False),
                'url_analysis': result.get('url_analysis', {}),
                'page_analysis': result.get('page_analysis', {}),
                'form_analysis': result.get('form_analysis', {}),
                'script_analysis': result.get('script_analysis', {}),
                'redirect_analysis': result.get('redirect_analysis', {}),
                'download_analysis': result.get('download_analysis', {}),
                'security_indicators': result.get('security_indicators', {}),
                'model_version': result.get('model_version', '')
            },
            raw_detail=result.get('explanation_markdown', ''),
            user_id=user_id
        )
        
        result['scan_id'] = scan_id
        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"Error checking website: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/check-image', methods=['POST'])
def check_image():
    """
    Image Authenticity & Deepfake Forensic Inspection.
    """
    try:
        if 'image' not in request.files:
            return jsonify({"success": False, "error": "No image file provided."}), 400
            
        file = request.files['image']
        if file.filename == '':
            return jsonify({"success": False, "error": "No file selected."}), 400
            
        filename = secure_filename(file.filename) or "uploaded_image.png"
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)
        
        result = gemini_service.analyze_image(save_path)
        user_id = g.user.id if g.user else None

        scan_id = database.add_scan_record(
            scan_type='image',
            input_data=filename,
            risk_level=result.get('risk_level', 'Suspicious'),
            result_json={
                'ai_confidence': result.get('ai_confidence', 50.0),
                'ai_probability': result.get('ai_probability', 0),
                'fingerprints': result.get('fingerprints', 'Unknown'),
                'jpeg_artifacts': result.get('jpeg_artifacts', 'Unknown'),
                'ela_score': result.get('ela_score', 0.0),
                'noise_score': result.get('noise_score', ''),
                'lighting_consistency': result.get('lighting_consistency', ''),
                'metadata_status': result.get('metadata_status', ''),
                'organic_texture': result.get('organic_texture', ''),
                'gan_artifacts': result.get('gan_artifacts', ''),
                'compression_analysis': result.get('compression_analysis', ''),
                'pixel_irregularity': result.get('pixel_irregularity', ''),
                'resolution': result.get('resolution', '')
            },
            raw_detail=result.get('explanation_markdown', ''),
            user_id=user_id
        )
        
        result['scan_id'] = scan_id
        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"Error verifying image: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# ==============================================================================
# Email Security Analyzer (Local Multi-Modal ML Engine)
# ==============================================================================

from ml.email.analyzer import EmailSecurityAnalyzer

@app.route('/api/check-email', methods=['POST'])
@app.route('/api/email/scan', methods=['POST'])
def check_email():
    """
    Email Phishing & Spam Inspection Endpoint.
    Uses local Multi-Modal ML Engine (Transformer Embeddings + Structured Features + URL Security Model + OOF Stacking + Calibration).
    Accepts:
      - Multipart file upload: .eml file in request.files['eml_file'] or request.files['file']
      - JSON body: {"sender": "...", "body": "...", "subject": "..."}
      - Form data: sender, body, subject
    """
    try:
        analyzer = EmailSecurityAnalyzer()
        user_id = g.user.id if g.user else None

        # Check for uploaded .eml file
        uploaded_file = request.files.get('eml_file') or request.files.get('file')
        if uploaded_file and uploaded_file.filename:
            filename = secure_filename(uploaded_file.filename)
            raw_bytes = uploaded_file.read()
            if len(raw_bytes) > app.config['MAX_CONTENT_LENGTH']:
                return jsonify({"success": False, "error": "Email file exceeds 16MB limit."}), 400
            
            result = analyzer.analyze_eml_bytes(raw_bytes)
            sender_display = result.get("meta", {}).get("sender") or filename
        else:
            # Check JSON or Form data
            data = request.get_json(silent=True) or request.form or {}
            sender = data.get('sender', '').strip()
            body = data.get('body', '').strip()
            subject = data.get('subject', '').strip()

            if not sender and not body:
                return jsonify({"success": False, "error": "Please provide an email sender and body or upload a .eml file."}), 400

            result = analyzer.analyze_pasted(sender=sender, body_or_headers=body, subject=subject)
            sender_display = sender or "pasted_email"

        if not result.get("success"):
            return jsonify({"success": False, "error": result.get("error", "Email analysis failed.")}), 400

        # Persist to database with comprehensive telemetry
        url_metrics = result.get('url_metrics', {})
        meta = result.get('meta', {})
        scan_id = database.add_scan_record(
            scan_type='email',
            input_data=sender_display,
            risk_level=result.get('verdict', 'Suspicious'),
            result_json={
                'body_snippet': meta.get('subject', '')[:200] or sender_display[:200],
                'phishing_score': int(result.get('risk_score', 50)),
                'calibrated_probability': result.get('calibrated_probability', 0.5),
                'classification': result.get('classification', 'uncertain'),
                'model_signals': result.get('model_signals', {}),
                'evidence': result.get('evidence', []),
                'meta': meta,
                'url_metrics': url_metrics,
                'classified_urls': result.get('classified_urls', []),
                'unique_clickable_hrefs': url_metrics.get('unique_clickable_hrefs', meta.get('url_count', 0)),
                'suspicious_links': url_metrics.get('suspicious_urls', 0),
                'malicious_links': url_metrics.get('malicious_urls', 0),
                'attachment_count': meta.get('attachment_count', 0),
                'spf_check': meta.get('spf', 'none'),
                'dkim_check': meta.get('dkim', 'none'),
                'dmarc_check': meta.get('dmarc', 'none'),
                'model_version': result.get('model_version', '')
            },
            raw_detail=result.get('explanation_markdown', ''),
            user_id=user_id
        )

        result['scan_id'] = scan_id
        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"Error checking email: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/email/scan/<int:scan_id>', methods=['GET'])
def get_email_scan(scan_id):
    """Retrieves JSON scan telemetry for an email scan record."""
    report = database.get_scan_by_id(scan_id, scan_type='email')
    if not report:
        return jsonify({"success": False, "error": "Scan record not found."}), 404
    return jsonify({"success": True, "scan": report})

@app.route('/api/email/report/<int:scan_id>', methods=['GET'])
def get_email_report(scan_id):
    """Renders printable security audit report for an email scan."""
    report = database.get_scan_by_id(scan_id, scan_type='email')
    if not report:
        return "Email scan report not found.", 404
    return render_template('report.html', report=report)

@app.route('/api/email/url-debug', methods=['POST'])
def email_url_debug():
    """
    Diagnostic endpoint: Runs ONLY the URL classification pipeline on the submitted email.
    Returns full per-URL forensics (category, CompPhish raw score, contextual risk, reason).
    Does NOT run the full ML inference pipeline.
    """
    try:
        from ml.email.parser import parse_raw_eml, parse_pasted_email
        from ml.email.url_aggregator import EmailURLAggregator
        from ml.email.url_classifier import normalize_url, classify_single_url, detect_brand_impersonation, compute_contextual_url_risk
        from ml.email.domain_analyzer import get_organizational_domain
        from ml.features.url_features import extract_url_features
        from ml.models.model_registry import ModelRegistry

        # Accept file upload or JSON/form
        uploaded_file = request.files.get('eml_file') or request.files.get('file')
        if uploaded_file and uploaded_file.filename:
            raw_bytes = uploaded_file.read()
            record = parse_raw_eml(raw_bytes)
        else:
            data = request.get_json(silent=True) or request.form or {}
            sender = data.get('sender', '').strip()
            body = data.get('body', '').strip()
            subject = data.get('subject', '').strip()
            if not sender and not body:
                return jsonify({"success": False, "error": "Provide sender+body or upload .eml"}), 400
            record = parse_pasted_email(sender=sender, body_or_headers=body, subject=subject)

        sender_domain = (record.from_domain or '').lower()
        sender_org = get_organizational_domain(sender_domain)
        aggregation = EmailURLAggregator().analyze_urls(record)
        metrics = aggregation["url_metrics"]
        url_forensics = []
        for item in aggregation["classified_urls"]:
            brand_check = item.get("brand_check", {})
            destination_features = item.get("destination_features", {})
            url_forensics.append({
                "original_urls": item.get("original_urls", [item.get("url", "")]),
                "occurrence_count": item.get("occurrence_count", 1),
                "normalized_url": item.get("url", ""),
                "wrapper_domain": item.get("org_domain", ""),
                "decoded_destination": item.get("destination_url", ""),
                "destination_domain": item.get("destination_domain", ""),
                "category": item.get("category", "DIRECT"),
                "is_tracking": item.get("is_tracking", False),
                "is_social": item.get("is_social", False),
                "is_unsubscribe": item.get("is_unsubscribe", False),
                "is_cdn_asset": item.get("is_cdn_asset", False),
                "brand_detected": brand_check.get("brand") or None,
                "brand_domain_relationship": "IMPERSONATION" if brand_check.get("is_impersonation") else "NO_BRAND_IMPERSONATION",
                "wrapper_risk": item.get("wrapper_risk", 0.0),
                "destination_risk": item.get("destination_risk", 0.0),
                "compphish_probability": item.get("raw_url_model_risk", 0.0),
                "destination_features": destination_features,
                "final_url_verdict": item.get("final_classification", "SAFE"),
                "reason": item.get("contextual_reason", ""),
            })

        malicious = [u for u in url_forensics if u["final_url_verdict"] == "MALICIOUS"]
        suspicious = [u for u in url_forensics if u["final_url_verdict"] == "SUSPICIOUS"]
        safe = [u for u in url_forensics if u["final_url_verdict"] == "SAFE"]

        return jsonify({
            "success": True,
            "sender_domain": sender_domain,
            "sender_org": sender_org,
            "metrics": metrics,
            "summary": {
                "malicious": len(malicious),
                "suspicious": len(suspicious),
                "safe": len(safe),
                "highest_individual_url_model_score": metrics.get("max_raw_url_model_score", 0.0),
                "max_contextual_risk": max((
                    item.get("contextual_risk", 0.0) for item in aggregation["classified_urls"]
                ), default=0.0),
            },
            "malicious_urls": malicious,
            "suspicious_urls": suspicious,
            "all_urls": url_forensics,
        })
    except Exception as e:
        logger.error(f"URL debug error: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/check-password', methods=['POST'])
def check_password():
    """
    Password Strength Audit Endpoint.
    Delegates entirely to the Gemini AI service for strength analysis.
    """
    try:
        data = request.get_json() or {}
        password = data.get('password', '')

        if not password:
            return jsonify({"success": False, "error": "Password input is empty."}), 400

        # Gemini AI performs the full password analysis (no rule-based logic).
        result = gemini_service.analyze_password(password)

        risk = result.get('risk_level', 'Suspicious')
        entropy = result.get('entropy', 0)
        pwned_count = result.get('pwned_count', 0)
        explanation = result.get('explanation_markdown', '')
        recommendations = result.get('recommendations', [])

        hashed_display = "*" * min(len(password), 12)
        user_id = g.user.id if g.user else None

        scan_id = database.add_scan_record(
            scan_type='password',
            input_data=hashed_display,
            risk_level=risk,
            result_json={
                'entropy': entropy,
                'pwned_count': pwned_count,
                'has_uppercase': result.get('has_uppercase', False),
                'has_lowercase': result.get('has_lowercase', False),
                'has_digit': result.get('has_digit', False),
                'has_special': result.get('has_special', False),
                'dictionary_risk': result.get('dictionary_risk', 'Not Assessed'),
                'pattern_detection': result.get('pattern_detection', 'None Detected'),
                'estimated_crack_time': result.get('estimated_crack_time', 'N/A')
            },
            raw_detail=explanation + "\n\n**Action Steps:**\n" + "\n".join(f"* {r}" for r in recommendations),
            user_id=user_id
        )

        # Return full result with all XAI fields
        result['scan_id'] = scan_id
        return jsonify({
            "success": True,
            "result": result
        })
    except Exception as e:
        logger.error(f"Error checking password: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/get-advice', methods=['POST'])
def get_advice():
    """
    Security Posture Audit Endpoint.
    """
    try:
        profile = request.get_json() or {}
        result = gemini_service.get_security_advice(profile)
        user_id = g.user.id if g.user else None

        score = result.get('overall_score', 100)
        risk = 'Safe' if score >= 80 else ('Suspicious' if score >= 50 else 'Malicious')

        scan_id = database.add_scan_record(
            scan_type='profile',
            input_data='Personal Exposure Questionnaire Audit',
            risk_level=risk,
            result_json={
                'overall_score': score,
                'recommendation_count': len(result.get('recommendations', []))
            },
            raw_detail=result.get('general_advisor_markdown', ''),
            user_id=user_id
        )
        
        result['scan_id'] = scan_id
        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"Error processing posture profile: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/chat', methods=['POST'])
def chat():
    """
    AI Security Assistant Chat Endpoint.
    Saves message history into MySQL database.
    """
    try:
        data = request.get_json() or {}
        message = data.get('message', '').strip()
        history = data.get('history', [])
        
        if not message:
            return jsonify({"success": False, "error": "Message content is empty."}), 400
            
        reply = gemini_service.process_chat_message(message, history)
        user_id = g.user.id if g.user else None
        session_id = session.get('session_id', 'guest-chat-session')

        # Persist conversation to DB
        with database.get_db_session() as db_sess:
            user_msg = database.models.ChatMessage(
                user_id=user_id,
                session_id=session_id,
                sender='user',
                message=message
            )
            bot_msg = database.models.ChatMessage(
                user_id=user_id,
                session_id=session_id,
                sender='model',
                message=reply
            )
            db_sess.add(user_msg)
            db_sess.add(bot_msg)

        return jsonify({"success": True, "reply": reply})
    except Exception as e:
        logger.error(f"Error during AI Chat: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/reports/<int:scan_id>', methods=['GET'])
def get_report(scan_id):
    """
    Renders detailed security report template for individual audit elements.
    """
    scan_type = request.args.get('type')
    report = database.get_scan_by_id(scan_id, scan_type=scan_type)
    if not report:
        return "Report not found.", 404

    return render_template('report.html', report=report)

@app.route('/api/clear-history', methods=['POST'])
def clear_history():
    """
    Clears recorded audit history for the active user session.
    """
    try:
        user_id = g.user.id if g.user else None
        database.clear_db_history(user_id=user_id)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    database.init_db()
    logger.info("Starting CyberShield AI Server on Port 5000...")

    # use_reloader=False prevents the Werkzeug watchdog from restarting the
    # server when SentenceTransformer / PyTorch lazy-compiles .pyc files in
    # site-packages.  Without this, every first email scan triggers a reload
    # that kills the server mid-request, causing alternating "Failed to fetch"
    # errors.  Debug error pages still work; you just restart manually after
    # code changes.
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
