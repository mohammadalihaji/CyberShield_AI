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
    Website Security Checker. Performs threat scan and persists result into database.
    """
    try:
        data = request.get_json() or {}
        url = data.get('url', '').strip()
        if not url:
            return jsonify({"success": False, "error": "URL parameter is missing or empty."}), 400
            
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        result = gemini_service.analyze_website(url)
        user_id = g.user.id if g.user else None

        # Save to DB
        scan_id = database.add_scan_record(
            scan_type='website',
            input_data=url,
            risk_level=result.get('risk_level', 'Suspicious'),
            result_json={
                'phishing_score': result.get('phishing_score', 50),
                'ssl_valid': result.get('ssl_valid', False),
                'malware_found': result.get('malware_found', False),
                'domain_age': result.get('domain_age', 'Unknown'),
                'reputation': result.get('reputation', 'Neutral')
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

@app.route('/api/check-email', methods=['POST'])
def check_email():
    """
    Email Phishing Inspection Endpoint.
    """
    try:
        data = request.get_json() or {}
        sender = data.get('sender', '').strip()
        body = data.get('body', '').strip()
        
        if not sender or not body:
            return jsonify({"success": False, "error": "Both sender and email body must be provided."}), 400
            
        result = gemini_service.analyze_email(sender, body)
        user_id = g.user.id if g.user else None

        scan_id = database.add_scan_record(
            scan_type='email',
            input_data=sender,
            risk_level=result.get('risk_level', 'Suspicious'),
            result_json={
                'body_snippet': body[:200],
                'phishing_score': result.get('phishing_score', 50),
                'urgency': result.get('urgency', 'Medium'),
                'suspicious_links': result.get('suspicious_links', 0),
                'spoofed_domain': result.get('spoofed_domain', False),
                'spf_check': result.get('spf_check', 'Neutral'),
                'dkim_check': result.get('dkim_check', 'Not Available'),
                'dmarc_check': result.get('dmarc_check', 'Not Available'),
                'social_engineering': result.get('social_engineering', 'Not Assessed')
            },
            raw_detail=result.get('explanation_markdown', ''),
            user_id=user_id
        )
        
        result['scan_id'] = scan_id
        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"Error checking email: {e}")
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
    app.run(debug=True, host='0.0.0.0', port=5000)
