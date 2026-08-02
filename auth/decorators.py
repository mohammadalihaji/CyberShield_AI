from functools import wraps
from flask import request, jsonify, session, g
from auth.jwt_service import JWTService
from database import get_db_session
import models

def get_current_user():
    """
    Extracts the authenticated User object from Flask session or Authorization Bearer header.
    Returns User model instance or None.
    """
    # 1. Check Flask session user_id
    user_id = session.get('user_id')
    
    # 2. Check Authorization Header if session is empty
    if not user_id:
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            payload = JWTService.decode_token(token)
            if payload:
                user_id = payload.get('sub')
                
    if user_id:
        with get_db_session() as db_session:
            user = db_session.query(models.User).filter_by(id=user_id).first()
            if user:
                return user
    return None

def login_required(f):
    """
    Decorator to restrict access to authenticated users.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"success": False, "error": "Authentication required. Please log in."}), 401
        g.current_user = user
        return f(*args, **kwargs)
    return decorated_function
