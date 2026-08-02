import os
from datetime import datetime, timedelta
import jwt

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "cybershield-jwt-secret-key-2026")

class JWTService:
    """
    JWT Token Management Service for stateless API and web session authentication.
    """

    @staticmethod
    def generate_token(user_id: int, username: str, email: str, expires_in_hours: int = 24) -> str:
        """
        Encodes a JWT bearer token containing user claims.
        """
        payload = {
            'sub': user_id,
            'username': username,
            'email': email,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=expires_in_hours)
        }
        return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    @staticmethod
    def decode_token(token: str) -> dict:
        """
        Decodes and verifies a JWT token. Returns payload dict or None.
        """
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
