from werkzeug.security import generate_password_hash, check_password_hash

class PasswordService:
    """
    Handles secure password hashing and verification.
    """
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hashes password using PBKDF2 / Scrypt via Werkzeug.
        """
        return generate_password_hash(password, method='scrypt')

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """
        Verifies plaintext password against stored hash.
        """
        if not password or not password_hash:
            return False
        return check_password_hash(password_hash, password)
