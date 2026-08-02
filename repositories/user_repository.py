from typing import Optional, List
from datetime import datetime
from database import get_db_session
import models
from auth.password_service import PasswordService

class UserRepository:
    """
    Data Repository for User entities & authentication tracking.
    """

    @staticmethod
    def create_user(username: str, email: str, password: str, first_name: str = None, last_name: str = None) -> models.User:
        """
        Creates and persists a new user with hashed password.
        """
        hashed = PasswordService.hash_password(password)
        with get_db_session() as session:
            user = models.User(
                username=username.strip(),
                email=email.strip().lower(),
                password_hash=hashed,
                first_name=first_name,
                last_name=last_name
            )
            session.add(user)
            session.flush()
            user_id = user.id

        with get_db_session() as session:
            return session.query(models.User).filter_by(id=user_id).first()

    @staticmethod
    def get_by_id(user_id: int) -> Optional[models.User]:
        with get_db_session() as session:
            return session.query(models.User).filter_by(id=user_id).first()

    @staticmethod
    def get_by_username_or_email(identifier: str) -> Optional[models.User]:
        clean_id = identifier.strip().lower()
        with get_db_session() as session:
            return session.query(models.User).filter(
                (models.User.username == clean_id) | (models.User.email == clean_id)
            ).first()

    @staticmethod
    def update_last_login(user_id: int):
        with get_db_session() as session:
            user = session.query(models.User).filter_by(id=user_id).first()
            if user:
                user.last_login_at = datetime.utcnow()
                user.failed_login_attempts = 0

    @staticmethod
    def record_login_attempt(username_attempted: str, status: str, user_id: int = None, ip_address: str = None, failure_reason: str = None):
        with get_db_session() as session:
            log = models.LoginHistory(
                user_id=user_id,
                username_attempted=username_attempted,
                status=status,
                ip_address=ip_address,
                failure_reason=failure_reason
            )
            session.add(log)
