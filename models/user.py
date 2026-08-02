from datetime import datetime

from sqlalchemy import Boolean
from sqlalchemy import DateTime
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from models.base_model import BaseModel


class User(BaseModel):
    """
    User model.

    Stores user account information and acts as the parent entity
    for all scans, reports, sessions, notifications, and audit logs.
    """

    __tablename__ = "users"

    # ------------------------------------------------------------------
    # Basic Information
    # ------------------------------------------------------------------

    username: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    first_name: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    last_name: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    phone_number: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )

    profile_image: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    # ------------------------------------------------------------------
    # Account Status
    # ------------------------------------------------------------------

    email_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    failed_login_attempts: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    account_locked_until: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    last_password_change: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------

    user_roles = relationship(
        "UserRole",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    website_scans = relationship(
        "WebsiteScan",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    email_scans = relationship(
        "EmailScan",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    image_scans = relationship(
        "ImageScan",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    password_scans = relationship(
        "PasswordScan",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    reports = relationship(
        "AIReport",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    security_audits = relationship(
        "SecurityAudit",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    chat_messages = relationship(
        "ChatMessage",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    sessions = relationship(
        "UserSession",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    refresh_tokens = relationship(
        "RefreshToken",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    login_history = relationship(
        "LoginHistory",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    notifications = relationship(
        "Notification",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    audit_logs = relationship(
        "AuditLog",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    # ------------------------------------------------------------------
    # Utility Methods
    # ------------------------------------------------------------------

    @property
    def full_name(self) -> str:
        """
        Returns the user's full name.
        """
        return f"{self.first_name or ''} {self.last_name or ''}".strip()

    def __repr__(self) -> str:
        return (
            f"<User("
            f"id={self.id}, "
            f"username='{self.username}', "
            f"email='{self.email}')>"
        )