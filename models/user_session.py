from datetime import datetime
from typing import Optional
from sqlalchemy import String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base_model import BaseModel

class UserSession(BaseModel):
    """
    User Session Tracking Model.
    """
    __tablename__ = "user_sessions"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    session_token: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )

    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True
    )

    user_agent: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False
    )

    user = relationship("User", back_populates="sessions")

    def __repr__(self) -> str:
        return f"<UserSession(user_id={self.user_id}, active={self.is_active})>"
