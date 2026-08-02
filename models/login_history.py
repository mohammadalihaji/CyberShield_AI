from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base_model import BaseModel

class LoginHistory(BaseModel):
    """
    Login Audit History Model.
    """
    __tablename__ = "login_history"

    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    username_attempted: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    status: Mapped[str] = mapped_column(
        String(20),
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

    failure_reason: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True
    )

    login_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True
    )

    user = relationship("User", back_populates="login_history")

    def __repr__(self) -> str:
        return f"<LoginHistory(username='{self.username_attempted}', status='{self.status}')>"
