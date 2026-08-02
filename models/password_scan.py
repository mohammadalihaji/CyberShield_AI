from typing import Optional, Dict, Any
from sqlalchemy import String, Text, Integer, Float, Boolean, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base_model import BaseModel

class PasswordScan(BaseModel):
    """
    Password Strength & Breach Audit Model.
    Tracks masked password indicator, entropy score, pwned breaches, character criteria, recommendations, and AI advice.
    """
    __tablename__ = "password_scans"

    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    masked_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )

    risk_level: Mapped[str] = mapped_column(
        String(20),
        default="Medium",
        nullable=False,
        index=True
    )

    entropy: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False
    )

    pwned_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False
    )

    has_uppercase: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )

    has_lowercase: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )

    has_digit: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )

    has_special: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )

    explanation_markdown: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True
    )

    recommendations_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True
    )

    result_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True
    )

    user = relationship("User", back_populates="password_scans")

    def __repr__(self) -> str:
        return f"<PasswordScan(entropy={self.entropy}, risk='{self.risk_level}')>"
