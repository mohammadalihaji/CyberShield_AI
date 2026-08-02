from typing import Optional, Dict, Any
from sqlalchemy import String, Text, Integer, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base_model import BaseModel

class SecurityAudit(BaseModel):
    """
    Security Advisor Audit Model.
    Tracks user posture profile, questionnaire responses, vulnerability score, and generated advice.
    """
    __tablename__ = "security_audits"

    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    title: Mapped[str] = mapped_column(
        String(255),
        default="Personal Security Exposure Audit",
        nullable=False
    )

    overall_score: Mapped[int] = mapped_column(
        Integer,
        default=100,
        nullable=False
    )

    risk_level: Mapped[str] = mapped_column(
        String(20),
        default="Safe",
        nullable=False
    )

    questionnaire_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True
    )

    advisor_markdown: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True
    )

    user = relationship("User", back_populates="security_audits")

    def __repr__(self) -> str:
        return f"<SecurityAudit(score={self.overall_score}, risk='{self.risk_level}')>"
