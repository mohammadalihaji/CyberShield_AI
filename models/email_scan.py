from typing import Optional, Dict, Any
from sqlalchemy import String, Text, Integer, Boolean, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base_model import BaseModel

class EmailScan(BaseModel):
    """
    Email Phishing Audit Model.
    Tracks email sender, body snippet, urgency, spoofed status, SPF alignments, and AI analysis.
    """
    __tablename__ = "email_scans"

    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    sender: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True
    )

    body_snippet: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    risk_level: Mapped[str] = mapped_column(
        String(20),
        default="Suspicious",
        nullable=False,
        index=True
    )

    phishing_score: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False
    )

    urgency: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True
    )

    suspicious_links: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False
    )

    spoofed_domain: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )

    spf_check: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True
    )

    explanation_markdown: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True
    )

    result_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True
    )

    user = relationship("User", back_populates="email_scans")

    def __repr__(self) -> str:
        return f"<EmailScan(sender='{self.sender}', risk='{self.risk_level}')>"
