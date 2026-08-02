from typing import Optional, Dict, Any
from sqlalchemy import String, Text, Integer, Boolean, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base_model import BaseModel

class WebsiteScan(BaseModel):
    """
    Website Safety Scan Model.
    Tracks user target URLs, domain checks, SSL integrity, phishing metrics, and AI breakdown.
    """
    __tablename__ = "website_scans"

    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    url: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True
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

    ssl_valid: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )

    malware_found: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )

    domain_age: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True
    )

    reputation: Mapped[Optional[str]] = mapped_column(
        String(100),
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

    user = relationship("User", back_populates="website_scans")

    def __repr__(self) -> str:
        return f"<WebsiteScan(domain='{self.domain}', risk='{self.risk_level}')>"
