from typing import Optional
from sqlalchemy import String, Text, BigInteger, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base_model import BaseModel

class AIReport(BaseModel):
    """
    Printable AI Threat Report Model.
    Stores generated printable reports for individual security scans.
    """
    __tablename__ = "ai_reports"

    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    scan_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True
    )

    scan_id: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )

    summary: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True
    )

    report_content: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    risk_level: Mapped[str] = mapped_column(
        String(20),
        default="Suspicious",
        nullable=False
    )

    user = relationship("User", back_populates="reports")

    def __repr__(self) -> str:
        return f"<AIReport(title='{self.title}', type='{self.scan_type}')>"
