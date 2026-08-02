from typing import Optional, Dict, Any
from sqlalchemy import String, Text, Float, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base_model import BaseModel

class ImageScan(BaseModel):
    """
    Image Deepfake & Forensic Scan Model.
    Tracks media filename, upload path, AI confidence, fingerprints, JPEG grid noise, and AI analysis.
    """
    __tablename__ = "image_scans"

    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )

    file_path: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True
    )

    risk_level: Mapped[str] = mapped_column(
        String(20),
        default="Suspicious",
        nullable=False,
        index=True
    )

    ai_confidence: Mapped[float] = mapped_column(
        Float,
        default=50.0,
        nullable=False
    )

    fingerprints: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True
    )

    jpeg_artifacts: Mapped[Optional[str]] = mapped_column(
        String(255),
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

    user = relationship("User", back_populates="image_scans")

    def __repr__(self) -> str:
        return f"<ImageScan(filename='{self.filename}', risk='{self.risk_level}')>"
