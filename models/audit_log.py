from typing import Optional
from sqlalchemy import String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base_model import BaseModel

class AuditLog(BaseModel):
    """
    Security Audit Log Model.
    """
    __tablename__ = "audit_logs"

    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True
    )

    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True
    )

    details: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True
    )

    user = relationship("User", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<AuditLog(action='{self.action}', user_id={self.user_id})>"
