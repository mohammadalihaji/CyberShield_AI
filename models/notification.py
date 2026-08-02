from typing import Optional
from sqlalchemy import String, Text, Boolean, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base_model import BaseModel

class Notification(BaseModel):
    """
    Notification Model.
    """
    __tablename__ = "notifications"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )

    message: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    is_read: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True
    )

    notification_type: Mapped[str] = mapped_column(
        String(50),
        default="info",
        nullable=False
    )

    user = relationship("User", back_populates="notifications")

    def __repr__(self) -> str:
        return f"<Notification(title='{self.title}', is_read={self.is_read})>"
