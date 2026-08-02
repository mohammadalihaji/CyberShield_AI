from datetime import datetime
from typing import Optional
from sqlalchemy import String, Text, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from database.base import Base

class SystemSetting(Base):
    """
    System Setting Model.
    """
    __tablename__ = "system_settings"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True
    )

    setting_key: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True
    )

    setting_value: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True
    )

    description: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False
    )

    def __repr__(self) -> str:
        return f"<SystemSetting(key='{self.setting_key}')>"
