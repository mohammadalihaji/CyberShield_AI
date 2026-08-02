from sqlalchemy import String
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from models.base_model import BaseModel


class Role(BaseModel):
    """
    System role.

    Examples:
    - Super Admin
    - Admin
    - Security Analyst
    - User
    """

    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )

    display_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    # Relationship to the association table
    user_roles = relationship(
        "UserRole",
        back_populates="role",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Role(name='{self.name}')>"