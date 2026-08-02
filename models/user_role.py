from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship

from models.base_model import BaseModel


class UserRole(BaseModel):
    """
    Association table between users and roles.
    """

    __tablename__ = "user_roles"

    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "role_id",
            name="uq_user_role",
        ),
    )

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    role_id: Mapped[int] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user = relationship(
        "User",
        back_populates="user_roles",
    )

    role = relationship(
        "Role",
        back_populates="user_roles",
    )

    def __repr__(self) -> str:
        return (
            f"<UserRole(user_id={self.user_id}, "
            f"role_id={self.role_id})>"
        )