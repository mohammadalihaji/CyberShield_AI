from typing import Optional
from sqlalchemy import String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base_model import BaseModel

class ChatMessage(BaseModel):
    """
    Conversational AI Chat Message Model.
    Tracks user session ID, sender ('user' or 'model'), prompt, and AI assistant reply.
    """
    __tablename__ = "chat_messages"

    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    session_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True
    )

    sender: Mapped[str] = mapped_column(
        String(20),
        nullable=False
    )

    message: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    user = relationship("User", back_populates="chat_messages")

    def __repr__(self) -> str:
        return f"<ChatMessage(sender='{self.sender}', session='{self.session_id}')>"
