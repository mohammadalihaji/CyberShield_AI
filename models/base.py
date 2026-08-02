from datetime import datetime
from extensions import db


class BaseModel(db.Model):
    __abstract__ = True

    id = db.Column(
        db.BigInteger,
        primary_key=True,
        autoincrement=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False
    )