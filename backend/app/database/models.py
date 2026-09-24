from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.sql import func

from backend.app.database.connection import Base


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)

    timestamp = Column(DateTime, nullable=False)

    level = Column(String(20), nullable=False)

    user = Column(String(100), nullable=True)

    action = Column(String(100), nullable=False)

    ip = Column(String(45), nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)

    rule = Column(String(100), nullable=False)

    severity = Column(String(20), nullable=False)

    user = Column(String(100), nullable=True)

    ip = Column(String(45), nullable=True)

    message = Column(String(500), nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )