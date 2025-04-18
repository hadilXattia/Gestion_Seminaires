from sqlalchemy import Column, Integer, String, Text, TIMESTAMP, func
from notification_service.database import Base

class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    event_type = Column(String(50), nullable=False)
    event_id = Column(Integer, nullable=False)
    message = Column(Text, nullable=False)
    status = Column(String(20), default="pending")
    created_at = Column(TIMESTAMP, server_default=func.now())
