from app.db import db
from datetime import datetime

class Seminar(db.Model):
    __tablename__ = 'seminars'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)  # Foreign key to user
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Seminar(id={self.id}, title={self.title}, user_id={self.user_id})>"
