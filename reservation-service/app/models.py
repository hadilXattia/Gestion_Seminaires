# from flask_sqlalchemy import SQLAlchemy
# from datetime import datetime

# db = SQLAlchemy()

# class Reservation(db.Model):
#     __tablename__ = 'reservation'
#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     utilisateur_id = db.Column(db.Integer, nullable=False)  # Placeholder pour l'utilisateur
#     seminaire_id = db.Column(db.Integer, nullable=False)   # Placeholder pour le séminaire
#     date_debut = db.Column(db.DateTime, nullable=False)
#     date_fin = db.Column(db.DateTime, nullable=False)
#     statut = db.Column(db.String(50), default='en attente')

from app import db

class Reservation(db.Model):
    __tablename__ = 'reservations'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    utilisateur_id = db.Column(db.Integer, nullable=False)
    seminaire_id = db.Column(db.Integer, nullable=False)
    date_debut = db.Column(db.DateTime, nullable=False)
    date_fin = db.Column(db.DateTime, nullable=False)
    statut = db.Column(db.String(50), default='en attente')

    def __repr__(self):
        return f"<Reservation {self.id} - Statut: {self.statut}>"
