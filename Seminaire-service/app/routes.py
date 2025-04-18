from flask import Blueprint, request, jsonify
import requests
from app.models import Seminar
from app.db import db
from app.services import verify_token
from app.utils import parse_iso_datetime

seminar_bp = Blueprint("seminar", __name__)

# URL des autres microservices
AUTH_SERVICE_URL = "http://auth-service/validate-token"
RESERVATION_SERVICE_URL = "http://reservation-service/create-reservation"

@seminar_bp.route("/create", methods=["POST"])
def create_seminar():
    #route de la creation de séminaire Prend en paramètre le token (via Authorization Header) et les détails du séminaire.

    data = request.json
    title = data.get("title")
    description = data.get("description")
    start_datetime = data.get("start_datetime")  # Ex: '2024-11-20T10:00:00'
    duration_minutes = data.get("duration_minutes")

    if not title or not description or not start_datetime or not duration_minutes:
        return jsonify({"error": "Missing required fields"}), 400
     # Validate and parse start_datetime
    try:
        start_datetime = parse_iso_datetime(start_datetime)
    except ValueError:
        return jsonify({"error": "Invalid start_datetime format"}), 400

    # Extraction du token
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "Authorization token is missing"}), 401

    user_id, error = verify_token(token)
    if error:
        return jsonify(error), 401

    # Création du séminaire dans la base de données
    seminar = Seminar(title=title, description=description, user_id=user_id)
    db.session.add(seminar)
    db.session.commit()

    # Appel au service de réservation pour enregistrer la disponibilité
    reservation_payload = {
        "utilisateur_id":user_id,
        "seminar_id": seminar.id,
        "date": start_datetime.isoformat(),
        "duree": duration_minutes,
    }
    reservation_response = requests.post(RESERVATION_SERVICE_URL, json=reservation_payload)
    if reservation_response.status_code == 201:
        return jsonify({"message": "Seminar created and reservation confirmed. Check your email."}), 201

    return jsonify({"error": "Seminar created, but reservation failed"}), 500



@seminar_bp.route("/list", methods=["GET"])
def get_user_seminars():
    
    #Route pour récupérer la liste des séminaires créés par un utilisateur.
    
    
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "Authorization token is missing"}), 401

    
    user_id, error = verify_token(token)
    if error:
        return jsonify(error), 401

    # Requête pour récupérer les séminaires de l'utilisateur
    user_seminars = Seminar.query.filter_by(user_id=user_id).all()

    # Transformation en format JSON pour la réponse
    seminars_list = [
        {
            "id": seminar.id,
            "title": seminar.title,
            "description": seminar.description,
            "created_at": seminar.created_at.isoformat(),
        }
        for seminar in user_seminars
    ]

    return jsonify({"seminars": seminars_list}), 200
