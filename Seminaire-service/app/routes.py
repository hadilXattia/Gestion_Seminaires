from flask import Blueprint, request, jsonify
import requests
from app.models import Seminar
from app.db import db
from app.services import verify_token
from app.utils import parse_iso_datetime
import logging

seminar_bp = Blueprint("seminar", __name__)

# 🛠️ Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 📡 URLs of other microservices
AUTH_SERVICE_URL = "http://auth-service/validate-token"
RESERVATION_SERVICE_URL = "http://reservation-service/create-reservation"

@seminar_bp.route("/create", methods=["POST"])
def create_seminar():
    logger.info("Requête reçue pour créer un séminaire")

    data = request.json
    title = data.get("title")
    description = data.get("description")
    start_datetime = data.get("start_datetime")
    duration_minutes = data.get("duration_minutes")

    if not title or not description or not start_datetime or not duration_minutes:
        logger.warning("Champs manquants dans la création du séminaire")
        return jsonify({"error": "Missing required fields"}), 400

    try:
        start_datetime = parse_iso_datetime(start_datetime)
    except ValueError:
        logger.error("Format invalide pour 'start_datetime'")
        return jsonify({"error": "Invalid start_datetime format"}), 400

    token = request.headers.get("Authorization")
    if not token:
        logger.warning("Token d'authentification manquant")
        return jsonify({"error": "Authorization token is missing"}), 401

    user_id, error = verify_token(token)
    if error:
        logger.warning(f"Token invalide pour la création du séminaire - Erreur: {error}")
        return jsonify(error), 401

    seminar = Seminar(title=title, description=description, user_id=user_id)
    db.session.add(seminar)
    db.session.commit()

    logger.info(f"Séminaire créé avec succès - ID: {seminar.id}, Utilisateur: {user_id}")

    reservation_payload = {
        "utilisateur_id": user_id,
        "seminar_id": seminar.id,
        "date": start_datetime.isoformat(),
        "duree": duration_minutes,
    }

    try:
        reservation_response = requests.post(RESERVATION_SERVICE_URL, json=reservation_payload)
        if reservation_response.status_code == 201:
            logger.info(f"Réservation confirmée pour le séminaire ID: {seminar.id}")
            return jsonify({"message": "Seminar created and reservation confirmed. Check your email."}), 201
        else:
            logger.warning(f"Échec de la réservation pour le séminaire ID: {seminar.id}")
    except Exception as e:
        logger.exception("Erreur lors de la communication avec le service de réservation")

    return jsonify({"error": "Seminar created, but reservation failed"}), 500


@seminar_bp.route("/list", methods=["GET"])
def get_user_seminars():
    logger.info("Requête reçue pour lister les séminaires de l'utilisateur")

    token = request.headers.get("Authorization")
    if not token:
        logger.warning("Token d'authentification manquant pour la récupération des séminaires")
        return jsonify({"error": "Authorization token is missing"}), 401

    user_id, error = verify_token(token)
    if error:
        logger.warning(f"Token invalide lors de la récupération des séminaires - Erreur: {error}")
        return jsonify(error), 401

    user_seminars = Seminar.query.filter_by(user_id=user_id).all()

    logger.info(f"{len(user_seminars)} séminaires récupérés pour l'utilisateur ID: {user_id}")

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
