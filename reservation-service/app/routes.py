from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from app.models import db, Reservation
import requests
from app.services import trouver_dates_possibles, Confirmation_email, new_date_email, verify_token
import logging

bp = Blueprint('reservations', __name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
@bp.route("/")
def home():
    logger.info("Reservation service root endpoint called")
    return "Bienvenue dans le service de réservation !", 200

@bp.route('/reservation-service/create-reservation', methods=['POST'])
def creer_reservation():
    logger.info(f"Demande de réservation reçue - Utilisateur ID: {utilisateur_id}, Séminaire ID: {seminaire_id}")

    # Récupérer les données JSON envoyées dans le corps de la requête
    data = request.get_json()

    # Extraire les paramètres du JSON payload
    utilisateur_id = data.get('utilisateur_id')
    seminaire_id = data.get('seminaire_id')
    date_debut_str = data.get('date')  # Format ISO8601 attendu
    duree = data.get('duree', 1)  # Par défaut, durée = 1 heure
    logger.warning("Conflit détecté avec une autre réservation.")
    if not utilisateur_id or not seminaire_id or not date_debut_str:
        return {"error": "Paramètres manquants : 'utilisateur_id', 'seminaire_id', 'date' sont obligatoires."}, 400

    try:
        # Convertir la date de début depuis le format ISO 8601
        date_debut = datetime.fromisoformat(date_debut_str)
    except ValueError:
        return {"error": "Format de date invalide. Utilisez ISO 8601 (ex : '2024-12-02T10:00:00')"}, 400

    # Calculer la date de fin
    date_fin = date_debut + timedelta(hours=duree)

    # Vérifier si la date est disponible
    conflit = Reservation.query.filter(
        (Reservation.date_debut < date_fin) & (Reservation.date_fin > date_debut)
    ).first()

    if conflit:
        # Trouver des dates possibles si la réservation entre en conflit
        dates_possibles = trouver_dates_possibles(date_debut, duree, seminaire_id)

        if dates_possibles:
            # Récupérer la première date possible
            premier_reservation = dates_possibles[0]['periodes'][0]
            date_debut_str = premier_reservation['entre']
            jour_date = datetime.strptime(dates_possibles[0]['jour'], '%Y-%m-%d').date()
            heure_debut = datetime.strptime(date_debut_str, '%H:%M').time()
            date_debut = datetime.combine(jour_date, heure_debut)
            date_fin = date_debut + timedelta(hours=duree)

            # Créer un message pour notifier l'utilisateur
            message = {
                "message": (
                    f"La date demandée n'était pas disponible. La réservation a été déplacée à : "
                    f"{date_debut.strftime('%Y-%m-%d %H:%M:%S')}."
                ),
                "dates_possibles": dates_possibles
            }

            # Envoyer un e-mail de proposition
            new_date_email(utilisateur_id, seminaire_id, date_debut, dates_possibles)

        else:
            # Aucun créneau disponible
            return {"error": "Aucun créneau disponible pour la réservation."}, 409
    else:
        # Si aucune réservation en conflit, créer la réservation
        message = {
            "message": f"Réservation créée avec succès pour le {date_debut.strftime('%Y-%m-%d %H:%M:%S')}."
        }
        logger.info(f"Réservation créée avec succès - ID utilisateur: {utilisateur_id}, Séminaire ID: {seminaire_id}, Date: {date_debut}")

        Confirmation_email(utilisateur_id, seminaire_id, date_debut)

    # Créer et sauvegarder la réservation
    reservation = Reservation(
        utilisateur_id=utilisateur_id,
        seminaire_id=seminaire_id,
        date_debut=date_debut,
        date_fin=date_fin
    )
    db.session.add(reservation)
    db.session.commit()

    # Retourner un message de succès
    return message, 201


@bp.route('/reservation-service/update-reservation/<int:seminaire_id>', methods=['PUT'])
def modifier_reservation(seminaire_id):
    """Mettre à jour une réservation existante."""
    data = request.get_json()
    utilisateur_existe = verify_token(data.get('token'))
    logger.info(f"Demande de mise à jour de la réservation pour le séminaire ID: {seminaire_id}")

    # Vérifier si l'utilisateur est authentifié
    if not utilisateur_existe:
        return jsonify({"message": "Utilisateur non authentifié."}), 403

    # Vérifier si la réservation existe
    reservation = Reservation.query.filter_by(seminaire_id=seminaire_id).first()

    # if not reservation:
    #     return jsonify({"message": "Réservation non trouvée."}), 404

    # Vérifier si une nouvelle date est fournie
    if 'date' in data:
        try:
            # Conversion depuis le format ISO 8601
            nouvelle_date_debut = datetime.fromisoformat(data['date'])
            nouvelle_duree = int(data.get('duree', 1))  # Par défaut, durée = 1 heure
            nouvelle_date_fin = nouvelle_date_debut + timedelta(hours=nouvelle_duree)

            # Vérifier si la nouvelle plage horaire est disponible
            conflit = Reservation.query.filter(
                (Reservation.id != reservation.id) &  # Exclure la réservation actuelle
                (Reservation.date_debut < nouvelle_date_fin) &
                (Reservation.date_fin > nouvelle_date_debut)
            ).first()

            if conflit:
                return jsonify({
                    "message": "La date demandée n'est pas disponible.",
                    "conflit": {
                        "date_debut": conflit.date_debut.strftime('%Y-%m-%d %H:%M:%S'),
                        "date_fin": conflit.date_fin.strftime('%Y-%m-%d %H:%M:%S'),
                    }
                }), 409
            logger.warning("Date de mise à jour en conflit avec une autre réservation.")


            # Mettre à jour les dates si elles sont disponibles
            reservation.date_debut = nouvelle_date_debut
            reservation.date_fin = nouvelle_date_fin

        except ValueError:
            return jsonify({"message": "Format de date invalide. Utilisez le format ISO 8601 (ex : '2024-12-04T10:00:00')."}), 400

    # Mettre à jour le statut si présent dans les données
    if 'statut' in data:
        reservation.statut = data.get('statut')

    # Enregistrer les modifications
    db.session.commit()
    logger.info(f"Réservation mise à jour avec succès pour le séminaire ID: {seminaire_id}")

    return jsonify({"message": "Réservation mise à jour avec succès."}), 200


@bp.route('/reservation-service/remove-reservation/<int:seminaire_id>', methods=['DELETE'])
def supprimer_reservation(seminaire_id):
    """Supprimer une réservation."""
    reservation = Reservation.query.filter_by(seminaire_id=seminaire_id).first()
    logger.info(f"Tentative de suppression de la réservation pour le séminaire ID: {seminaire_id}")

    if not reservation:
        return jsonify({"message": "Réservation non trouvée."}), 404

    db.session.delete(reservation)
    db.session.commit()
    logger.info(f"Réservation supprimée pour le séminaire ID: {seminaire_id}")

    return jsonify({"message": "Réservation supprimée avec succès."})
