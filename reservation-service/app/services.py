import requests
from datetime import datetime, timedelta
from app.models import db, Reservation
from flask import jsonify

AUTH_SERVICE_URL = "http://auth-service/api/verify-token"
notification_URL = "http://notification_service/events"

def verify_token(token):
    
    try:
        # Appel au service Authentification
        response = requests.get(AUTH_SERVICE_URL, headers={"Authorization": token})
        
        if response.status_code != 200:
            return None, {"error": "Invalid or expired token"}
        
        user_id = response.json().get("user_id")
        if not user_id:
            return None, {"error": "User ID could not be retrieved"}
        
        return user_id, None

    except requests.RequestException as e:
        # Gestion des erreurs de requêtes HTTP
        return None, {"error": f"Authentication service error: {str(e)}"}

def Confirmation_email(utilisateur_id, seminaire_id, date_debut):
    """Appelle un microservice pour envoyer un email de notification."""
    payload = {
        "event_type": "confirmation",
        "user_id": utilisateur_id,
        "event_id": seminaire_id,
        "date": date_debut,
    }
    try:
        response = requests.post(notification_URL, json=payload)
        if response.status_code != 200:
            print(f"Erreur lors de l'envoi de l'email : {response.text}")
    except Exception as e:
        print(f"Erreur de connexion au service email : {e}")


def new_date_email(utilisateur_id, seminaire_id, date_debut, dates_possibles):
    payload = {
        "event_type": "update",
        "user_id": utilisateur_id,
        "event_id": seminaire_id,
        "date_proposed": date_debut,
        "liste_autrechoix": dates_possibles,
    }
    try:
        response = requests.post(notification_URL, json=payload)
        if response.status_code != 200:
            print(f"Erreur lors de l'envoi de l'email : {response.text}")
    except Exception as e:
        print(f"Erreur de connexion au service email : {e}")


def trouver_dates_possibles(date_initiale, duree, seminaire_id, delta_jours=7):
    # Durée de l'événement sous forme de timedelta
    duree_timedelta = timedelta(hours=duree)
    print(duree_timedelta)
    
    heure_debut = 8
    heure_fin = 20

    suggestions = []

    # Commencer la recherche à partir de maintenant si la date initiale est déjà passée
    start_date = max(date_initiale.date(), datetime.now().date())
    start_time = max(date_initiale, datetime.now())
    today = datetime.now()
    days_diff = (date_initiale - today).days  # Nombre de jours avant ou après la date initiale
    start_offset = min(delta_jours, days_diff) if days_diff > 0 else 0

    for offset in range(-start_offset, delta_jours + 1):
        jour_test = start_date + timedelta(days=offset)
        debut_jour = datetime.combine(jour_test, datetime.min.time()) + timedelta(hours=heure_debut)
        fin_jour = datetime.combine(jour_test, datetime.min.time()) + timedelta(hours=heure_fin)
        
        # Si c'est le jour de la demande, ajuster l'heure de début
        if jour_test == start_date:  
            debut_jour = max(debut_jour, start_time)  # Ne pas commencer avant l'heure actuelle

        # Recherche des créneaux horaires disponibles pour ce jour
        plages_disponibles = []
        debut_test = debut_jour

        while debut_test + duree_timedelta <= fin_jour:
            fin_test = debut_test + duree_timedelta
            
            # Vérification s'il y a un conflit avec les réservations existantes
            conflit = Reservation.query.filter(
                (Reservation.date_debut < fin_test) & 
                (Reservation.date_fin > debut_test) &
                (Reservation.seminaire_id == seminaire_id)
            ).first()

            if not conflit:
                # Ajouter le créneau sans modifier l'heure si aucun conflit
                plages_disponibles.append((debut_test, fin_test))
                debut_test += duree_timedelta  # Passer au créneau suivant
            else:
                # Si conflit, vérifier le créneau suivant après 15 minutes
                debut_test += timedelta(minutes=15)

        # Si des créneaux sont disponibles, les regrouper par période
        if plages_disponibles:
            heures_disponibles = {
                "jour": jour_test.strftime('%Y-%m-%d'),
                "periodes": []
            }

            debut_plage, fin_plage = plages_disponibles[0]
            for i in range(1, len(plages_disponibles)):
                if plages_disponibles[i][0] <= fin_plage:  # Créneau adjacent ou chevauchant
                    fin_plage = plages_disponibles[i][1]
                else:
                    heures_disponibles["periodes"].append({
                        "entre": debut_plage.strftime('%H:%M'),
                        "et": fin_plage.strftime('%H:%M')
                    })
                    debut_plage, fin_plage = plages_disponibles[i]

            # Ajouter la dernière période
            heures_disponibles["periodes"].append({
                "entre": debut_plage.strftime('%H:%M'),
                "et": fin_plage.strftime('%H:%M')
            })

            # Ajouter les résultats au tableau de suggestions
            suggestions.append(heures_disponibles)
    print(suggestions)
    return suggestions

