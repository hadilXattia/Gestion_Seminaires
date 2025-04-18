from enum import Enum
import httpx
from fastapi import HTTPException
from functools import lru_cache
import os

AUTH_SERVICE_URL = os.getenv('AUTH_SERVICE_URL')
SEMINAR_SERVICE_URL = os.getenv('SEMINAIRE_SERVICE_URL')


class EventType(str, Enum):
    CONFIRMATION = "confirmation"
    UPDATE = "update"
    RAPPEL = "rappel"

def generate_message(event_type: str, **kwargs) -> str:
    if event_type == EventType.CONFIRMATION:
        return f"Votre réservation pour l'événement {kwargs['event_name']} le {kwargs['date']} a été confirmée."
    elif event_type == EventType.UPDATE:
        list_autrechoix = kwargs.get('list_autrechoix', [])
        choix_message = []

        for choix in list_autrechoix:
            jours = choix.get('jour')
            periodes = ", ".join([f"{periode['entre']} - {periode['et']}" for periode in choix.get('periodes', [])])
            choix_message.append(f"Le {jours}, de {periodes}")

        list_choices = "\n".join(choix_message)

        return (
            f"Nous sommes désolés, mais la date initialement demandée pour l'événement {kwargs['event_name']} n'est pas disponible.\n"
            f"Nous vous proposons la date suivante : {kwargs['date_proposed']}.\n"
            f"Si cette date ne vous convient pas, voici d'autres options possibles : \n{list_choices}.\n"
            f"Veuillez répondre rapidement pour confirmer votre choix."
        )
    elif event_type == EventType.RAPPEL:
        return f"Rappel : Votre événement {kwargs['event_name']} est prévu pour le {kwargs['date']}."
    else:
        raise ValueError("Invalid event type")

@lru_cache(maxsize=100)
def get_user_email(user_id: int) -> str:
    url = f"{AUTH_SERVICE_URL}/email/{user_id}"
    try:
        response = httpx.get(url, timeout=5)
        response.raise_for_status()  # Gère les erreurs HTTP (4xx, 5xx)
    except httpx.RequestError as exc:
        raise HTTPException(status_code=500, detail=f"Auth service unavailable: {exc}")
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            raise HTTPException(status_code=404, detail="User not found")
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text)

    data = response.json()
    return data.get("email")  # Assure-toi que "email" existe dans la réponse

@lru_cache(maxsize=100)
async def get_seminar_name(event_id: int) -> str:
    url = f"{SEMINAR_SERVICE_URL}/seminars/{event_id}"
    try:
        response = httpx.get(url, timeout=5)
        response.raise_for_status()  # Gère les erreurs HTTP (4xx, 5xx)
    except httpx.RequestError as exc:
        raise HTTPException(status_code=500, detail=f"Auth service unavailable: {exc}")
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            raise HTTPException(status_code=404, detail="User not found")
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text)

    data = response.json()
    return data.get("event_name")