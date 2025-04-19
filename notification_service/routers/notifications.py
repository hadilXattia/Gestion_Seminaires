from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from notification_service.database import SessionLocal
from notification_service.models import Notification
from notification_service.utils.mail import send_email
from notification_service.utils.helpers import get_user_email, generate_message, get_seminar_name
import logging

# ✅ Setup structured logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()

class Event(BaseModel):
    event_type: str
    user_id: int
    event_id: int
    date: str
    date_proposed: str = None
    list_autrechoix: list[dict] = None

@router.post("/events/")
async def handle_event(event: Event):
    logger.info(f"Reçu un événement: type={event.event_type}, user_id={event.user_id}, event_id={event.event_id}")

    db = SessionLocal()

    try:
        user_email = get_user_email(event.user_id)
        logger.info(f"Email de l'utilisateur récupéré: {user_email}")
    except HTTPException as e:
        logger.warning(f"Erreur lors de la récupération de l'email pour user_id={event.user_id}: {e.detail}")
        raise HTTPException(status_code=e.status_code, detail=e.detail)

    try:
        event_name = get_seminar_name(event.event_id)
        logger.info(f"Nom du séminaire récupéré: {event_name}")
    except HTTPException as e:
        logger.warning(f"Erreur lors de la récupération du nom du séminaire pour event_id={event.event_id}: {e.detail}")
        raise HTTPException(status_code=e.status_code, detail=e.detail)

    try:
        message = generate_message(
            event.event_type,
            event_name=event_name,
            date=event.date,
            date_proposed=event.date_proposed,
            list_autrechoix=event.list_autrechoix,
        )
        logger.info(f"Message généré pour la notification")
    except ValueError as e:
        logger.error(f"Erreur lors de la génération du message: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

    new_notification = Notification(
        user_id=event.user_id,
        event_type=event.event_type,
        event_id=event.event_id,
        message=message,
    )

    db.add(new_notification)
    db.commit()
    db.refresh(new_notification)
    logger.info(f"Notification enregistrée dans la base de données: ID={new_notification.id}")

    subject = f"Notification pour l'événement {event_name.capitalize()}"
    subject = subject.encode('utf-8').decode('utf-8')
    message = message.encode('utf-8').decode('utf-8')

    response = send_email(subject, user_email, message)
    if response:
        logger.info(f"Email envoyé avec succès à {user_email}")
        return {
            "status": "success",
            "notification_id": new_notification.id,
            "email_status": "sent"
        }
    else:
        logger.error(f"Échec de l'envoi de l'email à {user_email}")
        raise HTTPException(status_code=500, detail="Email sending failed")
