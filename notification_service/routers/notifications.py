from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from notification_service.database import SessionLocal
from notification_service.models import Notification
from notification_service.utils.mail import send_email
from notification_service.utils.helpers import get_user_email, generate_message, get_seminar_name

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

    db = SessionLocal()
    try:
        user_email = get_user_email(event.user_id)
        print(user_email)
    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)

    try:
        event_name = get_seminar_name(event.event_id)
        print(event_name)
    except HTTPException as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)

    # Générer le message
    try:
        message = generate_message(
            event.event_type,
            event_name=event_name,
            date=event.date,
            date_proposed=event.date_proposed,
            list_autrechoix=event.list_autrechoix,
        )
        print(message)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Créer la notification
    new_notification = Notification(
        user_id=event.user_id,
        event_type=event.event_type,
        event_id=event.event_id,
        message=message,
    )
    db.add(new_notification)
    db.commit()
    db.refresh(new_notification)

    # Envoyer l'email
    subject = f"Notification pour l'événement {event_name.capitalize()}"
    subject = subject.encode('utf-8').decode('utf-8')
    message = message.encode('utf-8').decode('utf-8')
    response = send_email(subject, user_email, message)
    print(response)
    if response:
        return {"status": "success", "notification_id": new_notification.id, "email_status": "sent"}
    else:
        raise HTTPException(status_code=500, detail="Email sending failed")
