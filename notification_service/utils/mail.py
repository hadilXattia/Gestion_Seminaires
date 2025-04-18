import resend

# Configure ta clé API Resend
resend.api_key = "re_JBMdkvHD_EW67vYyz7WX2waCzzg7HEtFM"

# Fonction pour envoyer un e-mail
def send_email(subject: str, to_email: str, content: str):
    try:
        # Préparation des paramètres de l'email
        params: resend.Emails.SendParams = {
            "from": "Acme <onboarding@resend.dev>",  # Adresse validée par Resend
            "to": "blkchaimae11@gmail.com",  # Liste des destinataires
            "subject": subject,  # Sujet de l'email
            "html": f"<p>{content}</p>",  # Contenu HTML du mail
        }

        email = resend.Emails.send(params)
        print(f"Email sent! Response: {email}")
        return email
    except Exception as e:
        print(f"Error sending email: {e}")
        raise
