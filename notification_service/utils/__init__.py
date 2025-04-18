from notification_service.utils.mail import send_email

if __name__ == "__main__":
    subject = "Test Email"
    to_email = "blkchaimae11@gmail.com"
    content = "This is a test email from Resend."

    response = send_email(subject, to_email, content)
    print(response)
