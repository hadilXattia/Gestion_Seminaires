import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Keycloak settings
    KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL")
    KEYCLOAK_REALM_NAME = os.getenv("KEYCLOAK_REALM_NAME")
    KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
    KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")

    # Rôles Keycloak
    KEYCLOAK_ADMIN_ROLE = "admin"
    KEYCLOAK_ORGANIZER_ROLE = "organisateur"

    # JWT settings
    SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
    JWT_ACCESS_TOKEN_EXPIRES = 300  # 5 min
    JWT_REFRESH_TOKEN_EXPIRES = 600  # 10 min
