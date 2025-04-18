import requests
from flask import jsonify

AUTH_SERVICE_URL = "http://auth-service/api/verify-token"

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
