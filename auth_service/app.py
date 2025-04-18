from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import requests
from config import Config

app = Flask(__name__)

# Configurer Flask pour utiliser JWT
app.config.from_object(Config)
jwt = JWTManager(app)

# Fonction pour vérifier les informations de connexion auprès de Keycloak
def authenticate_user(email, password):
    keycloak_url = f"{Config.KEYCLOAK_SERVER_URL}/realms/{Config.KEYCLOAK_REALM_NAME}/protocol/openid-connect/token"
    data = {
        "client_id": Config.KEYCLOAK_CLIENT_ID,
        "client_secret": Config.KEYCLOAK_CLIENT_SECRET,
        "username": email,
        "password": password,
        "grant_type": "password",
    }
    response = requests.post(keycloak_url, data=data)
    
    if response.status_code == 200:
        # Récupération des informations de l'utilisateur, y compris les rôles
        access_token = response.json().get("access_token")
        roles = get_user_roles_from_keycloak(access_token)
        return access_token, roles
    else:
        return None, None

# Fonction pour récupérer les rôles d'un utilisateur depuis Keycloak
def get_user_roles_from_keycloak(access_token):
    """Récupérer les rôles d'un utilisateur à partir de Keycloak"""
    user_info_url = f"{Config.KEYCLOAK_SERVER_URL}/realms/{Config.KEYCLOAK_REALM_NAME}/protocol/openid-connect/userinfo"
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(user_info_url, headers=headers)

    if response.status_code == 200:
        user_info = response.json()
        roles = user_info.get("roles", [])
        return roles
    else:
        return []
    
@app.route("/signup", methods=["POST"])
def signup():
    """
    Route for user registration (Sign-Up).
    """
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    first_name = data.get("first_name", "")
    last_name = data.get("last_name", "")

    # Keycloak admin API endpoint to create a new user
    keycloak_url = f"{Config.KEYCLOAK_SERVER_URL}/admin/realms/{Config.KEYCLOAK_REALM_NAME}/users"
    token_url = f"{Config.KEYCLOAK_SERVER_URL}/realms/{Config.KEYCLOAK_REALM_NAME}/protocol/openid-connect/token"
    
    # Data to obtain an admin access token
    admin_data = {
        "client_id": Config.KEYCLOAK_CLIENT_ID,
        "client_secret": Config.KEYCLOAK_CLIENT_SECRET,
        "grant_type": "client_credentials"
    }

    try:
        # Obtain an admin access token
        token_response = requests.post(token_url, data=admin_data)
        token_response.raise_for_status()
        access_token = token_response.json().get("access_token")

        # Create the user in Keycloak
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        user_data = {
            "username": email,
            "email": email,
            "enabled": True,
            "firstName": first_name,
            "lastName": last_name,
            "credentials": [
                {
                    "type": "password",
                    "value": password,
                    "temporary": False
                }
            ]
        }
        response = requests.post(keycloak_url, json=user_data, headers=headers)
        
        if response.status_code == 201:
            return jsonify({"msg": "User created successfully"}), 201
        else:
            return jsonify({"msg": "Failed to create user", "error": response.json()}), response.status_code

    except requests.exceptions.RequestException as e:
        return jsonify({"msg": f"Error communicating with Keycloak: {e}"}), 500

# Route pour le login (connexion)
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    
    # Authentifier l'utilisateur via Keycloak
    access_token, roles = authenticate_user(email, password)
    
    if access_token:
        # Créer un access token JWT pour l'utilisateur et ajouter les rôles
        user_data = {
            "email": email,
            "roles": roles
        }
        jwt_token = create_access_token(identity=user_data)
        return jsonify({
            "access_token": jwt_token,
            "keycloak_token": access_token,
            "roles": roles
        }), 200
    else:
        return jsonify({"msg": "Bad credentials"}), 401

# Route pour le logout (déconnexion)
@app.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    return jsonify({"msg": "Successfully logged out"}), 200

# Route protégée par JWT pour admin
@app.route("/admin", methods=["GET"])
@jwt_required()
def admin():
    current_user = get_jwt_identity()
    if Config.KEYCLOAK_ADMIN_ROLE not in current_user["roles"]:
        return jsonify({"msg": "Permission denied, you need admin role"}), 403
    return jsonify({"msg": "Welcome Admin!"}), 200

# Route protégée par JWT pour organisateur
@app.route("/organizer", methods=["GET"])
@jwt_required()
def organizer():
    current_user = get_jwt_identity()
    if Config.KEYCLOAK_ORGANIZER_ROLE not in current_user["roles"]:
        return jsonify({"msg": "Permission denied, you need organizer role"}), 403
    return jsonify({"msg": "Welcome Organizer!"}), 200
# Route pour service reservation

#@app.route("/api/verify-token", methods=["GET"])
@jwt_required()
def verify_token() :
    """
    Vérifie le token JWT envoyé dans l'en-tête Authorization.
    """
    
    try:
        # Décoder le token JWT et récupérer l'identité de l'utilisateur
        user_identity = get_jwt_identity()

        if not user_identity:
            return jsonify({"msg": "Invalid token or user identity not found"}), 401

        return jsonify({
            "user_id": user_identity.get("email"),  # Retourne l'email ou une autre identité
            "roles": user_identity.get("roles")    # Retourne les rôles de l'utilisateur
        }), 200

    except Exception as e:
        return jsonify({"msg": f"Token verification failed: {str(e)}"}), 401

@app.route("/api/verify-token", methods=["GET"])
@jwt_required()
def verify_token():
    user_identity = get_jwt_identity()
    return jsonify({
        "user_id": user_identity.get("email"),
        "roles": user_identity.get("roles")
    }), 200

@app.route("/email/<user_id>", methods=["GET"])
def get_email(user_id):
    """
    Route publique pour récupérer l'email d'un utilisateur basé sur son user_id.
    """
    keycloak_url = f"{Config.KEYCLOAK_SERVER_URL}/admin/realms/{Config.KEYCLOAK_REALM_NAME}/users/{user_id}"

    # Authentification avec un compte administrateur Keycloak
    data = {
        "client_id": Config.KEYCLOAK_CLIENT_ID,
        "client_secret": Config.KEYCLOAK_CLIENT_SECRET,
        "grant_type": "client_credentials"
    }
    token_url = f"{Config.KEYCLOAK_SERVER_URL}/realms/{Config.KEYCLOAK_REALM_NAME}/protocol/openid-connect/token"
    
    try:
        # Obtenir un token d'accès pour utiliser l'API Admin Keycloak
        token_response = requests.post(token_url, data=data)
        token_response.raise_for_status()
        access_token = token_response.json().get("access_token")

        # Récupérer les informations utilisateur depuis l'API Admin Keycloak
        headers = {"Authorization": f"Bearer {access_token}"}
        user_response = requests.get(keycloak_url, headers=headers)
        user_response.raise_for_status()

        user_data = user_response.json()
        email = user_data.get("email")
        if not email:
            return jsonify({"msg": "Email not found for the user"}), 404

        return jsonify({"email": email}), 200

    except requests.exceptions.RequestException as e:
        return jsonify({"msg": f"Error communicating with Keycloak: {e}"}), 500


if __name__ == "__main__":
    app.run(debug=True)
