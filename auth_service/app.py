import logging
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import requests
from config import Config

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
jwt = JWTManager(app)

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
    logger.info(f"Authenticating user: {email}, response: {response.status_code}")

    if response.status_code == 200:
        access_token = response.json().get("access_token")
        roles = get_user_roles_from_keycloak(access_token)
        return access_token, roles
    else:
        logger.warning(f"Authentication failed for user: {email}")
        return None, None

def get_user_roles_from_keycloak(access_token):
    user_info_url = f"{Config.KEYCLOAK_SERVER_URL}/realms/{Config.KEYCLOAK_REALM_NAME}/protocol/openid-connect/userinfo"
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(user_info_url, headers=headers)

    if response.status_code == 200:
        user_info = response.json()
        roles = user_info.get("roles", [])
        logger.info(f"Roles retrieved from Keycloak: {roles}")
        return roles
    else:
        logger.error(f"Failed to retrieve user roles, status: {response.status_code}")
        return []

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    first_name = data.get("first_name", "")
    last_name = data.get("last_name", "")

    logger.info(f"Signup attempt for {email}")

    keycloak_url = f"{Config.KEYCLOAK_SERVER_URL}/admin/realms/{Config.KEYCLOAK_REALM_NAME}/users"
    token_url = f"{Config.KEYCLOAK_SERVER_URL}/realms/{Config.KEYCLOAK_REALM_NAME}/protocol/openid-connect/token"
    
    admin_data = {
        "client_id": Config.KEYCLOAK_CLIENT_ID,
        "client_secret": Config.KEYCLOAK_CLIENT_SECRET,
        "grant_type": "client_credentials"
    }

    try:
        token_response = requests.post(token_url, data=admin_data)
        token_response.raise_for_status()
        access_token = token_response.json().get("access_token")

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
            "credentials": [{
                "type": "password",
                "value": password,
                "temporary": False
            }]
        }
        response = requests.post(keycloak_url, json=user_data, headers=headers)

        if response.status_code == 201:
            logger.info(f"User {email} successfully created.")
            return jsonify({"msg": "User created successfully"}), 201
        else:
            logger.warning(f"User creation failed for {email}, response: {response.status_code}")
            return jsonify({"msg": "Failed to create user", "error": response.json()}), response.status_code

    except requests.exceptions.RequestException as e:
        logger.error(f"Error communicating with Keycloak during signup: {str(e)}")
        return jsonify({"msg": f"Keycloak error: {str(e)}"}), 500

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    access_token, roles = authenticate_user(email, password)
    if access_token:
        user_data = {
            "email": email,
            "roles": roles
        }
        jwt_token = create_access_token(identity=user_data)
        logger.info(f"User {email} logged in successfully.")
        return jsonify({
            "access_token": jwt_token,
            "keycloak_token": access_token,
            "roles": roles
        }), 200
    else:
        logger.warning(f"Login failed for user: {email}")
        return jsonify({"msg": "Bad credentials"}), 401

@app.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    user = get_jwt_identity()
    logger.info(f"User {user.get('email')} logged out.")
    return jsonify({"msg": "Successfully logged out"}), 200

@app.route("/admin", methods=["GET"])
@jwt_required()
def admin():
    current_user = get_jwt_identity()
    if Config.KEYCLOAK_ADMIN_ROLE not in current_user["roles"]:
        logger.warning("Unauthorized admin access attempt.")
        return jsonify({"msg": "Permission denied, admin role required"}), 403
    return jsonify({"msg": "Welcome Admin!"}), 200

@app.route("/organizer", methods=["GET"])
@jwt_required()
def organizer():
    current_user = get_jwt_identity()
    if Config.KEYCLOAK_ORGANIZER_ROLE not in current_user["roles"]:
        logger.warning("Unauthorized organizer access attempt.")
        return jsonify({"msg": "Permission denied, organizer role required"}), 403
    return jsonify({"msg": "Welcome Organizer!"}), 200

@app.route("/api/verify-token", methods=["GET"])
@jwt_required()
def verify_token():
    user_identity = get_jwt_identity()
    logger.info(f"Token verified for user: {user_identity.get('email')}")
    return jsonify({
        "user_id": user_identity.get("email"),
        "roles": user_identity.get("roles")
    }), 200

@app.route("/email/<user_id>", methods=["GET"])
def get_email(user_id):
    keycloak_url = f"{Config.KEYCLOAK_SERVER_URL}/admin/realms/{Config.KEYCLOAK_REALM_NAME}/users/{user_id}"
    data = {
        "client_id": Config.KEYCLOAK_CLIENT_ID,
        "client_secret": Config.KEYCLOAK_CLIENT_SECRET,
        "grant_type": "client_credentials"
    }
    token_url = f"{Config.KEYCLOAK_SERVER_URL}/realms/{Config.KEYCLOAK_REALM_NAME}/protocol/openid-connect/token"

    try:
        token_response = requests.post(token_url, data=data)
        token_response.raise_for_status()
        access_token = token_response.json().get("access_token")

        headers = {"Authorization": f"Bearer {access_token}"}
        user_response = requests.get(keycloak_url, headers=headers)
        user_response.raise_for_status()

        user_data = user_response.json()
        email = user_data.get("email")

        if not email:
            return jsonify({"msg": "Email not found"}), 404
        return jsonify({"email": email}), 200

    except requests.exceptions.RequestException as e:
        logger.error(f"Error retrieving email for user {user_id}: {str(e)}")
        return jsonify({"msg": f"Error communicating with Keycloak: {e}"}), 500

if __name__ == "__main__":
    app.run(debug=True)
