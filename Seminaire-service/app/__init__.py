from flask import Flask
from flask_migrate import Migrate  # Import Migrate
from app.db import init_db, db  # Assuming `db` is the SQLAlchemy object in app.db


def create_app():
    app = Flask(__name__)

    # Configurations
    app.config["SQLALCHEMY_DATABASE_URI"] = (
        "postgresql://postgres:Hadil123@postgres_db:5432/seminars"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Initialize the database
    init_db(app)

    # Initialize Flask-Migrate
    migrate = Migrate(app, db)  # Passing app and db to Migrate

    # Register routes
    from app.routes import seminar_bp

    app.register_blueprint(seminar_bp, url_prefix="/api/seminaires")

    return app
