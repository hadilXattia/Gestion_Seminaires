from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

db = SQLAlchemy()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.Config')

    db.init_app(app)
    migrate.init_app(app, db)

    from app.routes import bp
    app.register_blueprint(bp)

    return app



# http://127.0.0.1:5000/reservations/101?date=2024-11-26 14:00:00&duree=2
# http://127.0.0.1:5000/reservations?utilisateur_id=1&seminaire_id=101&date=2024-11-24 10:00:00&duree=2