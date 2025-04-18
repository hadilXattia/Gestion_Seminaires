from flask_sqlalchemy import SQLAlchemy

# Instantiate the db object
db = SQLAlchemy()

def init_db(app):
    # Initialize the db object with the app
    db.init_app(app)
