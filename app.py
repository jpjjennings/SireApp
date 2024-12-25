from flask import Flask
from config import Config
from models import initialize_db, ensure_sysadmin_exists, User, db
from routes import app as main_routes
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/james/Desktop/FYP_Report/SireApp/sireapp.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    
    login_manager.init_app(app)

    initialize_db(app)
    ensure_sysadmin_exists(app)

    app.register_blueprint(main_routes)
    if Config.DEBUG_MODE:
        print("SireApp is running in DEBUG mode.")

    return app

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

app = create_app()

if __name__ == '__main__':
    app.run(debug=False)