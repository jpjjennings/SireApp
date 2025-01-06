from flask import Flask
from config import Config
from models import initialize_db, ensure_sysadmin_exists, User, db, create_test_admin, create_test_manager, create_test_responder
from routes import app as main_routes
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

login_manager = LoginManager()

def create_app():
    app = Flask(__name__, template_folder='/home/SireApp/sireapp/templates')
    app.config.from_object(Config)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/SireApp/sireapp/sireapp.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    login_manager.init_app(app)

    initialize_db(app)
    ensure_sysadmin_exists(app)
    create_test_admin(app)
    create_test_manager(app)
    create_test_responder(app)

    app.register_blueprint(main_routes)
    if Config.DEBUG_MODE:
        print("SireApp is running in DEBUG mode.")

    print("Templates Folder:", app.template_folder)

    return app

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

app = create_app()

if __name__ == '__main__':
    app.run(debug=False)