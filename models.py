import sqlite3
import os
from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy import Table, ForeignKey
from sqlalchemy.orm import relationship
import secrets
from werkzeug.security import generate_password_hash
import pyotp
import logging

db = SQLAlchemy()

assigned_users = Table(
    'assigned_users',
    db.Model.metadata,
    db.Column('incident_id', db.Integer, ForeignKey('Incident.ID'), primary_key=True),
    db.Column('username', db.String, ForeignKey('User.Username'), primary_key=True)
)


class User(db.Model, UserMixin):
    __tablename__ = 'User'

    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Username = db.Column(db.String, unique=True, nullable=False)
    Password = db.Column(db.String, nullable=False)
    First_Name = db.Column(db.String)
    Last_Name = db.Column(db.String)
    Email = db.Column(db.String)
    Role = db.Column(db.String)
    Manager = db.Column(db.String, default="")
    Is_Admin = db.Column(db.Boolean, default=False)
    Is_Manager = db.Column(db.Boolean, default=False)
    Is_Responder = db.Column(db.Boolean, default=False)
    Is_Test_User = db.Column(db.Boolean, default=False)
    MFA_Secret = db.Column(db.String)
    MFA_Setup_Completed = db.Column(db.Boolean, default=False)
    MFA_Required = db.Column(db.Boolean, default=False)
    First_Login_Completed = db.Column(db.Boolean, default=False)
    Security_Questions_Set = db.Column(db.Boolean, default=False)

    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.ID)




class Incident(db.Model):
    __tablename__ = 'Incident'

    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Title = db.Column(db.String, unique=True, nullable=False)
    Description = db.Column(db.String, nullable=False)
    Category = db.Column(db.String)
    Severity = db.Column(db.String)
    Status = db.Column(db.String, default='New')
    Reporter = db.Column(db.String, nullable=False)
    Created_At = db.Column(db.DateTime, default=db.func.current_timestamp())
    Updated_At = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    Is_Urgent = db.Column(db.Boolean, default=False)

    assigned_to = relationship('User', secondary=assigned_users, backref='incidents')

class WorkNote(db.Model):
    __tablename__ = 'WorkNote'

    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Incident_ID = db.Column(db.Integer, db.ForeignKey('Incident.ID'), nullable=False)
    Note = db.Column(db.String, nullable=False)
    Created_At = db.Column(db.DateTime, default=db.func.current_timestamp())
    Updated_At = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    Author = db.Column(db.String, db.ForeignKey('User.Username'), nullable=False)
    Is_Note_Private = db.Column(db.Boolean, default=False)

    incident = db.relationship('Incident', backref=db.backref('work_notes', lazy=True))

class SecurityQuestion(db.Model):
    __tablename__ = 'SecurityQuestion'

    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Question_Text = db.Column(db.String, nullable=False)
    Is_Active = db.Column(db.Boolean, default=True)

class SecurityAnswer(db.Model):
    __tablename__ = 'SecurityAnswer'

    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    User_ID = db.Column(db.Integer, db.ForeignKey('User.ID'), nullable=False)
    Question_ID = db.Column(db.Integer, db.ForeignKey('SecurityQuestion.ID'), nullable=False)
    Answer_Text = db.Column(db.String, nullable=False)

    user = db.relationship('User', backref=db.backref('security_answers', lazy=True))
    security_question = db.relationship('SecurityQuestion', backref=db.backref('security_answers', lazy=True))

def get_db_connection():
    db_path = current_app.config['DATABASE']
    logging.debug(f"Database path: {db_path}")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_db(app):
    with app.app_context():
        db.init_app(app)
        db.create_all()

def ensure_sysadmin_exists(app):
    from utils import send_password_via_email
    try:
        with app.app_context():
            user = User.query.filter_by(Username='sysadmin').first()

            if not user:
                random_password = secrets.token_urlsafe(16)
                hashed_password = generate_password_hash(random_password)


                MFA_Secret = pyotp.random_base32()


                sysadmin = User(
                    Username='sysadmin',
                    Password=hashed_password,
                    First_Name='System',
                    Last_Name='Administrator',
                    Email='sammiejennings09@gmail.com',
                    Role='Administrator',
                    Manager='hosimpson',
                    Is_Admin=True,
                    Is_Manager=True,
                    Is_Responder=False,
                    Is_Test_User=False,
                    MFA_Secret=MFA_Secret,
                    MFA_Setup_Completed=False,
                    MFA_Required=True,
                    First_Login_Completed=False,
                    Security_Questions_Set=False
                )


                db.session.add(sysadmin)
                db.session.commit()


                otp_auth_url = pyotp.totp.TOTP(MFA_Secret).provisioning_uri(name='sysadmin')
                print(f"OTP Auth URL for sysadmin: {otp_auth_url}")


                send_password_via_email(sysadmin.Email, random_password, sysadmin.Username)
                print("SysAdmin user created successfully. An email with the password has been sent.")
            else:
                print("SysAdmin user already exists.")
    except Exception as e:
        print("An error occurred while ensuring the sysadmin exists:", str(e))

def create_test_admin(app):
    from utils import send_password_via_email
    try:
        with app.app_context():
            user = User.query.filter_by(Username='testadmin').first()

            if not user:
                random_password = secrets.token_urlsafe(16)
                hashed_password = generate_password_hash(random_password)


                MFA_Secret = pyotp.random_base32()


                testadmin = User(
                    Username='testadmin',
                    Password=hashed_password,
                    First_Name='Test',
                    Last_Name='Admin',
                    Email='noreply.sireapp@gmail.com',
                    Role='Administrator',
                    Manager='sysadmin',
                    Is_Admin=True,
                    Is_Manager=True,
                    Is_Responder=False,
                    Is_Test_User=True,
                    MFA_Secret=MFA_Secret,
                    MFA_Setup_Completed=True,
                    MFA_Required=False,
                    First_Login_Completed=True,
                    Security_Questions_Set=True
                )


                db.session.add(testadmin)
                db.session.commit()


                otp_auth_url = pyotp.totp.TOTP(MFA_Secret).provisioning_uri(name='testadmin')


                send_password_via_email(testadmin.Email, random_password, testadmin.Username)
                print("Test admin created successfully. An email with the password has been sent.")
            else:
                print("Test admin already exists.")
    except Exception as e:
        print("An error occurred while ensuring the testadmin exists:", str(e))


def create_test_manager(app):
    from utils import send_password_via_email
    try:
        with app.app_context():
            user = User.query.filter_by(Username='testmanager').first()

            if not user:
                random_password = secrets.token_urlsafe(16)
                hashed_password = generate_password_hash(random_password)


                MFA_Secret = pyotp.random_base32()


                testmanager = User(
                    Username='testmanager',
                    Password=hashed_password,
                    First_Name='Test',
                    Last_Name='Manager',
                    Email='noreply.sireapp@gmail.com',
                    Role='Manager',
                    Manager='sysadmin',
                    Is_Admin=False,
                    Is_Manager=True,
                    Is_Responder=False,
                    Is_Test_User=True,
                    MFA_Secret=MFA_Secret,
                    MFA_Setup_Completed=False,
                    MFA_Required=True,
                    First_Login_Completed=False,
                    Security_Questions_Set=False
                )


                db.session.add(testmanager)
                db.session.commit()


                otp_auth_url = pyotp.totp.TOTP(MFA_Secret).provisioning_uri(name='testmanager')


                send_password_via_email(testmanager.Email, random_password, testmanager.Username)
                print("Test manager created successfully. An email with the password has been sent.")
            else:
                print("Test manager already exists.")
    except Exception as e:
        print("An error occurred while ensuring the testmanager exists:", str(e))

def create_test_responder(app):
    from utils import send_password_via_email
    try:
        with app.app_context():
            user = User.query.filter_by(Username='testresponder').first()

            if not user:
                random_password = secrets.token_urlsafe(16)
                hashed_password = generate_password_hash(random_password)


                MFA_Secret = pyotp.random_base32()


                testresponder = User(
                    Username='testresponder',
                    Password=hashed_password,
                    First_Name='Test',
                    Last_Name='Responder',
                    Email='noreply.sireapp@gmail.com',
                    Role='Manager',
                    Manager='testmanager',
                    Is_Admin=False,
                    Is_Manager=False,
                    Is_Responder=True,
                    Is_Test_User=True,
                    MFA_Secret=MFA_Secret,
                    MFA_Setup_Completed=False,
                    MFA_Required=True,
                    First_Login_Completed=False,
                    Security_Questions_Set=False
                )


                db.session.add(testresponder)
                db.session.commit()


                otp_auth_url = pyotp.totp.TOTP(MFA_Secret).provisioning_uri(name='testresponder')


                send_password_via_email(testresponder.Email, random_password, testresponder.Username)
                print("Test responder created successfully. An email with the password has been sent.")
            else:
                print("Test responder already exists.")
    except Exception as e:
        print("An error occurred while ensuring the testresponder exists:", str(e))

