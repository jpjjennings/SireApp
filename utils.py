import requests
from flask import current_app, session
from werkzeug.security import generate_password_hash
from models import get_db_connection, Incident
from functools import wraps
from flask import flash, redirect, url_for
import mailtrap as mt
from config import Config
from itsdangerous import URLSafeTimedSerializer
import requests
from flask import current_app
import secrets
import string

SECRET_KEY = Config.SECRET_KEY
serializer = URLSafeTimedSerializer(SECRET_KEY)

def send_password_via_email(email, password, username):
    mail = mt.Mail(
    sender=mt.Address(email="noreply.sireapp@sammie.ie", name="SireApp"),
    to=[mt.Address(email=email)],
    subject=f"SireApp New User {username}",
    text=f"Your password is: {password}",
    category="SireApp",
)
    client = mt.MailtrapClient(token="b954472180f797a68cdfb8bc2dd116b9")
    response = client.send(mail)

    print(response)

def password_reset_via_email(email):
    token = serializer.dumps(email, salt='password-reset-salt')

    reset_url = f"http://localhost:5000/reset_password/{token}"

    mail = mt.Mail(
    sender=mt.Address(email="noreply.sireapp@sammie.ie", name="SireApp"),
    to=[mt.Address(email=email)],
    subject="SireApp Password Reset",
    text=f"Click the link to reset your password: {reset_url}",
    category="SireApp",
)
    client = mt.MailtrapClient(token="b954472180f797a68cdfb8bc2dd116b9")
    response = client.send(mail)

    print(response)

def user_password_no_security_q_set(email, temporary_password):

    mail = mt.Mail(
    sender=mt.Address(email="noreply.sireapp@sammie.ie", name="SireApp"),
    to=[mt.Address(email=email)],
    subject="SireApp Password Generation",
    text=f"Your administrator has set a new password for you. Please use the following password to login: \n\n----------------------------\n{temporary_password}\n----------------------------\n\nPlease change your password as soon as you login.",
    category="SireApp",
)
    client = mt.MailtrapClient(token="b954472180f797a68cdfb8bc2dd116b9")
    response = client.send(mail)

    print(response)

def notify_assign_via_email(email, first_name, incident):
    incident_id = incident.ID
    title = incident.Title
    desc = incident.Description
    severity = incident.Severity
    mail = mt.Mail(
    sender=mt.Address(email="noreply.sireapp@sammie.ie", name="SireApp"),
    to=[mt.Address(email=email)],
    subject=f"Incident {incident} has been assigned to you",
    text=f"{first_name},\n\n Incident {incident_id} has been assigned to you. \n\n Incident Title: {title} \n\n Incident Description: {desc} \n\n Incident Severity: {severity} \n\n Please review this incident as soon as possible. \n\n Link: https://sireapp.sammie.ie/incident/{incident_id}",
    category="SireApp",
)
    client = mt.MailtrapClient(token="b954472180f797a68cdfb8bc2dd116b9")
    response = client.send(mail)

    print(response)




def get_user_by_session():
    user_id = session.get('user_id')
    if user_id:
        with get_db_connection() as conn:
            return conn.execute('SELECT * FROM User WHERE ID = ?', (user_id,)).fetchone()
    return None

def role_required(role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if 'role' not in session or session['role'] != role:
                flash('Unauthorized access.', 'danger')
                return redirect(url_for('main.home'))
            return func(*args, **kwargs)
        return wrapper
    return decorator
