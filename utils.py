from flask import current_app, session
from werkzeug.security import generate_password_hash
from models import get_db_connection
from functools import wraps
from flask import flash, redirect, url_for
import mailtrap as mt
from config import Config
from itsdangerous import URLSafeTimedSerializer
import requests

SECRET_KEY = Config.SECRET_KEY
serializer = URLSafeTimedSerializer(SECRET_KEY)

def send_password_via_email(email, password):
    mail = mt.Mail(
    sender=mt.Address(email="noreply.sireapp@sammie.ie", name="SireApp"),
    to=[mt.Address(email="noreply.sireapp@gmail.com")],
    subject="SireApp New User",
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
