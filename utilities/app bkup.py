from flask import Flask, render_template, request, redirect, url_for, flash, session
import secrets
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, TextAreaField, SubmitField, BooleanField
from wtforms.validators import InputRequired, Length, DataRequired, Email
import os
from functools import wraps
import pyotp
import requests

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

csrf = CSRFProtect(app)

def get_db_connection():
    db_path = os.path.join(os.getcwd(), 'sireapp.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS User (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT NOT NULL UNIQUE,
            Password TEXT NOT NULL,
            First_Name TEXT,
            Last_Name TEXT,
            Email TEXT,
            Role TEXT,
            Is_Admin INTEGER,
            Is_Manager INTEGER,
            Is_Responder INTEGER,
            Mfa_Secret TEXT,
            Mfa_Setup_Completed INTEGER DEFAULT 0
        );
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS Incident (
            ID TEXT PRIMARY KEY,
            Title TEXT NOT NULL,
            Description TEXT NOT NULL,
            Category TEXT NOT NULL,
            Severity TEXT NOT NULL,
            Status TEXT NOT NULL,
            Assigned_To TEXT NOT NULL,
            Reporter TEXT,
            Created_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            Updated_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        ''')
        conn.commit()

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=50)])

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Role', choices=[
        ('Administrator', 'Administrator'),
        ('Manager', 'Manager'),
        ('Responder', 'Responder'),
        ('Reporter', 'Reporter')
    ], validators=[InputRequired()])
    enable_mfa = BooleanField('Enable MFA')

class IncidentForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[InputRequired(), Length(max=500)])
    category = SelectField('Category', choices=[
        ('Malware', 'Malware'),
        ('Social Engineering', 'Social Engineering'),
        ('Unauthorized Access', 'Unauthorized Access'),
        ('Network Attack', 'Network Attack'),
        ('Data Breach', 'Data Breach'),
        ('Vulnerability', 'Vulnerability'),
        ('Physical Security', 'Physical Security'),
        ('Policy Violation', 'Policy Violation'),
        ('Insider Threat', 'Insider Threat'),
        ('Vendor-Related', 'Vendor-Related'),
        ('Email and Comm. Threat', 'Email and Comm. Threat'),
        ('Cryptojacking', 'Cryptojacking'),
        ('Compromised Device', 'Compromised Device'),
        ('Compliance Violation', 'Compliance Violation'),
        ('Other', 'Other')
    ], validators=[InputRequired()])
    severity = SelectField('Severity', choices=[
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical')
    ], validators=[InputRequired()])
    submit = SubmitField('Submit Incident')

def send_password_via_email(email, password):
    API_KEY = "YOUR_API_KEY"  # Securely store and use your Mailgun API key
    DOMAIN_NAME = "YOUR_DOMAIN_NAME"  # Securely store and use your Mailgun domain name

    url = f"https://api.mailgun.net/v3/{DOMAIN_NAME}/messages"
    
    data = {
        'from': 'SIREApp <noreply.sireapp@gmail.com>',
        'to': email,
        'subject': 'Your new sysadmin password',
        'text': f'Your new sysadmin password is: {password}'
    }

    try:
        response = requests.post(url, auth=("api", API_KEY), data=data)
        response.raise_for_status()  # Raise an error for bad responses
        print(f"Email sent to {email}.")
    except requests.exceptions.RequestException as e:
        print(f"Failed to send email: {e}")

def ensure_sysadmin_exists():
    try:
        with app.app_context():
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM User WHERE Username = ?', ('sysadmin',))
                user = cursor.fetchone()

                if not user:
                    random_password = secrets.token_urlsafe(16)
                    hashed_password = generate_password_hash(random_password)
                    sysadmin_data = ('sysadmin', hashed_password, 'System', 'Administrator', 'noreply.sireapp@gmail.com', 'Administrator', 1, 0, 0, None, 0)
                    cursor.execute(''' 
                        INSERT INTO User (Username, Password, First_Name, Last_Name, Email, Role, Is_Admin, Is_Manager, Is_Responder, Mfa_Secret, Mfa_Setup_Completed) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) 
                    ''', sysadmin_data)
                    conn.commit()
                    send_password_via_email('noreply.sireapp@gmail.com', random_password)
                    print("SysAdmin user created successfully. An email with the password has been sent.")

                else:
                    print("SysAdmin user already exists.")
    except Exception as e:
        print("An error occurred while ensuring the sysadmin exists:", str(e))

@app.route('/')
def home():
    return render_template('home.html')

def role_required(role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if 'role' not in session or session['role'] != role:
                flash('Unauthorized access.', 'danger')
                return redirect(url_for('home'))
            return func(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        with get_db_connection() as conn:
            user = conn.execute('SELECT * FROM User WHERE Username = ?', (username,)).fetchone()

            if user and check_password_hash(user['Password'], password):
                session['user_id'] = user['ID']
                if user['Role'] in ['Administrator', 'Manager']:
                    if not user['Mfa_Setup_Completed']:
                        return redirect(url_for('setup_mfa'))
                    elif user['Mfa_Secret']:
                        session['mfa_required'] = True
                        return redirect(url_for('mfa'))

                session.update({
                    'username': user['Username'],
                    'role': user['Role'],
                    'first_name': user['First_Name'],
                    'last_name': user['Last_Name'],
                    'is_admin': user['Is_Admin'],
                    'is_manager': user['Is_Manager'],
                    'is_responder': user['Is_Responder']
                })
                flash('Login successful!', 'success')
                return redirect(url_for('user_dashboard'))
            else:
                flash('Invalid username or password.', 'danger')

    return render_template('login.html', form=form)

@app.route('/setup_mfa', methods=['GET', 'POST'])
def setup_mfa():
    user = get_user_by_session()
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        mfa_secret = pyotp.random_base32()
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE User SET Mfa_Secret = ?, Mfa_Setup_Completed = 1 WHERE ID = ?', (mfa_secret, user['ID']))
            conn.commit()

        otp_auth_url = pyotp.totp.TOTP(mfa_secret).provisioning_uri(name=user['Username'], issuer='YourAppName')
        return render_template('mfa_setup_success.html', otp_auth_url=otp_auth_url)

    return render_template('setup_mfa.html')

@app.route('/mfa_verification', methods=['POST'])
def mfa_verification():
    user = get_user_by_session()
    if not user:
        return redirect(url_for('login'))

    otp = request.form.get('otp')
    if pyotp.TOTP(user['Mfa_Secret']).verify(otp):
        flash('MFA setup successful! You can now log in.', 'success')
        return redirect(url_for('user_dashboard'))
    else:
        flash('Invalid OTP. Please try again.', 'danger')
        return redirect(url_for('setup_mfa'))

@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if request.method == 'POST':
        otp = request.form.get('otp')
        user = get_user_by_session()
        if user and pyotp.TOTP(user['Mfa_Secret']).verify(otp):
            session.update({'username': user['Username'], 'role': user['Role'], 'first_name': user['First_Name'], 'last_name': user['Last_Name']})
            flash('Login successful!', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('mfa.html')

def get_user_by_session():
    user_id = session.get('user_id')
    if user_id:
        with get_db_connection() as conn:
            return conn.execute('SELECT * FROM User WHERE ID = ?', (user_id,)).fetchone()
    return None

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

@app.route('/report_incident', methods=['GET', 'POST'])
def report_incident():
    form = IncidentForm()
    if form.validate_on_submit():
        title = form.title.data
        description = form.description.data
        category = form.category.data
        severity = form.severity.data
        reporter = session.get('username', "Anonymous")
        assigned_to = "Unassigned"
        new_incident_id = generate_incident_id()

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO Incident (ID, Title, Description, Category, Severity, Status, Assigned_To, Reporter) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (new_incident_id, title, description, category, severity, "New", assigned_to, reporter)
            )
            conn.commit()

        return redirect(url_for('incident_reported', incident_id=new_incident_id))

    return render_template('report_incident.html', form=form)

def generate_incident_id():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT ID FROM Incident ORDER BY ID DESC LIMIT 1')
        last_incident = cursor.fetchone()
        last_id_number = int(last_incident[0][3:]) if last_incident else 999
        return f'INC{last_id_number + 1}'

@app.route('/incident-reported/<string:incident_id>')
def incident_reported(incident_id):
    return render_template('successful_report.html', incident_id=incident_id)

@app.route('/view_incidents')
def view_incidents():
    if 'user_id' in session:
        with get_db_connection() as conn:
            incidents = conn.execute('SELECT * FROM Incident').fetchall()
        return render_template('incidents.html', incidents=incidents)
    return redirect(url_for('home'))

@app.route('/admin_incidents')
@role_required('Administrator')
def admin_incidents():
    with get_db_connection() as conn:
        incidents = conn.execute('SELECT * FROM Incident').fetchall()
    return render_template('admin_incidents.html', incidents=incidents)

if __name__ == '__main__':
    initialize_db()
    with app.app_context():
        ensure_sysadmin_exists()
    app.run(debug=True)
