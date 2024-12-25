from flask import Blueprint, render_template, request, session, redirect, url_for, flash, abort
from flask_login import current_user, login_required, login_user, logout_user
from forms import LoginForm, UserForm, IncidentForm, SecurityQuestionForm, AdminResetPasswordForm
from models import get_db_connection, User, db, Incident, WorkNote, assigned_users, SecurityQuestion, SecurityAnswer
from utils import get_user_by_session, serializer, password_reset_via_email, mt, user_password_no_security_q_set
from config import Config
from werkzeug.security import check_password_hash, generate_password_hash
import pyotp
from functools import wraps
from utils import role_required
import secrets
from forms import IncidentForm, UserForm, LoginForm, LogoutForm, DeleteUserForm, AddUserForm, EditUserForm
from datetime import datetime
import logging

app = Blueprint('main', __name__)

current_time = datetime.now()
""" current_formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S") """

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/')
def home():
    return render_template('home.html')

#*Login*

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        if Config.DEBUG_MODE:
            print("Username entered:", username)
            print("Password entered")
        password = form.password.data
        
        try:
            user = User.query.filter_by(Username=username).first()
            print("User found:", user)

            if user and check_password_hash(user.Password, password):
                login_user(user)
                if Config.DEBUG_MODE:
                    print("User logged in as:", user)
                
                if not user.Security_Questions_Set:
                    print("Security questions not set. Redirecting to set_security_questions.")
                    return redirect(url_for('main.set_security_questions'))
                elif user.Role in ['Administrator', 'Manager', 'Responder']:
                    print("User is an admin, manager or responder. Redirecting to MFA verification.")
                    if not user.MFA_Setup_Completed:
                        print("MFA setup not completed. Redirecting to setup_MFA.")
                        return redirect(url_for('main.setup_MFA'))
                    elif user.MFA_Secret:
                        print("MFA Secret found. Redirecting to MFA verification.")
                        session['MFA_Required'] = True
                        return redirect(url_for('main.MFA'))

                flash('Login successful!', 'success')
                print("Loging successful. Redirecting to user_dashboard.")
                return redirect(url_for('main.user_dashboard'))
            else:
                flash('Invalid username or password.', 'danger')
                if Config.DEBUG_MODE:
                    print("Invalid username or password.")
                
        except Exception as e:
            flash('Login failed. Please try again.', 'danger')
            print("Login failed. Error:")
            print(e)

    return render_template('login.html', form=form)


#*MFA*

@app.route('/setup_MFA', methods=['GET', 'POST'])
@login_required
def setup_MFA():

    user = current_user
    if Config.DEBUG_MODE:
        print("User found:", user)

    if user:
        if request.method == 'POST':
            if 'complete_setup' in request.form:
                otp = request.form.get('otp')
                
                if user.MFA_Secret:
                    if pyotp.TOTP(user.MFA_Secret).verify(otp):
                        try:
                            user.MFA_Setup_Completed = True
                            db.session.commit()
                            flash('MFA setup completed successfully!', 'success')
                            return redirect(url_for('main.user_dashboard'))
                        except Exception as e:
                            flash('Failed to update MFA status. Please try again.', 'danger')
                            print(e)
                    else:
                        flash('Invalid OTP. Please try again.')
                else:
                    flash('MFA secret is not set. Please contact support.', 'danger')

        if user.MFA_Secret:
            otp_auth_url = create_otp_auth_url(user.MFA_Secret)
            return render_template('setup_MFA.html', MFA_Setup_Completed=False, otp_auth_url=otp_auth_url)

    flash('MFA secret not found. Please contact support.', 'danger')
    return render_template('setup_MFA.html', MFA_Setup_Completed=False)


    
def create_otp_auth_url(MFA_Secret):
    base_url = "otpauth://totp/"
    label = "SireApp"
    uri = f"{base_url}{label}?secret={MFA_Secret}&issuer=SireApp"
    if Config.DEBUG_MODE:
        print("OTP Auth URL:", uri)
    return uri
    
@app.route('/MFA_verification', methods=['POST'])
def MFA_verification():
    try:
        user = get_user_by_session()
        if not user:
            flash('User not found, please log in.', 'danger')
            return redirect(url_for('main.login'))

        otp = request.form.get('otp')
        if user and user.MFA_Setup_Completed:
            if pyotp.TOTP(user.MFA_Secret).verify(otp):
                session.update({
                    'Username': user.Username,
                    'Role': user.Role,
                    'First_Name': user.First_Name,
                    'Last_Name': user.Last_Name
                })
                flash('Login successful!', 'success')
                return redirect(url_for('main.user_dashboard'))
            else:
                flash('Invalid OTP. Please try again.', 'danger')
                return render_template('MFA_failed.html')
        else:
            flash('MFA setup not completed. Please complete setup before logging in.', 'danger')
            return redirect(url_for('main.setup_MFA'))
    except Exception as e:
        flash('An error occurred during MFA verification. Please try again.', 'danger')
        print(f"Error: {e}")
        return redirect(url_for('main.login'))



@app.route('/MFA', methods=['GET', 'POST'])
def MFA():
    if request.method == 'POST':
        otp = request.form.get('otp')
        user = get_user_by_session()
        MFA_setup_completed = user['MFA_Setup_Completed']
        if MFA_setup_completed:
            if user and pyotp.TOTP(user['MFA_Secret']).verify(otp):
                session.update({key: user[key] for key in ['Username', 'Role', 'First_Name', 'Last_Name']})
                flash('Login successful!', 'success')
                return redirect(url_for('main.user_dashboard'))
            else:
                flash('Invalid OTP. Please try again.', 'danger')
                return render_template('MFA_failed.html')
        else:
            flash('MFA setup not completed. Please complete setup before logging in.', 'danger')
            return redirect(url_for('main.setup_MFA'))

    return render_template('MFA.html')

@app.route('/setup_MFA_help')
def setup_MFA_help():
    return render_template('setup_MFA_help.html')

@app.route('/MFA_failed')
def MFA_failed():
    return render_template('MFA_failed.html')

#*Get_User*
def get_user_by_session():
    if current_user.is_authenticated:
        if Config.DEBUG_MODE:
            print("User found in session:", current_user)
        return current_user

    if 'reset_email' in session:
        if Config.DEBUG_MODE:
            print("Reset email found in session:", session['reset_email'])
        return User.query.filter_by(Email=session['reset_email']).first()
    
    
    if Config.DEBUG_MODE:
        print("No user found in session.")

    return None

#*Password_Reset*
@app.route('/request_reset', methods=['GET', 'POST'])
def request_reset():
    if request.method == 'POST':
        email = request.form.get('email')
        if Config.DEBUG_MODE:
            print("Email entered:", email)
        
        user = User.query.filter_by(Email=email).first()
        if Config.DEBUG_MODE:
            print("User found:", user)

        if user:
            password_reset_via_email(email)
            
            flash('A password reset link has been sent to your email.', 'success')
            return redirect(url_for('main.login'))
        else:
            flash('Email not found. Please enter a valid email address.', 'danger')

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
        session['reset_email'] = email
        if Config.DEBUG_MODE:
            print("Reset email found in token:", email)
            print("Reset email found in session:", session['reset_email'])
    except Exception:
        flash('Invalid or expired token. Please try again.', 'danger')
        return redirect(url_for('main.login'))

    user = User.query.filter_by(Email=email).first()
    if user is None:
        flash('User not found. Please try again.', 'danger')
        return redirect(url_for('main.login'))
    
    security_questions_set = user.Security_Questions_Set
    first_login = not user.First_Login_Completed
    if Config.DEBUG_MODE:
        print("Security questions set:", security_questions_set)
        print("First login:", first_login)

    if not security_questions_set and not first_login:
        flash('Something went wrong. Please contact your system administrator.', 'danger')
        return redirect(url_for('main.login'))


    verified = user.Role == 'Reporter'
    if Config.DEBUG_MODE:
        print("Reset email verified:", verified)

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        if Config.DEBUG_MODE:
            print("New password entered")
        if not new_password:
            flash('Please provide a new password.', 'warning')
            return render_template('reset_password.html', email=email, verified=verified)

        hashed_password = generate_password_hash(new_password)
        if Config.DEBUG_MODE: 
            print("Hashed password generated")

        try:
            if user.Role in ['Administrator', 'Manager', 'Responder']:
                if Config.DEBUG_MODE:
                    print("User is an admin, manager or responder. Proceeding to MFA verification.")
                return password_reset_MFA()
            elif user.Role == 'Reporter':
                if Config.DEBUG_MODE:
                    print("User is a reporter. Proceeding to Reset Password.")
                user.Password = hashed_password
                db.session.commit()
                flash('Password reset successful! You can now log in with your new password.', 'info')
                return redirect(url_for('main.login'))
            else:
                flash('Invalid user role. Please try again.', 'danger')
                
        except Exception as e:
            db.session.rollback()
            flash('Failed to reset password. Please try again.', 'danger')
            print(f"Error: {e}")

    return render_template('reset_password.html', email=email, verified=verified)


@app.route('/password_reset_MFA', methods=['POST'])
def password_reset_MFA():
    try:
        email = request.form.get('email')
        if Config.DEBUG_MODE:
            print("Email entered:", email)
        otp = request.form.get('otp')
        session['reset_email'] = email
        if Config.DEBUG_MODE:
            print("Reset email found in session:", session['reset_email'])

        user = User.query.filter_by(Email=email).first()
        if Config.DEBUG_MODE:
            print("User found:", user)
        
        if not user:
            if Config.DEBUG_MODE:
                print("User not found.")
            flash('User not found, please log in.', 'danger')
            return redirect(url_for('main.login'))

        if not user.MFA_Setup_Completed:
            if Config.DEBUG_MODE:
                print("MFA setup not completed.")
            flash('MFA setup not completed. Please complete setup before logging in.', 'danger')
            return redirect(url_for('main.setup_MFA'))

        if pyotp.TOTP(user.MFA_Secret).verify(otp):
            if Config.DEBUG_MODE:
                print("MFA verification successful.")
            flash('MFA verification successful! You can now reset your password.', 'success')
            return redirect(url_for('reset_password_after_MFA'))

        flash('Invalid OTP. Please try again.', 'danger')
        if Config.DEBUG_MODE:
            print("Invalid OTP from user.")
        return render_template('MFA_failed.html')

    except Exception as e:
        flash('An error occurred during MFA verification. Please try again.', 'danger')
        print(f"Error: {e}")
        return redirect(url_for('main.login'))

@app.route('/reset_password_after_security_verification', methods=['GET', 'POST'])
def reset_password_after_security_verification():
    email = session.get('reset_email')
    if Config.DEBUG_MODE:
        print("Reset email found in session:", email)
    verified = True

    if not email:
        if Config.DEBUG_MODE:
            print("Reset email not found in session.")
        flash('Reset email is not set. Please request a new password reset link.', 'danger')
        return redirect(url_for('main.request_reset'))

    user = User.query.filter_by(Email=email).first()
    if Config.DEBUG_MODE:
        print("User found:", user)
    if user is None:
        if Config.DEBUG_MODE:
            print("User not found.")
        flash('User not found. Please try again.', 'danger')
        return redirect(url_for('main.request_reset'))
    
    if user.Role in ['Administrator', 'Manager', 'Responder']:
        if Config.DEBUG_MODE:
            print("User is an admin, manager or responder. Redirecting to MFA verification.")
        return redirect(url_for('password_reset_MFA'))
    elif user.Role == 'Reporter':
        if Config.DEBUG_MODE:
            print("User is a reporter. Proceeding to Reset Password.")
        return redirect(url_for('reset_password_after_MFA'))
    else:
        if Config.DEBUG_MODE:
            print("Invalid user role.")
        flash('Invalid user role. Please try again.', 'danger')
        

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        if Config.DEBUG_MODE:
            print("New password entered")
        
        if new_password:
            try:
                user.Password = generate_password_hash(new_password)
                db.session.commit()
                if Config.DEBUG_MODE:
                    print("Password reset successful!")
                flash('Password reset successful! You can now log in with your new password.', 'info')
                if Config.DEBUG_MODE:
                    print("Clearing reset_email from session.")
                    print("Redirecting to login page.")
                session.pop('reset_email', None)
                return redirect(url_for('main.login'))
            except Exception as e:
                db.session.rollback()
                flash('Failed to reset password. Please try again.', 'danger')
                print(f"Error: {e}")
        else:
            flash('Please provide a new password.', 'warning')
            if Config.DEBUG_MODE:
                print("No new password provided.")

    
    return render_template('reset_password.html', email=email, verified=verified)

    
@app.route('/reset_password_after_MFA', methods=['GET', 'POST'])
@login_required  
def reset_password_after_MFA():
    
    user = current_user
    if Config.DEBUG_MODE:
        print("User found:", user)

    if not user:
        if Config.DEBUG_MODE:
            print("User not found.")
        flash('User not found. Please request a new password reset link.', 'danger')
        return redirect(url_for('main.request_reset'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        print("New password entered")

        if new_password:
            try:
                user.Password = generate_password_hash(new_password)
                if Config.DEBUG_MODE:
                    print("Hashed password generated")
                db.session.commit()
                if Config.DEBUG_MODE:
                    print("DB Commit successful!")
                flash('Password reset successful! You can now log in with your new password.', 'info')
                if Config.DEBUG_MODE:
                    print("Password reset successful for user:", user.Username)
                return redirect(url_for('main.login'))
            except Exception as e:
                db.session.rollback()
                flash('Failed to reset password. Please try again.', 'danger')
                print(f"Error: {e}")
        else:
            flash('Please provide a new password.', 'warning')

    return render_template('reset_password.html', email=user.Email)


#*Security_Questions*
@app.route('/verify_security_questions', methods=['GET', 'POST'])
@login_required
def verify_security_questions():
    user = current_user
    email = user.Email
    security_questions_set = user.Security_Questions_Set
    if Config.DEBUG_MODE:
        print("Security questions set:", security_questions_set)
        print("Current user email:", email)

    if not security_questions_set:
        if Config.DEBUG_MODE:
            print(f"Security questions not set for {user}")
        flash('Something went wrong. Please contact your system administrator.', 'danger')
        return redirect(url_for('main.request_reset'))

    if not user:
        if Config.DEBUG_MODE:
            print("User not found.")
        flash('User not found. Please try again.', 'danger')
        return redirect(url_for('main.request_reset'))

    form = SecurityQuestionForm()

    if request.method == 'POST':
        answer_1 = request.form.get('answer_1').lower()
        answer_2 = request.form.get('answer_2').lower()
        answer_3 = request.form.get('answer_3').lower()
        if Config.DEBUG_MODE:
            print(f"{user} Answer 1:", answer_1)
            print(f"{user} Answer 2:", answer_2)
            print(f"{user} Answer 3:", answer_3)

        if (user.security_answers[0].Answer_Text.lower() == answer_1 and
            user.security_answers[1].Answer_Text.lower() == answer_2 and
            user.security_answers[2].Answer_Text.lower() == answer_3):
            if Config.DEBUG_MODE:
                print(f"{user} Security questions verified successfully.")
            return redirect(url_for('reset_password_after_security_verification'))
        else:
            if Config.DEBUG_MODE:
                print(f"{user} Security questions verification failed.")
            flash('One or more answers are incorrect. Please try again.', 'danger')

    return render_template('verify_security_questions.html', email=email, security_questions=user.security_answers)
@app.route('/set_security_questions', methods=['GET', 'POST'])
@login_required
def set_security_questions():

    form = SecurityQuestionForm()
    user = current_user
    if Config.DEBUG_MODE:
        print("Current user:", user)
    
    if not user.is_authenticated:
        if Config.DEBUG_MODE:
            print("User not found.")
        flash('User not found.', 'danger')
        return redirect(url_for('main.login'))

    if form.validate_on_submit():
        for i in range(1, 4):
            question_text = form[f'question_{i}'].data
            answer_text = form[f'answer_{i}'].data
            if Config.DEBUG_MODE:
                print(f"Question {i}: {question_text}")
                print(f"Answer {i}: {answer_text}")
            
            
            if question_text and answer_text:
                security_question = SecurityQuestion.query.filter_by(Question_Text=question_text).first()
                if Config.DEBUG_MODE:
                    print("Security question found:", security_question)
                if not security_question:
                    if Config.DEBUG_MODE:
                        print("Security question not found. Creating new question.")
                    security_question = SecurityQuestion(Question_Text=question_text)
                    db.session.add(security_question)
                    if Config.DEBUG_MODE:
                        print("New security question added to database:", security_question)
                    db.session.commit()
                    if Config.DEBUG_MODE:
                        print("DB Commit successful!")
                
                
                user_answer = SecurityAnswer(User_ID=user.ID, Question_ID=security_question.ID, Answer_Text=answer_text)
                db.session.add(user_answer)
                if Config.DEBUG_MODE:
                    print("New security answer added to database:", user_answer)

        user.Security_Questions_Set = True 
        if Config.DEBUG_MODE:
            print("Security_Questions_Set attribute updated for user:", user)
        
        db.session.commit()
        if Config.DEBUG_MODE:
            print("DB Commit successful!")
        
        flash('Security questions set up successfully!', 'success')
        if Config.DEBUG_MODE:
            print("Security questions set up successfully for user:", user)
        if user.MFA_Setup_Completed:
            if session.get('MFA_Required', False):
                if Config.DEBUG_MODE:
                    print("MFA required. Redirecting to MFA verification.")
                return redirect(url_for('main.MFA'))
            else:
                if Config.DEBUG_MODE:
                    print("MFA not required. Redirecting to user dashboard.")
                return redirect(url_for('main.user_dashboard'))
        else:
            if Config.DEBUG_MODE:
                print("MFA not setup. Redirecting to MFA setup.")
            return redirect(url_for('main.setup_MFA'))

    return render_template('set_security_questions.html', form=form)

#*Logout*
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    if Config.DEBUG_MODE:
        print("User logged out successfully.")
    flash("You have been logged out.", "success")
    return redirect(url_for('main.login'))

#*Analytics*
@app.route('/analytics')
@login_required
def analytics():
    if current_user.Role not in ["Administrator", "Manager"]:
        if Config.DEBUG_MODE:
            print("User not authorized to view analytics. User role:", current_user.Role)
        flash("You are not authorized to view this page.", "danger")
        return redirect(url_for('main.user_dashboard'))

    try:
        incident_count = Incident.query.count()
        open_incident_count = Incident.query.filter_by(Status='Open').count()
        resolved_incident_count = Incident.query.filter_by(Status='Resolved').count()
        if Config.DEBUG_MODE:
            print("Incident count:", incident_count)
            print("Open incident count:", open_incident_count)
            print("Resolved incident count:", resolved_incident_count)

        severity_data = (db.session.query(Incident.Severity, db.func.count(Incident.ID))
                         .group_by(Incident.Severity).all())
        if Config.DEBUG_MODE:
            print("Severity data calculated")
        severity_pie_chart = {
            "data": [{
                "values": [row[1] for row in severity_data],
                "labels": [row[0] for row in severity_data],
                "type": "pie"
            }],
            "layout": {"title": "Severity Distribution"}
        }
        if Config.DEBUG_MODE:
            print("Severity pie chart generated")

        trend_data = (db.session.query(Incident.Created_At, db.func.count(Incident.ID))
                      .group_by(Incident.Created_At).all())
        if Config.DEBUG_MODE:
            print("Trend data calculated")
        incident_trend_chart = {
            "data": [{
                "x": [row[0] for row in trend_data],
                "y": [row[1] for row in trend_data],
                "type": "scatter",
                "mode": "lines+markers"
            }],
            "layout": {"title": "Incident Trends Over Time", "xaxis": {"title": "Date"}, "yaxis": {"title": "Incidents"}}
        }
        if Config.DEBUG_MODE:
            print("Incident trend chart generated")

        category_data = (db.session.query(Incident.Category, db.func.count(Incident.ID))
                         .group_by(Incident.Category).all())
        if Config.DEBUG_MODE:
            print("Category data calculated")
        category_bar_chart = {
            "data": [{
                "x": [row[0] for row in category_data],
                "y": [row[1] for row in category_data],
                "type": "bar"
            }],
            "layout": {"title": "Incident Categories", "xaxis": {"title": "Category"}, "yaxis": {"title": "Incidents"}}
        }
        if Config.DEBUG_MODE:
            print("Category bar chart generated")

        return render_template(
            'analytics.html',
            incident_count=incident_count,
            open_incident_count=open_incident_count,
            resolved_incident_count=resolved_incident_count,
            severity_pie_chart=severity_pie_chart,
            incident_trend_chart=incident_trend_chart,
            category_bar_chart=category_bar_chart
        )
    except Exception as e:
        flash('Failed to retrieve analytics data.', 'danger')
        print(f"Error: {e}")
        return redirect(url_for('main.user_dashboard'))


#*Report_Incident*
@app.route('/report_incident', methods=['GET', 'POST'])
def report_incident():
    form = IncidentForm()
    if form.validate_on_submit():
        title = form.title.data
        description = form.description.data
        category = form.category.data
        severity = form.severity.data
        status = "New"
       
        reporter = current_user.Username if current_user.is_authenticated else "Anonymous"
        
        is_urgent = severity in ["High", "Critical"]

        if Config.DEBUG_MODE:

            logger.info(f"Title: {title}, Description: {description}, Category: {category}, Severity: {severity}, Reporter: {reporter}, Is_Urgent: {is_urgent}")

        try:
            new_incident = Incident(
                Title=title,
                Description=description,
                Category=category,
                Severity=severity,
                Status=status,
                Reporter=reporter,
                Is_Urgent=is_urgent
            )
            db.session.add(new_incident)
            db.session.flush()
            if Config.DEBUG_MODE:
                print("DB flush successful!")
            db.session.commit()
            if Config.DEBUG_MODE:
                print("DB commit successful!")

            return redirect(url_for('main.incident_reported', incident_id=new_incident.ID))
        except Exception as e:
            db.session.rollback()
            flash('Incident reporting failed. Please try again.', 'danger')
            logger.error(f"Error reporting incident: {e}, Title: {title}, Description: {description}, Category: {category}, Severity: {severity}, Reporter: {reporter}, Is_Urgent: {is_urgent}")

    return render_template('report_incident.html', form=form)




#*Generate_Incident_ID*
def generate_incident_id():
    try:
        last_incident = db.session.query(Incident.ID).order_by(Incident.ID.desc()).first()
        if Config.DEBUG_MODE:
            print("Last incident found:", last_incident)
        
        last_id_number = last_incident.ID if last_incident else 999
        if Config.DEBUG_MODE:
            print("Last ID number:", last_id_number)


        new_id_number = last_id_number + 1
        if Config.DEBUG_MODE:
            print("New ID number:", new_id_number)

        return new_id_number
    except Exception as e:
        print(e)
        return 100


#*Incident_Reported*
@app.route('/incident-reported/<string:incident_id>')
def incident_reported(incident_id):
    return render_template('successful_report.html', incident_id=incident_id)

#*View_Incidents*
@app.route('/view_incidents')
def view_incidents():
    user = current_user
    if Config.DEBUG_MODE:
        print("Current user:", user)
    if user.is_authenticated:
        form = IncidentForm()
    
        incidents = Incident.query.all()
        if Config.DEBUG_MODE:
            print("Incidents fetched successfully.")

        return render_template('incidents.html', incidents=incidents, form=form)
    else:
        return redirect(url_for('main.user_dashboard'))

#*View_Specific_Incident*    
@app.route('/incident/<int:incident_id>', methods=['GET', 'POST'])
def view_incident(incident_id):
    incident = Incident.query.get(incident_id)
    is_urgent = incident.Is_Urgent
    if Config.DEBUG_MODE:
        print("Incident found:", incident)
        print("Is urgent:", is_urgent)
    if is_urgent:
        flash("High Priority Incident.", "error")
    if incident is None:
        if Config.DEBUG_MODE:
            print("Incident not found. 404 error.")
        abort(404)
    if request.method == 'POST':
        note_content = request.form.get('note')
        if Config.DEBUG_MODE:
            print("Note content found")
        if note_content:
            new_work_note = WorkNote(Incident_ID=incident.ID, Note=note_content, Author=f"{session['first_name']} {session['last_name']}")
            db.session.add(new_work_note)
            if Config.DEBUG_MODE:
                print("New work note added to database:")
            incident.Updated_At = db.func.current_timestamp()
            if Config.DEBUG_MODE:
                print("Incident timestamp updated.")
            db.session.commit()
            if Config.DEBUG_MODE:
                print("DB Commit successful!")
            flash('Work note added successfully!', 'success')
            return redirect(url_for('main.view_incident', incident_id=incident.ID))
        else:
            if Config.DEBUG_MODE:
                print("No note content found.")
            flash('Please enter a note.', 'error')

    return render_template('view_incident.html', incident=incident)

#*Assign_To_Me*
@app.route('/assign_to_me/<int:incident_id>', methods=['POST'])
@login_required
def assign_to_me(incident_id):

    user = current_user
    if Config.DEBUG_MODE:
        print("Current user:", user)

    incident = Incident.query.get(incident_id)
    if Config.DEBUG_MODE:
        print("Incident found:", incident)

    if incident is None:
        if Config.DEBUG_MODE:
            print("Incident not found.")
        flash('Incident not found.', 'danger')
        return redirect(url_for('main.view_incidents'))

    max_assigned_users = 3
    if Config.DEBUG_MODE:
        print("Max assigned users:", max_assigned_users)
    if len(incident.assigned_to) >= max_assigned_users:
        if Config.DEBUG_MODE:
            print(f"Incident {incident_id} already assigned to max users.")
        flash(f'Incident {incident_id} is already assigned to {max_assigned_users} users. Please contact a manager to have a user unassigned.', 'danger')
        return redirect(url_for('main.view_incident', incident_id=incident_id))

    if user in incident.assigned_to:
        if Config.DEBUG_MODE:
            print(f"User already assigned to incident {incident_id}.")
        flash(f'You are already assigned to incident {incident_id}.', 'info')
    else:
        incident.assigned_to.append(user)
        if Config.DEBUG_MODE:
            print(f"User added to assigned_to list for incident {incident_id}.")
        try:
            db.session.commit()
            if Config.DEBUG_MODE:
                print("DB Commit successful!")
            flash(f'You have been assigned to incident {incident_id}.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Failed to assign to incident. Please try again.', 'danger')
            print(f"Error: {e}")

    return redirect(url_for('main.view_incidents'))


#*Unassign_User*
@app.route('/unassign_user/<int:incident_id>', methods=['GET', 'POST'])
@login_required
def unassign_user(incident_id):
    incident = Incident.query.get(incident_id)
    role = current_user.Role
    if Config.DEBUG_MODE:
        print("Current user role:", role)
        print("Incident found:", incident)

    if incident is None:
        if Config.DEBUG_MODE:
            print("Incident not found.")
        flash('Incident not found.', 'danger')
        return redirect(url_for('main.view_incidents'))

    if role not in ["Administrator", "Manager"]:
        if Config.DEBUG_MODE:
            print("User not authorized to unassign users from incidents.")
        flash("You do not have permission to unassign users from incidents.", "danger")
        return redirect(url_for('main.view_incidents'))


#*Admin_Incidents*
@app.route('/admin_incidents')
@role_required('Administrator')
def admin_incidents():
    try:
        incidents = Incident.query.all()
        if Config.DEBUG_MODE:
            print("Incidents fetched successfully.")
        return render_template('admin_incidents.html', incidents=incidents)
    except Exception as e:
        if Config.DEBUG_MODE:
            print("Error retrieving incidents.")
        flash('Failed to retrieve incidents.', 'danger')
        print(f"Error: {e}")
        return redirect(url_for('main.home'))

#*Admin_Dashboard*
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    first_name = current_user.First_Name
    role = current_user.Role
    if Config.DEBUG_MODE:
        print("Current user first name:", first_name)
        print("Current user role:", role)

    logout_form = LogoutForm()

    if role not in ["Administrator"]:
        if Config.DEBUG_MODE:
            print("User not authorized to view this page.")
        flash("You are not authorized to view this page.")
        return redirect(url_for('main.login'))

    return render_template('admin_dashboard.html', first_name=first_name, form=logout_form)


#*Manager_Dashboard*

@app.route('/manager_dashboard')
@login_required
def manager_dashboard():

    first_name = current_user.First_Name
    role = current_user.Role
    if Config.DEBUG_MODE:
        print("Current user first name:", first_name)
        print("Current user role:", role)

    logout_form = LogoutForm()

    if role not in ["Administrator", "Manager"]:
        if Config.DEBUG_MODE:
            print("User not authorized to view this page.")
        flash("You are not authorized to view this page.")
        return redirect(url_for('main.login'))
    
    queue_incidents = Incident.query.filter(
        Incident.assigned_to == None
    ).all()

    return render_template('manager_dashboard.html', first_name=first_name, form=logout_form)


#*Responder_Dashboard*
@app.route('/responder_dashboard')
@login_required
def responder_dashboard():
    user = current_user
    first_name = current_user.First_Name
    role = current_user.Role
    if Config.DEBUG_MODE:
        print("Current user first name:", first_name)
        print("Current user role:", role)

    logout_form = LogoutForm()

    if role not in ["Administrator", "Manager", "Responder"]:
        if Config.DEBUG_MODE:
            print("User not authorized to view this page.")
        flash("You are not authorized to view this page.")
        return redirect(url_for('main.login'))
    
    assigned_incidents = Incident.query.filter(
        Incident.assigned_to.any(User.Username == user.Username)
    ).all()

    queue_incidents = Incident.query.filter(
        Incident.assigned_to == None
    ).all()

    urgent_incidents = Incident.query.filter(
        (Incident.Is_Urgent == True) | (Incident.Severity.in_(['High', 'Critical']))
    ).all()

    return render_template('responder_dashboard.html', first_name=first_name, form=logout_form, assigned_incidents=assigned_incidents, queue_incidents=queue_incidents, urgent_incidents=urgent_incidents)


#*User_Dashboard*
@app.route('/user_dashboard')
@login_required 
def user_dashboard():

    first_name = current_user.First_Name
    is_admin = current_user.Is_Admin
    is_manager = current_user.Is_Manager
    is_responder = current_user.Is_Responder
    logout_form = LogoutForm()
    if Config.DEBUG_MODE:
        print("Current user first name:", first_name)
        print("Is admin:", is_admin)
        print("Is manager:", is_manager)
        print("Is responder:", is_responder)

    return render_template('user_dashboard.html', 
                           first_name=first_name, 
                           is_admin=is_admin, 
                           is_manager=is_manager, 
                           is_responder=is_responder, 
                           form=logout_form)

#*Admin_Users*
@app.route('/admin_users')
@login_required
def admin_users():
    if current_user.is_authenticated:
        if current_user.Is_Admin:
            if Config.DEBUG_MODE:
                print("User is an admin and has been authenticated.")
            users = User.query.all()
            if Config.DEBUG_MODE:
                print("Users fetched successfully.")
            delete_form = DeleteUserForm()
            return render_template('admin_users.html', users=users, form=delete_form)
        else:
            if Config.DEBUG_MODE:
                print("User is not an admin and is unauthorized to view this page.")
            flash("You are not authorized to view this page.")
            return redirect(url_for('main.user_dashboard'))
    else:
        if Config.DEBUG_MODE:
            print("User is not authenticated and is unauthorized to view this page.")
        flash("You must be logged in as an admin to view this page", "danger")
        return redirect(url_for('main.login'))


#*Admin_Add_User*
@app.route('/admin_users_add', methods=['GET', 'POST'])
@login_required
def admin_users_add():
    user = current_user
    if Config.DEBUG_MODE:
        print("Current user:", user)
    if not user.Is_Admin:
        if Config.DEBUG_MODE:
            print("User is not an admin and is unauthorized to view this page.")
        flash("You are not authorized to view this page.")
        return redirect(url_for('main.user_dashboard'))
    form = AddUserForm()
    
    if form.validate_on_submit():
        first_name = form.first_name.data
        last_name = form.last_name.data
        email = form.email.data
        password = form.password.data
        role = form.role.data
        manager = form.manager.data

        is_admin = role == 'Administrator'
        is_manager = role == 'Manager'
        is_responder = role == 'Responder'

        MFA_Secret = pyotp.random_base32() if is_admin or is_manager or is_responder else ''
        MFA_setup_completed = 0 if is_admin or is_manager or is_responder else 1
        MFA_required = 1 if is_admin or is_manager or is_responder else 0
        security_questions_set = 0
        first_login_completed = 0
        username = first_name[:2].lower() + last_name.lower()

        hashed_password = generate_password_hash(password)

        try:
            new_user = User(
                Username=username,
                First_Name=first_name,
                Last_Name=last_name,
                Email=email,
                Password=hashed_password,
                Role=role,
                Manager=manager,
                Is_Admin=is_admin,
                Is_Manager=is_manager,
                Is_Responder=is_responder,
                MFA_Secret=MFA_Secret,
                MFA_Setup_Completed=MFA_setup_completed,
                MFA_Required=MFA_required,
                Security_Questions_Set=security_questions_set,
                First_Login_Completed=first_login_completed
            )
            if Config.DEBUG_MODE:
                print("New user created:")
                print(new_user)

            db.session.add(new_user)
            if Config.DEBUG_MODE:
                print("User added to the session.")
            db.session.commit()
            if Config.DEBUG_MODE:
                print("DB Commit successful!")

            flash('User added successfully!', 'success')
            return redirect(url_for('main.admin_users'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to add user. Please try again.', 'danger')
            print(f"Error: {e}")

    return render_template('admin_users_add.html', form=form)


#*Admin_Edit_User*
@app.route('/admin_users_edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_users_edit(user_id):
    user = current_user
    if Config.DEBUG_MODE:
        print("Current user:", user)
    if not user.Is_Admin:
        if Config.DEBUG_MODE:
            print("User is not an admin and is unauthorized to view this page.")
        flash("You are not authorized to view this page.")
        return redirect(url_for('main.user_dashboard'))
    
    user_to_edit = User.query.get_or_404(user_id)
    if Config.DEBUG_MODE:
        print("User to edit:", user_to_edit)
    form = EditUserForm(obj=user_to_edit)
    reset_form = AdminResetPasswordForm()

    if Config.DEBUG_MODE:
        if form.errors != {}:
            print("EditUserForm errors:", form.errors)
        elif reset_form.errors != {}:
            print("ResetPasswordForm errors:", reset_form.errors)
    
    if form.validate_on_submit():
        user_to_edit.First_Name = form.First_Name.data
        if Config.DEBUG_MODE:
            print("User_to_edit.First_Name:", user_to_edit.First_Name)
        user_to_edit.Last_Name = form.Last_Name.data
        if Config.DEBUG_MODE:
            print("User_to_edit.Last_Name:", user_to_edit.Last_Name)
        user_to_edit.Email = form.Email.data
        if Config.DEBUG_MODE:
            print("User_to_edit.Email:", user_to_edit.Email)
        user_to_edit.Role = form.Role.data
        if Config.DEBUG_MODE:
            print("User_to_edit.Role:", user_to_edit.Role)

        user_to_edit.Manager = form.Manager.data
        if Config.DEBUG_MODE:
            print("User_to_edit.Manager:", user_to_edit.Manager)

        user_to_edit.Is_Admin = form.Role.data == 'Administrator'
        if Config.DEBUG_MODE:
            print("User role contains Administrator. Boolean value assigned based on role.")
        user_to_edit.Is_Manager = form.Role.data == 'Manager'
        if Config.DEBUG_MODE:
            print("User role contains Manager. Boolean value assigned based on role.")
        user_to_edit.Is_Responder = form.Role.data == 'Responder'
        if Config.DEBUG_MODE:
            print("User role contains Responder. Boolean value assigned based on role.")

        if form.Role.data in ['Administrator', 'Manager', 'Responder']:
            if Config.DEBUG_MODE:
                print("User role contains Administrator, Manager, or Responder. Setting MFA Boolean values.")
            if not user_to_edit.MFA_Secret:
                user_to_edit.MFA_Secret = pyotp.random_base32()
            user_to_edit.MFA_Setup_Completed = form.MFA_Setup_Completed.data
            if Config.DEBUG_MODE:
                print("MFA setup completed boolean value assigned based on checkbox.")
            user_to_edit.MFA_Required = form.MFA_Required.data
            if Config.DEBUG_MODE:
                print("MFA required boolean value assigned based on checkbox.")
        else:
            if Config.DEBUG_MODE:
                print("User role does not contain Administrator, Manager, or Responder. Setting MFA Secret to null, MFA setup completed to true, and MFA required to FAlse.")
            user_to_edit.MFA_Secret = ''
            user_to_edit.MFA_Setup_Completed = 1
            user_to_edit.MFA_Required = 0

        user_to_edit.Security_Questions_Set = form.Security_Questions_Set.data
        if Config.DEBUG_MODE:
            print("Security questions set boolean value assigned based on checkbox.")

        try:
            db.session.commit()
            if Config.DEBUG_MODE:
                print("DB Commit successful!")
            flash('User updated successfully!', 'success')
            return redirect(url_for('main.admin_users'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to update user. Please try again.', 'danger')
            print(f"Error: {e}")
    else:
        print("Form validation failed.")
        print(form.errors)
        print("Form data:", request.form)

    return render_template('admin_users_edit.html', form=form, reset_form=reset_form, user_to_edit=user_to_edit)

@app.route('/admin_password_reset/<int:user_id>', methods=['POST'])
@login_required
def admin_password_reset(user_id):
    user = current_user
    user_to_reset = User.query.get_or_404(user_id)
    
    if Config.DEBUG_MODE:
        print("Current user:", user)
    
    if not user.Is_Admin:
        if Config.DEBUG_MODE:
            print("User is not an admin and is unauthorized to view this page.")
        flash("You are not authorized to reset this password.")
        return redirect(url_for('main.user_dashboard'))
    
    if user_to_reset.Security_Questions_Set == 0:
        flash("Security questions have not been set for this user. A temporary password will be sent to their email.", 'danger')
        temporary_password = secrets.token_urlsafe(16)
        user_to_reset.Password = generate_password_hash(temporary_password)
        try:
            db.session.commit()
            if Config.DEBUG_MODE:
                print("DB Commit successful!")
            flash(f'A temporary password has been sent to: {user_to_reset.Email}.', 'info')
            if Config.DEBUG_MODE:
                print("Sending temporary password to user's email.")
            user_password_no_security_q_set(user_to_reset.Email, temporary_password)
        except Exception as e:
            db.session.rollback()
            flash('Failed to reset password. Please try again.', 'danger')
            print(f"Error: {e}")
        return redirect(url_for('main.admin_users'))
    
    reset_form = AdminResetPasswordForm()
    if reset_form.validate_on_submit():
        if Config.DEBUG_MODE:
            print("User to reset:", user_to_reset)
        MFA_Secret = user.MFA_Secret
        
        if not MFA_Secret:
            if Config.DEBUG_MODE:
                print("Something has gone seriously wrong. MFA is not set up for this user, and this should not be possible.")
            flash("MFA is not set up for this user.", 'danger')
            return redirect(url_for('main.admin_users_edit', user_id=user_id))
        
        totp = pyotp.TOTP(MFA_Secret)
        if totp.verify(reset_form.MFA_otp.data):
            password_reset_via_email(user_to_reset.Email)
            session['admin_password_reset'] = True
            if Config.DEBUG_MODE:
                print("Password reset link sent to user's email.")
            
            flash(f'A password reset link has been sent to: {user_to_reset.Email}', 'success')
            return redirect(url_for('main.admin_users_edit', user_id=user_id))
        else:
            if Config.DEBUG_MODE:
                print("Invalid MFA OTP entered.")
            flash('Invalid MFA OTP. Please try again.', 'danger')
            return redirect(url_for('main.admin_users_edit', user_id=user_id))
        
    flash('Failed to validate MFA OTP. Please try again.', 'danger')
    if Config.DEBUG_MODE:
        print("Failed to validate MFA OTP.")
    return redirect(url_for('main.admin_users_edit', user_id=user_id))


@app.route('/admin_users_delete_<int:user_id>', methods=['POST'])
@login_required
def admin_users_delete(user_id):
    user = current_user
    if Config.DEBUG_MODE:
        print("Current user:", user)
    if not user.Is_Admin:
        if Config.DEBUG_MODE:
            print("User is not an admin and is unauthorized to view this page.")
        flash("You are not authorized to view this page.")
        return redirect(url_for('main.user_dashboard'))
    form = DeleteUserForm()

    if form.validate_on_submit():
        user_to_delete = User.query.get(user_id)
        if Config.DEBUG_MODE:
            print(f"User to delete: {user_to_delete}")
        current_user_id = current_user.ID
        if Config.DEBUG_MODE:
            print(f"Current user ID: {current_user_id}")
        if user_to_delete:
            if user_to_delete.ID == current_user_id:
                flash('You cannot delete your own account.', 'danger')
                if Config.DEBUG_MODE:
                    print("User is trying to delete their own account.")
            else:
                try:
                    db.session.delete(user_to_delete)
                    if Config.DEBUG_MODE:
                        print("User marked for deletion.")
                    db.session.commit()
                    if Config.DEBUG_MODE:
                        print("DB Commit successful!")
                        print("User deleted successfully.")
                    flash('User deleted successfully!', 'success')
                except Exception as e:
                    db.session.rollback()
                    flash('Failed to delete user. Please try again.', 'danger')
                    print(f"Error: {e}")
        else:
            flash('User not found.', 'danger')
    else:
        flash('Invalid CSRF token or form submission.', 'danger')

    return redirect(url_for('main.admin_users'))

#*Admin_Edit_Incident*
@app.route('/admin_incidents_edit_<string:incident_id>', methods=['GET', 'POST'])
def admin_edit_incident(incident_id):
    user = current_user
    if Config.DEBUG_MODE:
        print("Current user:", user)
    if not user.Is_Admin:
        if Config.DEBUG_MODE:
            print("User is not an admin and is unauthorized to view this page.")
        flash("You are not authorized to view this page.")
        return redirect(url_for('main.user_dashboard'))
    incident = Incident.query.filter_by(ID=incident_id).first()
    if Config.DEBUG_MODE:
        print("Incident to edit:", incident)

    if not incident:
        if Config.DEBUG_MODE:
            print("Incident not found.")
        flash('Incident not found.', 'danger')
        return redirect(url_for('main.view_incidents'))

    form = IncidentForm()
    if request.method == 'GET':
        form.title.data = incident.Title
        form.description.data = incident.Description
        form.severity.data = incident.Severity
        form.category.data = incident.Category
    else:
        form = IncidentForm(request.form)
    if Config.DEBUG_MODE:
        print("Form data:", form.data)

    if form.validate_on_submit():
        incident.Title = form.title.data
        incident.Description = form.description.data
        incident.Severity = form.severity.data
        incident.Category = form.category.data

        try:
            db.session.commit()
            if Config.DEBUG_MODE:
                print("DB Commit successful!")
                print("Form data:", form.data)
            flash('Incident updated successfully!', 'success')
            return redirect(url_for('main.view_incidents'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to update incident. Please try again.', 'danger')
            logger.error(f"Error while updating incident: {e}")

    if form.errors:
        logger.error(f"Validation errors: {form.errors}")
    else:
        logger.warning("Form validation did not pass, but no specific errors were recorded.")

    return render_template('admin_incidents_edit.html', form=form, incident=incident)


#*Admin_Delete_Incident*
@app.route('/admin_incidents_delete_<string:incident_id>', methods=['POST'])
@login_required
def admin_delete_incident(incident_id):
    user = current_user
    if Config.DEBUG_MODE:
        print("Current user:", user)
    if not user.Is_Admin:
        if Config.DEBUG_MODE:
            print("User is not an admin and is unauthorized to view this page.")
        flash("You are not authorized to view this page.")
        return redirect(url_for('main.user_dashboard'))
    incident = Incident.query.filter_by(ID=incident_id).first()
    if Config.DEBUG_MODE:
        print("Incident to delete:", incident)

    if incident:
        try:
            db.session.delete(incident)
            if Config.DEBUG_MODE:
                print(f"Incident {incident_id} marked for deletion.")
            db.session.commit()
            if Config.DEBUG_MODE:
                print("DB Commit successful!")
            flash('Incident deleted successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Failed to delete incident. Please try again.', 'danger')
            print(f"Error: {e}")
    else:
        flash('Incident not found.', 'danger')

    return redirect(url_for('main.view_incidents'))

