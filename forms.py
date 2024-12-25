from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, TextAreaField, SubmitField, BooleanField, EmailField, HiddenField
from wtforms.validators import InputRequired, Length, DataRequired, Email

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
    is_urgent = HiddenField('Is Urgent')
    status = HiddenField('Status')
    assigned_to = HiddenField('Assigned To')
    submit = SubmitField('Submit Incident')

class LogoutForm(FlaskForm):
    pass

class AddUserForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Role', choices=[
        ('Manager', 'Manager'),
        ('Responder', 'Responder'),
        ('Reporter', 'Reporter')
    ], validators=[InputRequired()])
    manager = StringField('Manager')
    submit = SubmitField('Add User')


class DeleteUserForm(FlaskForm):
    submit = SubmitField('Delete')

class EditUserForm(FlaskForm):
    Username = StringField('Username', render_kw={'disabled': 'disabled'})
    First_Name = StringField('First Name', validators=[DataRequired(), Length(max=50)])
    Last_Name = StringField('Last Name', validators=[DataRequired(), Length(max=50)])
    Email = EmailField('Email', validators=[DataRequired(), Email()])
    Role = SelectField('Role', choices=[('Manager', 'Manager'), ('Responder', 'Responder'), ('Reporter', 'Reporter')], validators=[DataRequired()])
    Manager = StringField('Manager')
    Is_Admin = BooleanField('Is Admin', render_kw={'disabled': 'disabled'})
    Is_Manager = BooleanField('Is Manager', render_kw={'disabled': 'disabled'})
    Is_Responder = BooleanField('Is Responder', render_kw={'disabled': 'disabled'})
    Security_Questions_Set = BooleanField('Security Questions Set')
    MFA_Setup_Completed = BooleanField('MFA Setup Completed')
    MFA_Required = BooleanField('MFA Required', render_kw={'disabled': 'disabled'})
    First_Login_Completed = BooleanField('First Login Completed', render_kw={'disabled': 'disabled'})
    Submit = SubmitField('Save Changes')

class SecurityQuestionForm(FlaskForm):
    questions = [
      ('question_1', 'What is your mother’s maiden name?'),
      ('question_2', 'What was the name of your first pet?'),
      ('question_3', 'What is your favorite book?'),
      ('question_4', 'What city were you born in?'),
      ('question_5', 'What is your favorite food?'),
      ('question_6', 'What is your dream job?'),
      ('question_7', 'What is your favorite color?'),
      ('question_8', 'What is your favorite movie?'),
      ('question_9', 'What was your childhood nickname?'),
      ('question_10', 'What is the name of your first school?'),
      ('question_11', 'Who is your favorite author?'),
      ('question_12', 'What is your favorite sport?'),
      ('question_13', 'What is your favorite holiday?'),
      ('question_14', 'What is your favorite music genre?'),
      ('question_15', 'What is your dream travel destination?')
    ]

    question_1 = SelectField('Question 1', choices=questions, validators=[DataRequired()])
    answer_1 = StringField('Answer', validators=[DataRequired(), Length(max=100)])

    question_2 = SelectField('Question 2', choices=questions, validators=[DataRequired()])
    answer_2 = StringField('Answer', validators=[DataRequired(), Length(max=100)])

    question_3 = SelectField('Question 3', choices=questions, validators=[DataRequired()])
    answer_3 = StringField('Answer', validators=[DataRequired(), Length(max=100)])
    
    submit = SubmitField('Save Changes')

class AdminResetPasswordForm(FlaskForm):
    mfa_otp = StringField('MFA OTP', validators=[DataRequired()])
    submit = SubmitField('Verify OTP')