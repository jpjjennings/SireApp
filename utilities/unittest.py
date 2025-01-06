import unittest
from flask import session
from app import app, db, User
from werkzeug.security import generate_password_hash
from itsdangerous import URLSafeTimedSerializer
import pyotp

class PasswordResetTests(unittest.TestCase):
    
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_reset_password_valid_token(self):
        user = User(Email='test@example.com', Password=generate_password_hash('old_password'), Role='Administrator')
        db.session.add(user)
        db.session.commit()
        
        token = URLSafeTimedSerializer('secret-key').dumps('test@example.com', salt='password-reset-salt')
        
        response = self.app.post(f'/reset_password/{token}', data={
            'new_password': 'new_password'
        })
        user = User.query.filter_by(Email='test@example.com').first()
        self.assertEqual(user.Password, generate_password_hash('new_password'))
        self.assertEqual(response.status_code, 302)  # Redirects

    def test_reset_password_invalid_token(self):
        response = self.app.post('/reset_password/invalid_token')
        self.assertFlashed('Invalid or expired token. Please try again.', category='danger')
        self.assertEqual(response.status_code, 302)  # Redirects

    def test_reset_password_user_not_found(self):
        token = URLSafeTimedSerializer('secret-key').dumps('unknown@example.com', salt='password-reset-salt')
        response = self.app.post(f'/reset_password/{token}', data={
            'new_password': 'new_password'
        })
        self.assertFlashed('User not found. Please try again.', category='danger')
        self.assertEqual(response.status_code, 302)  # Redirects

    def test_password_reset_mfa_success(self):
        user = User(Email='mfa_user@example.com', Password=generate_password_hash('old_password'), Mfa_Setup_Completed=True, Mfa_Secret='SECRET')
        db.session.add(user)
        db.session.commit()
        
        response = self.app.post('/password_reset_mfa', data={
            'email': 'mfa_user@example.com',
            'otp': pyotp.TOTP('SECRET').now()
        })
        self.assertIn('MFA verification successful!', session.pop('_flashes', None), 'success')
        self.assertEqual(response.status_code, 302)  # Redirects

    def test_password_reset_mfa_invalid_otp(self):
        user = User(Email='mfa_user@example.com', Password=generate_password_hash('old_password'), Mfa_Setup_Completed=True, Mfa_Secret='SECRET')
        db.session.add(user)
        db.session.commit()

        response = self.app.post('/password_reset_mfa', data={
            'email': 'mfa_user@example.com',
            'otp': 'invalid_otp'
        })
        self.assertFlashed('Invalid OTP. Please try again.', category='danger')
        self.assertEqual(response.status_code, 200)  # Render MFA failure page

if __name__ == '__main__':
    unittest.main()