# models.py
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from config import Config  # to access app.secret_key

class User(UserMixin):
    def __init__(self, id, username, password=None, email=None, phone=None, hostel=None, bio=None, role='user'):
        self.id = id
        self.username = username
        self.password = password
        self.email = email
        self.phone = phone
        self.hostel = hostel
        self.bio = bio
        self.role = role

    def get_id(self):
        return str(self.id)

    @property
    def is_admin(self):
        return self.role == 'admin'

    def generate_reset_token(self, expires_in=1800):  # 30 minutes
        """Generate a timed, signed reset token"""
        s = URLSafeTimedSerializer(Config.SECRET_KEY)
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token, max_age=1800):
        """Verify the token and return user_id if valid"""
        s = URLSafeTimedSerializer(Config.SECRET_KEY)
        try:
            data = s.loads(token, max_age=max_age)
            return data['user_id']
        except (SignatureExpired, BadSignature):
            return None

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"
