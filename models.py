from app import db
from flask_login import UserMixin
import jwt
import os
import base64
import onetimepass
import secrets
from time import time


class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    NYPaccount = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False, unique=True)
    pfpfilename = db.Column(db.String(85))
    two_factor_enabled = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false())
    otp_secret = db.Column(db.String(32))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            # generate a random secret
            self.otp_secret = base64.b32encode(secrets.token_bytes(20)).decode('utf-8')

    role = db.Column(db.String(20))
    age = db.Column(db.String(3))
    first_name = db.Column(db.LargeBinary)
    last_name = db.Column(db.LargeBinary)
    ferkey = db.Column(db.LargeBinary)

    gender = db.Column(db.String(10))
    date_joined = db.Column(db.String(50))
    doc = db.Column(db.String(60), unique=False)
    time = db.Column(db.String(30))
    remarks = db.Column(db.String(30))

    banned = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false())
    verified = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false())

    consultstate = db.Column(db.Boolean)
    failed_access = db.Column(db.Integer)

    def __repr__(self):
        return '<User %r>' % self.username

    def get_reset_token(self, expires=500):
        return jwt.encode({'reset_password': self.email, 'exp': time() + expires},
                          key=os.getenv('SECRET_KEY_FLASK'), algorithm="HS256")

    def get_totp_uri(self):
        return 'otpauth://totp/2FA-Appsec:{0}?secret={1}&issuer=2FA-Appsec' \
            .format(self.username, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)

    @staticmethod
    def verify_reset_token(token):
        try:
            email = jwt.decode(token, key=os.getenv('SECRET_KEY_FLASK'), algorithms="HS256")['reset_password']
            print(email)
        except Exception as e:
            print(e)
            return
        return User.query.filter_by(email=email).first()


class Post(db.Model):
    __tablename__ = "Post"
    id = db.Column(db.Integer, primary_key=True)
    Post_Name = db.Column(db.String(80), unique=False, nullable=False)
    content = db.Column(db.String, unique=True, nullable=False)





