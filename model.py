from flask_login import UserMixin
from config import db, app


class LoginModel(db.Model, UserMixin):
    __tablename__ = "user_data"

    id = db.Column(db.String(40), primary_key=True)
    email = db.Column(db.String(20), nullable=False, unique=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    subscription_tier = db.Column(db.String())
    downloads = db.Column(db.INTEGER(), nullable=False)
