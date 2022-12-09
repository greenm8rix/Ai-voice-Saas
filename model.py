from flask_login import UserMixin
from sqlalchemy import ForeignKey
from config import db, app


class LoginModel(db.Model, UserMixin):
    __tablename__ = "user_data"

    id = db.Column(db.String(40), primary_key=True)
    email = db.Column(db.String(20), nullable=False, unique=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    subscription_tier = db.Column(db.String())
    downloads = db.Column(db.INTEGER(), nullable=False)
    progress = db.Column(db.String(80), nullable=False)
    file_url = db.Column(db.String(200), nullable=True)
    is_verified = db.Column(db.BOOLEAN(), nullable=True)


class StripeCustomer(db.Model):
    id = db.Column(db.INTEGER(), primary_key=True, autoincrement=True)
    user_id = db.Column(db.String(40), db.ForeignKey("user_data.id"))
    stripeCustomerId = db.Column(db.String(255), nullable=False)
    stripeSubscriptionId = db.Column(db.String(255), nullable=False)


class products(db.Model):
    price_id = db.Column(db.String(40), primary_key=True)
    Product = db.Column(db.String(40), nullable=True)
