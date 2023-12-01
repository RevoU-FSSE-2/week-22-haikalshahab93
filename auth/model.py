from sqlalchemy import CheckConstraint
from db import db

class Auth(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(10), nullable=False)
    password = db.Column(db.String(100), nullable=False)

    __table_args__ = (
        CheckConstraint(role.in_(['user', 'admin']), name='valid_role'),
    )