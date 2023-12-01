from sqlalchemy import CheckConstraint
from db import db

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('auth.id'), nullable=False)
    todo = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(50), nullable=False)

    __table_args__ = (
        CheckConstraint(status.in_(['complete', 'incomplete']), name='valid_status'),
    )