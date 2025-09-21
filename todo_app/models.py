from .db import db
from sqlalchemy.sql import func
from .helpers import default_expiry

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(60),nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30),default="user",nullable = False)


class Todos(db.Model):
    id = db.Column(db.Integer,primary_key=True,autoincrement=True)
    title = db.Column(db.String(255),nullable=False)
    description = db.Column(db.String(255),nullable=False)
    user_id= db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
    user = db.relationship('User', backref='todos')
    is_completed = db.Column(db.Boolean,default=False)
    created_at = db.Column(db.DateTime,default=func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "user_id": self.user_id,
            "is_completed": self.is_completed,
        }
class CompletedTodos(db.Model):
    id = db.Column(db.Integer,primary_key=True,autoincrement=True)
    title= db.Column(db.String(255),nullable=False)
    description = db.Column(db.String(255),nullable=False)
    is_completed = db.Column(db.Boolean,default=False)
    completed_at = db.Column(db.DateTime,default=func.now())
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
    user = db.relationship('User', backref='completed_todos')

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            'is_completed': self.is_completed,
            "completed_at": self.completed_at,
            "user_id": self.user_id,
        }

class PasswordReset(db.Model):

    id = db.Column(db.Integer,primary_key=True,autoincrement=True)
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
    otp_hash = db.Column(db.String(255),nullable=False)
    expires_at = db.Column(db.DateTime,default=default_expiry)
    is_user = db.Column(db.Boolean,default=False)
    user = db.relationship('User', backref='password_reset')








