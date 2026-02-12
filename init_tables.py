# from flask import Flask
# from flask_sqlalchemy import SQLAlchemy
# from flask_login import UserMixin
# from config import SQLALCHEMY_DATABASE_URI

from app import app, db

# class User(UserMixin, db.Model):

#     __tablename__ = "users"
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(25), unique=True, nullable=False)
#     password = db.Column(db.String(), nullable=False)
#     post = db.relationship("Post", backref="author", lazy=True)


# class Post(db.Model):

#     __tablename__ = "posts"
#     id = db.Column(db.Integer, primary_key=True)
#     key = db.Column(db.String, nullable=False)
#     birdname = db.Column(db.String(50), nullable=False)
#     location = db.Column(db.String(50), nullable=False)
#     author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)


with app.app_context():
    db.create_all()
    db.session.commit()
    print("db created")
