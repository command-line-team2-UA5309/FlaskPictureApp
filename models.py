from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

likes = db.Table(
    "likes",
    db.Column("user_id", db.Integer, db.ForeignKey("users.id")),
    db.Column("post_id", db.Integer, db.ForeignKey("posts.id")),
)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password = db.Column(db.String(), nullable=False)
    post = db.relationship("Post", backref="author", lazy=True)


class Post(db.Model):
    __tablename__ = "posts"
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String, nullable=False)
    birdname = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(), nullable=False)
    password = db.Column(db.String(), nullable=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    likes = db.relationship("User", secondary=likes, backref="liked_posts")


class BlockedIP(db.Model):
    __tablename__ = "blacklist"
    id = db.Column(db.Integer, primary_key=True)
    ip_hash = db.Column(db.String(), nullable=False)
