import hashlib
import logging
import os
import secrets
import uuid
from base64 import urlsafe_b64decode as b64d
from base64 import urlsafe_b64encode as b64e

import boto3
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, redirect, render_template, request, url_for
from flask_login import LoginManager, current_user, login_user, logout_user
from flask_migrate import Migrate
from passlib.hash import pbkdf2_sha256
from werkzeug.utils import secure_filename

from config import (
    BUCKET_NAME,
    ENDPOINT,
    S3_ACCESS_KEY,
    S3_REGION,
    S3_SECRET_KEY,
    SECRET_KEY,
    SQLALCHEMY_DATABASE_URI,
)
from models import BlockedIP, Post, User, db
from wtform_fields import BlockIPForm, LoginFrom, RegistrationForm

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
migrate = Migrate(app, db)

db.init_app(app)


login_manager = LoginManager(app)
login_manager.init_app(app)

s3 = boto3.client(
    "s3",
    endpoint_url=ENDPOINT,
    aws_access_key_id=S3_ACCESS_KEY,
    aws_secret_access_key=S3_SECRET_KEY,
    region_name=S3_REGION,
)


def create_ip_hash(ip):
    ip_hash = hashlib.sha256(ip.encode())
    return ip_hash.hexdigest()


@app.before_request
def is_in_blacklist():
    ip_hash = create_ip_hash(str(request.headers.get("X-Real-IP")))
    blocked_ip = BlockedIP.query.filter_by(ip_hash=ip_hash).first()
    if blocked_ip is not None:
        return redirect("https://zakon.rada.gov.ua/laws/show/2341-14/page11#Text")
    return None


def create_presigned_url(bucket_name, object_name, expiration=3600):
    """Generate a presigned URL to share an S3 object

    :param bucket_name: string
    :param object_name: string
    :param expiration: Time in seconds for the presigned URL to remain valid
    :return: Presigned URL as string. If error, returns None.
    """

    try:
        response = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket_name, "Key": object_name},
            ExpiresIn=expiration,
        )
    except ClientError as e:
        logging.error(e)
        return None

    return response


def derive_key(password: bytes, salt: bytes, iterations: int = 210_000) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return b64e(kdf.derive(password))


def encrypt_data(message: bytes, password: str, iterations: int = 210_000) -> bytes:
    """Encrypt data using generated secret key"""
    salt = secrets.token_bytes(16)
    key = derive_key(password.encode(), salt, iterations)
    return b64e(
        b"%b%b%b"
        % (
            salt,
            iterations.to_bytes(4, "big"),
            b64d(Fernet(key).encrypt(message)),
        )
    )


def decrypt_data(token: bytes, password: str) -> bytes:
    """Decrypt data using generated secret key"""
    decoded = b64d(token)
    salt, iteration, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iteration)
    key = derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)


@login_manager.user_loader
def load_user(user_id):

    return User.query.get(int(user_id))


@app.route("/", methods=["GET", "POST"])
def index():

    return render_template("index.html")


@app.route("/registration", methods=["GET", "POST"])
def registration():

    reg_form = RegistrationForm()
    if reg_form.validate_on_submit():
        username = reg_form.username.data
        password = reg_form.password.data

        hashed_pswd = pbkdf2_sha256.hash(password)

        user = User(username=username, password=hashed_pswd)
        db.session.add(user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("registration.html", form=reg_form)


@app.route("/login", methods=["GET", "POST"])
def login():

    login_form = LoginFrom()

    if login_form.validate_on_submit():
        user_object = User.query.filter_by(username=login_form.username.data).first()
        login_user(user_object)
        return redirect(url_for("birds"))

    return render_template("login.html", form=login_form)


@app.route("/birds", methods=["GET", "POST"])
def birds():

    if not current_user.is_authenticated:
        return redirect(url_for("index"))

    posts = Post.query.all()
    posts_data = []
    for post in posts:
        post_data = {
            "url": create_presigned_url(BUCKET_NAME, post.key),
            "bird_name": post.birdname,
            "location": "**********" if post.password is not None else post.location,
            "id": post.id,
            "author": post.author,
            "likes": post.likes,
        }
        posts_data.append(post_data)

    return render_template("birds.html", posts_data=posts_data)


@app.route("/upload_post", methods=["GET", "POST"])
def upload_post():

    if not current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        image = request.files["file"]
        birdname = request.form.get("bird_name")
        location = request.form.get("location")
        password = request.form.get("password")

        # Encrypt location and hash password if password is entered
        if password:
            location = encrypt_data(location.encode(), password).decode()
            password = pbkdf2_sha256.hash(request.form.get("password"))
        else:
            password = None

        if image:
            filename = secure_filename(image.filename)
            image.save(filename)

            key = uuid.uuid4().hex + "." + filename.rsplit(".", 1)[1].lower()

            s3.upload_file(Bucket=BUCKET_NAME, Filename=filename, Key=key)
            post = Post(
                key=key,
                birdname=birdname,
                location=location,
                author_id=current_user.id,
                password=password,
            )
            db.session.add(post)
            db.session.commit()
            os.remove(filename)

            return redirect(url_for("birds"))

    return render_template("upload_post.html")


@app.route("/birds/<int:post_id>", methods=["GET"])
def view_post(post_id):

    if not current_user.is_authenticated:
        return redirect(url_for("index"))

    post = Post.query.get_or_404(post_id)
    post_data = {
        "url": create_presigned_url(BUCKET_NAME, post.key),
        "bird_name": post.birdname,
        "location": "**********" if post.password is not None else post.location,
        "id": post.id,
        "author": post.author,
        "likes": post.likes,
        "is_encrypted": post.password is not None,
    }

    return render_template("bird.html", post_data=post_data)


@app.route("/birds/decrypted/<int:post_id>", methods=["GET", "POST"])
def decrypt_location(post_id):

    if not current_user.is_authenticated:
        return redirect(url_for("index"))

    post = Post.query.get_or_404(post_id)

    # Redirect users to view_post endpoint if like button is pressed on
    # decrypt_location page
    if request.method == "GET":
        return redirect(url_for("view_post", post_id=post_id))

    if post.password is None:
        return redirect(request.referrer)

    if not pbkdf2_sha256.verify(request.form.get("password"), post.password):
        return redirect(request.referrer)

    post_data = {
        "url": create_presigned_url(BUCKET_NAME, post.key),
        "bird_name": post.birdname,
        "location": decrypt_data(
            post.location.encode(), request.form.get("password")
        ).decode(),
        "id": post.id,
        "author": post.author,
        "likes": post.likes,
    }

    return render_template("bird.html", post_data=post_data)


@app.route("/delete_post/<int:post_id>", methods=["POST"])
def delete_post(post_id):

    post = Post.query.get_or_404(post_id)
    if current_user == post.author:
        s3.delete_object(Bucket=BUCKET_NAME, Key=post.key)
        db.session.delete(post)
        db.session.commit()

    return redirect(url_for("birds"))


@app.route("/like/<int:post_id>", methods=["POST"])
def like_post(post_id):

    if not current_user.is_authenticated:
        return redirect(url_for("index"))

    post = Post.query.get_or_404(post_id)
    if post in current_user.liked_posts:
        post.likes.remove(current_user)
        db.session.commit()
    else:
        post.likes.append(current_user)
        db.session.commit()
    return redirect(request.referrer)


@app.route("/logout", methods=["GET"])
def logout():

    logout_user()
    return redirect(url_for("index"))


@app.route("/blacklist", methods=["GET", "POST"])
def add_to_blacklist():
    ip_form = BlockIPForm()
    if ip_form.validate_on_submit():
        ip_hash = create_ip_hash(str(ip_form.ip.data))

        blocked_ip = BlockedIP(ip_hash=ip_hash)
        db.session.add(blocked_ip)
        db.session.commit()

        return redirect(url_for("birds"))
    return render_template("block_ip.html", form=ip_form)


@app.route("/get_user_ip", methods=["GET"])
def get_ip():
    blacklist = 1

    return str(blacklist)


if __name__ == "__main__":
    app.run(debug=True)
