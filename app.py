import logging
import os
import uuid

import boto3
from botocore.exceptions import ClientError
from flask import Flask, redirect, render_template, request, url_for
from flask_login import LoginManager, current_user, login_user, logout_user
from passlib.hash import pbkdf2_sha256
from werkzeug.utils import secure_filename

from config import (
    BUCKET_NAME,
    ENDPOINT,
    S3_ACCESS_KEY,
    S3_SECRET_KEY,
    SECRET_KEY,
    SQLALCHEMY_DATABASE_URI,
)
from models import Post, User, db
from wtform_fields import LoginFrom, RegistrationForm

app = Flask(__name__)
app.secret_key = SECRET_KEY


app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI

db.init_app(app)


login_manager = LoginManager(app)
login_manager.init_app(app)

s3 = boto3.client(
    "s3",
    endpoint_url=ENDPOINT,
    aws_access_key_id=S3_ACCESS_KEY,
    aws_secret_access_key=S3_SECRET_KEY,
)


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
    username = current_user.username

    posts = Post.query.all()
    posts_data = []
    for post in posts:
        post_data = {}
        post_data["url"] = create_presigned_url(BUCKET_NAME, post.key)
        post_data["bird_name"] = post.birdname
        post_data["location"] = post.location
        post_data["id"] = post.id
        post_data["author"] = post.author
        post_data["likes"] = post.likes  #
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

        if image:
            filename = secure_filename(image.filename)
            image.save(filename)

            key = uuid.uuid4().hex + "." + filename.rsplit(".", 1)[1].lower()

            s3.upload_file(Bucket=BUCKET_NAME, Filename=filename, Key=key)
            post = Post(
                key=key, birdname=birdname, location=location, author_id=current_user.id
            )
            db.session.add(post)
            db.session.commit()
            os.remove(filename)

            return redirect(url_for("birds"))

    return render_template("upload_post.html")


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
    return redirect(url_for("birds"))


@app.route("/logout", methods=["GET"])
def logout():

    logout_user()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
