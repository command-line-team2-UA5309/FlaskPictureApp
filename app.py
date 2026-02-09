import uuid

import boto3
from flask import Flask, redirect, render_template, request, url_for
from flask_login import LoginManager, current_user, login_user, logout_user
from passlib.hash import pbkdf2_sha256
from werkzeug.utils import secure_filename

from config import (BUCKET_NAME, ENDPOINT, S3_ACCESS_KEY, S3_SECRET_KEY,
                    SECRET_KEY, SQLALCHEMY_DATABASE_URI)
from models import BlockedIP, Post, User, db
from wtform_fields import LoginFrom, PostForm, RegistrationForm

app = Flask(__name__)
app.secret_key = SECRET_KEY


app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI

db.init_app(app)


login_manager = LoginManager(app)
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):

    return User.query.get(int(user_id))


@app.route("/", methods=["GET", "POST"])
def index():

    reg_form = RegistrationForm()
    if reg_form.validate_on_submit():
        username = reg_form.username.data
        password = reg_form.password.data

        hashed_pswd = pbkdf2_sha256.hash(password)

        user = User(username=username, password=hashed_pswd)
        db.session.add(user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("index.html", form=reg_form)


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

    # Allow login in case of success validation
    if login_form.validate_on_submit():
        user_object = User.query.filter_by(username=login_form.username.data).first()
        login_user(user_object)
        return redirect(url_for("birds"))

    return render_template("login.html", form=login_form)


@app.route("/birds", methods=["GET", "POST"])
def birds():
    username = current_user.username
    # if not current_user.is_authenticated:
    #     return "Please login"

    return render_template("birds.html", username=username)


s3 = boto3.client(
    "s3",
    endpoint_url=ENDPOINT,
    aws_access_key_id=S3_ACCESS_KEY,
    aws_secret_access_key=S3_SECRET_KEY,
)


@app.route("/upload_post", methods=["GET", "POST"])
def upload_post():

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

            return render_template(
                "birds.html", key=key, birdname=birdname, location=location
            )

    return render_template("upload_post.html")


@app.route("/logout", methods=["GET"])
def logout():

    logout_user()
    return "Logged out!"


if __name__ == "__main__":
    app.run(debug=True)
