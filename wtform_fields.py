from flask_wtf import FlaskForm
from passlib.hash import pbkdf2_sha256
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import EqualTo, InputRequired, Length, ValidationError

from models import User


def invalid_credentials(form, field):

    username_entered = form.username.data
    password_entered = field.data

    # Check credentials are valid
    user_object = User.query.filter_by(username=username_entered).first()
    if user_object is None:
        raise ValidationError("Username or password are incorrect.")
    if not pbkdf2_sha256.verify(password_entered, user_object.password):
        raise ValidationError("Username or password are incorrect.")


class RegistrationForm(FlaskForm):

    username = StringField(
        "username_label",
        validators=[
            InputRequired(message="Username required"),
            Length(
                min=3, max=25, message="Username must be between 3 and 25 characters!"
            ),
        ],
    )
    password = PasswordField(
        "password_label",
        validators=[
            InputRequired(message="Password required"),
            Length(
                min=6, max=30, message="Password must be between 6 and 30 characters!"
            ),
        ],
    )
    confirm_pswd = PasswordField(
        "confirm_pswd_label",
        validators=[
            InputRequired(message="Password required"),
            EqualTo("password", message="Passwords must match!"),
        ],
    )
    submit_button = SubmitField("Create")

    def validate_username(self, username):
        user_object = User.query.filter_by(username=username.data).first()
        if user_object:
            raise ValidationError("Username already in use. Select other one.")


class LoginFrom(FlaskForm):

    username = StringField(
        "username_label", validators=[InputRequired(message="Username required!")]
    )
    password = PasswordField(
        "password_label",
        validators=[InputRequired(message="Password required!"), invalid_credentials],
    )
    submit_button = SubmitField("Login")
