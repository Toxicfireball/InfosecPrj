from wtforms import StringField, PasswordField, BooleanField, IntegerField, DateField, \
    TextAreaField, SelectField, FloatField, EmailField, RadioField, SubmitField, DecimalField, FileField, MultipleFileField
from wtforms_components import DateRange
from flask_wtf import FlaskForm
from wtforms.validators import InputRequired, Length, EqualTo, Email, Regexp, Optional, NumberRange
from wtforms_validators import AlphaNumeric, Alpha, AlphaSpace, Integer
import email_validator
from flask_login import current_user
from wtforms import ValidationError, validators
from models import User
from datetime import date
from flask import url_for, redirect, render_template
from werkzeug.utils import secure_filename
import os
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask_uploads import UploadSet, IMAGES



def length(min=-1, max=-1):
    message = 'Must be between %d and %d characters long.' % (min, max)

    def _length(form, field):
        l = field.data and len(field.data) or 0
        if l < min or max != -1 and l > max:
            raise ValidationError(message)

    return _length



class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Email(), Length(1, 64)])
    password = PasswordField(validators=[InputRequired(), Length(8, 72)])


class Login2Form(FlaskForm):
    otp = StringField(validators=[InputRequired(), Length(6, 6)])


class EmptyForm(FlaskForm):
    fake_field = StringField()


class SignUpForm(FlaskForm):
    username = StringField("", validators=[
        InputRequired(),
        Length(3, 20, message="Please provide a valid name"),
        Regexp("^[A-Za-z][A-Za-z0-9_.]*$", 0, "Usernames must have only letters, " "numbers, dots or underscores",),
    ])
    NYPaccount = StringField(validators=[InputRequired(), Email(), Length(27)])
    password = PasswordField(validators=[
        InputRequired(),
        Length(8, 72),
        Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,72}$", 0, "Password not strong enough")
    ])
    password_confirm = PasswordField(validators=[
        InputRequired(),
        Length(8, 72),
        EqualTo("password", message="Passwords must match !")
    ])

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError("Email already registered!")

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError("Username already taken!")


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField(validators=[InputRequired(), Length(8, 72)])
    new_password = PasswordField(validators=[
        InputRequired(),
        Length(8, 72),
        Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,72}$", 0, "Password not strong enough")
    ])
    confirm_new_password = PasswordField(validators=[
        InputRequired(),
        Length(8, 72),
        EqualTo("new_password", message="Passwords must match")
    ])





class ForgotPasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(), Length(1, 64)])


class ResetPasswordForm(FlaskForm):
    new_password = PasswordField(validators=[
        InputRequired(),
        Length(8, 72),
        Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,72}$", 0, "Password not strong enough")
    ])
    confirm_new_password = PasswordField(validators=[
        InputRequired(),
        Length(8, 72),
        EqualTo("new_password", message="Passwords must match")
    ])
    
images = UploadSet('images', IMAGES)


class PostForm(FlaskForm):
    Post_Name =StringField(validators= [InputRequired(), Length(8,300)])
    Post_Description = TextAreaField(validators = [InputRequired(), Length(8,300),])
    def validate_remarks(self, remarks ):
        excluded_chars = "*^%&()=}][{$@"
        for char in self.Post_Description.data:
            if char in excluded_chars:
                raise ValidationError(
                    f"Character {char} is not allowed in username.")

    file = FileField('image', validators=[

        FileRequired(),
        FileAllowed(images, 'Images only!')
    ])



class AccountListSearchForm(FlaskForm):
    search = StringField("")


