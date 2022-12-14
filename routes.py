from hashlib import new
from sre_constants import CH_LOCALE
from datetime import date
from io import BytesIO
from wtforms import ValidationError, validators
import re
from datetime import datetime
from flask import (
    Flask,
    render_template,
    redirect,
    flash,
    url_for,
    session,
    request
)

from datetime import timedelta
from sqlalchemy.exc import (
    IntegrityError,
    DataError,
    DatabaseError,
    InterfaceError,
    InvalidRequestError,
)
from werkzeug.routing import BuildError


from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash
from functions import send_password_reset_email
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    current_user,
    logout_user,
    login_required,
)

from app import create_app, db, login_manager, bcrypt, limiter, mail, jwt, required_roles
from forms import LoginForm, SignUpForm, ChangePasswordForm, ForgotPasswordForm, \
    ResetPasswordForm,  EmptyForm, \
    Login2Form, AccountListSearchForm, PostForm
from models import User, Post
import pyqrcode
import time, os, base64, atexit
from cryptography.fernet import Fernet
from apscheduler.schedulers.background import BackgroundScheduler
from flask_alchemydumps import AlchemyDumps


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


app = create_app()


def print_date_time():
    print(time.strftime("%A, %d. %B %Y %I:%M:%S %p"))

def backup():
    os.system('python manage.py alchemydumps create')
    os.system('python manage.py alchemydumps autoclean')

scheduler = BackgroundScheduler()
scheduler.add_job(func=backup, trigger="interval", seconds=60)
scheduler.start()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())

alchemydumps = AlchemyDumps(app, db)

@app.route("/", methods=["GET", "POST"])

def home():

    posts = Post.query.all()
    queried = Post.query.order_by((Post.id.desc())).limit(5).all()
    lis = []
    for i in queried:
          image = base64.b64encode(i.data).decode('ascii')
          lis.append(image)


    return render_template("home.html", queried = queried, data = list, lis = lis, zip = zip)
# render picture=render_picture



@app.route('/login' , methods=["GET", "POST"])
@limiter.limit("2/second")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()

    if form.validate_on_submit():
        try:
            user = User.query.filter_by(NYPaccount=form.email.data.lower()).first()
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash("Invalid Username or password!", "danger")
        except Exception as e:
            flash("Wrong username or password", "danger")

    return render_template('login.html', form=form)



@app.route('/signup', methods=["GET", "POST"])
@limiter.limit("2/second")
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        try:
            appointment = False
            username = form.username.data
            NYPaccount = form.NYPaccount.data
            password = form.password.data

            if True:

              newuser = User(username=username, NYPaccount=NYPaccount, password=bcrypt.generate_password_hash(password),
                             consultstate=False, pfpfilename='default.png', failed_access=0)

              db.session.add(newuser)
              db.session.commit()
              flash(f"Account Succesfully created", "success")
              return redirect(url_for("login"))

            else:
                return redirect(url_for('home'))

        except InvalidRequestError:
            db.session.rollback()
            flash(f"Something went wrong!", "danger")
        except IntegrityError:
            db.session.rollback()
            flash(f"User already exists!.", "warning")
        except DataError:
            db.session.rollback()
            flash(f"Invalid Entry", "warning")
        except InterfaceError:
            db.session.rollback()
            flash(f"Error connecting to the database", "danger")
        except DatabaseError:
            db.session.rollback()
            flash(f"Error connecting to the database", "danger")
        except BuildError:
            db.session.rollback()
            flash(f"An error occured !", "danger")

    return render_template('signup.html', form=form)



@app.route('/Post', methods=['GET', 'POST'])
def upload():
    form = PostForm()

    if form.validate_on_submit():
        print("I'm here")

        file = request.files['inputFile']
        data = file.read()
        postname = form.Post_Name.data
        postname = str(postname)
        content = form.Post_Description.data
        content = str(content)
        Postform  = Post(Post_Name = postname, content = content, data=data)
        db.session.add(Postform)
        db.session.commit()


        return redirect(url_for('home'))
    else:
        print("here")

    return render_template('post.html', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route('/user', methods=['GET', 'POST'])
@login_required
def user():
    form = EmptyForm()

    return render_template('useraccount.html', name=current_user, form=form)


"""
@app.route('/Post', methods=['GET', 'POST'])
def upload():
    form = PostForm()

    if form.validate_on_submit():
        filename = PostForm(form.file.data.filename)
        form.file.data.save('uploads/' + filename)
        return redirect(url_for('upload'))

    return render_template('Post.html', form=form)
    """



@app.route('/enable_2fa', methods=["GET", "POST"])
@login_required
def enable_2fa():
    user = current_user
    user.two_factor_enabled = True

    db.session.commit()
    flash(f'2fa has been enabled', 'success')

    return redirect(url_for('user'))


@app.route('/disable_2fa', methods=["GET", "POST"])
@login_required
def disable_2fa():
    user = current_user
    user.two_factor_enabled = False

    db.session.commit()
    flash(f'2fa has been disabled', 'info')

    return redirect(url_for('user'))


@app.route('/2fa-setup', methods=['GET', 'POST'])
@login_required
def twofactor_setup():
    return render_template('user/loggedin/2fa-setup.html')


@app.route('/qrcode', methods=["GET", "POST"])
@login_required
def qrcode():
    user = current_user
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=5)
    return stream.getvalue()


@app.route('/change_password', methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        user = current_user
        old_password = form.old_password.data
        new_password = form.new_password.data

        if check_password_hash(user.password, old_password) and not check_password_hash(user.password, new_password):

            user.password = bcrypt.generate_password_hash(new_password)
            db.session.commit()
            flash(f"Password has been changed, please log in again", "success")
            logout_user()
            return redirect(url_for('login'))

        elif check_password_hash(user.password, new_password):
            flash(f"New password cant be same as old password", "warning")

        elif not check_password_hash(user.password, old_password):
            flash(f"Old password is wrong", "warning")

    return render_template('/user/loggedin/user_password_edit.html', form=form)





@app.route('/forgot_password', methods=["GET", "POST"])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user:
            send_password_reset_email(user)
        else:
            pass

        flash(f"Email sent", "info")

    return render_template('user/guest/passwordforget.html', form=form)


@app.route('/reset_password/<token>', methods=["GET", "POST"])
def reset_password(token):
    form = ResetPasswordForm()

    user = User.verify_reset_token(token)

    if user:

        if form.validate_on_submit():
            try:
                user.password = bcrypt.generate_password_hash(form.new_password.data)
                db.session.commit()
                flash(f"Password has been reset", "info")
                return redirect(url_for('login'))

            except InvalidRequestError:
                db.session.rollback()
                flash(f"Something went wrong!", "danger")
            except IntegrityError:
                db.session.rollback()
                flash(f"User already exists!.", "warning")
            except DataError:
                db.session.rollback()
                flash(f"Invalid Entry", "warning")
            except InterfaceError:
                db.session.rollback()
                flash(f"Error connecting to the database", "danger")
            except DatabaseError:
                db.session.rollback()
                flash(f"Error connecting to the database", "danger")
            except BuildError:
                db.session.rollback()
                flash(f"An error occured !", "danger")

    return render_template('/user/guest/passwordreset.html', form=form, user=user)







@app.route('/staffaccountlist/<int:page>', methods=["GET", "POST"])  # list member accounts
@login_required
@required_roles('admin')
def staffaccountlist(page=1):
    form = AccountListSearchForm()
    user_list = User.query.filter_by(role=None).all()

    return render_template('user/staff/staffaccountlist_2.html', form=form, user_list=user_list, page=page)


@app.route('/stafflist/<int:page>', methods=["GET", "POST"])  # list staff accounts
@login_required
@required_roles('admin')
def stafflist(page=1):
    return render_template('user/staff/stafflist.html')


@app.route('/banUser/<id>', methods=['GET', 'POST'])
@login_required
@required_roles('admin')
def banUser(id):
    pass


@app.route('/unbanUser/<id>', methods=['GET', 'POST'])
@login_required
@required_roles('admin')
def unbanUser(id):
    pass


@app.route('/delete_account', methods=["GET", "POST"])
@login_required
def delete_account():
    if request.method == "POST":
        db.session.delete(current_user)
        db.session.commit()
        flash(f'Account has been deleted', 'info')

        return redirect(url_for('home'))




@app.route('/deletecard', methods=["GET", "POST"])
@login_required
def deletecard():
    user = current_user
    user.card_name = None
    user.card_no = None
    user.card_exp_month = None
    user.card_exp_year = None
    user.card_CVV = None

    db.session.commit()
    flash(f'card info has been deleted', 'info')

    return redirect(url_for('user'))



if __name__ == "__main__":
    app.run(debug=True)
