from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db   ##means from __init__.py import db
from flask_login import login_user, login_required, logout_user, current_user
from flask import Flask, request, render_template
from flask_mail import Message
import random

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(
                password1, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            recipient_email = request.form["email"]
            six_digit_code = random.randint(100000, 999999)

            msg = Message('Hello', sender='yourId@example.com', recipients=[recipient_email])
            msg.body = "Hello Flask message sent from Flask-Mail and here is your code {six_digit_code}".format(
                six_digit_code=six_digit_code)

            # Print email details to console instead of sending
            print(f"Subject: {msg.subject}")
            print(f"From: {msg.sender}")
            print(f"To: {recipient_email}")
            print(f"Body:\n{msg.body}")
            return redirect(url_for('auth.confirm_email',user=current_user))

    return render_template("sign_up.html", user=current_user)


@auth.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            send_reset_password_email(user)
            flash('パスワードリセットのリンクをメールに送信しました。', 'success')
        else:
            flash('このメールアドレスは登録されていません。', 'error')

        return redirect(url_for('auth.login', email=email))

    return render_template('reset_password.html',user=current_user)



@auth.route('/confirm-email', methods=['GET', 'POST'])
def confirm_email():
    if request.method == 'POST':
        code = request.form.get('code')


        if code == '123456':
            flash("確認成功しました！", "success")
            return redirect(url_for('views.home'))
        #if validate_code(code):  # Function to check if the code is valid
        #   flash("確認成功しました！", "success")
        # return redirect(url_for('auth.login'))  # Redirect to login after confirmation

    else:
            flash("無効なコードです。", "error")

    return render_template("confirm_email.html",user=current_user)


