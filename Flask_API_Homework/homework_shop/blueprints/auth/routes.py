from flask import Blueprint, render_template, request, redirect, flash
from werkzeug.security import check_password_hash
from flask_login import login_user, logout_user

#internal imports
from homework_shop.models import User, db
from homework_shop.forms import RegisterForm, LoginForm


auth = Blueprint('auth', __name__, template_folder='auth-templates')

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    registerfrom = RegisterForm()

    if request.method == 'POST' and registerfrom.validate_on_submit():
        first_name = registerfrom.first_name.data
        last_name = registerfrom.last_name.data
        username = registerfrom.username.data
        email = registerfrom.email.data
        password = registerfrom.password.data
        
        print(email, password, username)

        if User.query.filter(User.username == username).first():
            flash("Username already exists. Please Try Again", category='warning')
            return redirect('/signup')
        if User.query.filter(User.email == email).first():
            flash("Email already exists. Please Try Again", category='warning')
            return redirect('/signup')
        

        user = User(username, email, password, first_name, last_name)

        db.session.add(user)
        db.session.commit()


        flash(f"You have successfully registered user {username}", category='success')
        return redirect('/signin')
    
    return render_template('sign_up.html', form=registerfrom)

@auth.route('/signin', methods=['GET', 'POST'])
def signin():

    loginform = LoginForm

    if request.method == 'POST' and loginform.validate_on_submit():
        email = loginform.email.data
        password = loginform.password.data
        print("login info", email, password)

        user = User.query.filter(User.email == email).first()


        if user and check_password_hash(user.password, password):
            login_user(user)
            flash(f"Successfully logged in {email}", category='success')
            return redirect('/')
        else:
            flash("Invalid Email or Password. Please Try Again", category='warning')
            return redirect('/signin')
        
    return render_template('sign_in.html', form=loginform)


@auth.route('/logout')
def logout():
    login_user()
    return redirect('/')

