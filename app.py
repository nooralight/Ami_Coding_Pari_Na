from flask import Flask, render_template, request, redirect, url_for, session
from bcrypt import hashpw, gensalt
from functools import wraps
from model import User


app = Flask(__name__)

def hash_password(password):
    salt = gensalt()
    hashed_password = hashpw(password.encode('utf-8'), salt)
    return hashed_password

def check_password(password, hashed_password):
    return hashpw(password.encode('utf-8'), hashed_password.encode('utf-8')) == hashed_password.encode('utf-8')


def inserIntoUser(username , email, password):
    create_user = User(
        username = username,
        email = email,
        password = password
    )
    create_user.save()
    return create_user


def requires_login(view):
    @wraps(view)
    def decorated_view(*args, **kwargs):
        if 'logged_in' in session:
            return view(*args, **kwargs)
        else:
            return redirect(url_for('login'))
    return decorated_view

@app.route('/')
@requires_login
def home():
    return "Welcome to the home page!"

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.objects(email=email).first()
        if user:
            return "Account has been already registered with this email"
        else:
            new_user = inserIntoUser(username, email, password)
            return redirect(url_for(login))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.objects(email=email).first()
        if user and check_password(password, user.password_hash):
            session['logged_in'] = True
            return redirect(url_for('home'))
        else:
            return "Invalid"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
