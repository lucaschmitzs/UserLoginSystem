from flask import Flask, render_template, session, redirect
from functools import wraps
import os
import pymongo

app = Flask(__name__)
app.secret_key = os.urandom(16)

# Database
client = pymongo.MongoClient('localhost', 27017)
db = client.user_login_system

# Decorators


def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect('/')
    return wrap


# Routes
from user import routes


@app.route('/')
def home():
    if 'logged_in' in session:
        return redirect('/dashboard/')
    else:
        return render_template('home.html')


@app.route('/dashboard/')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/update_user/')
@login_required
def update_user():
    return render_template('update_user.html')
