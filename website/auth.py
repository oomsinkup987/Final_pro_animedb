from hashlib import new
from re import L
from xml.etree.ElementTree import Comment
from flask import Blueprint, render_template, request, flash
from .models import Note, User
from . import db
import json
from werkzeug.security import generate_password_hash, check_password_hash
from flask import redirect, url_for
from flask_login import login_user, login_required, logout_user, current_user, user_logged_in
from tmdbv3api import TMDb
from tmdbv3api import TV
import requests
from oauthlib.oauth2 import WebApplicationClient
 
# Configuration
GOOGLE_CLIENT_ID = "717354770534-43rp3hla02cmeta0nin5n2sg45159kvu.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)


client = WebApplicationClient(GOOGLE_CLIENT_ID)
tmdb = TMDb()
tmdb.api_key = 'c369400f245e2cf5ff6e7311bba5486f'
tmdb.language = 'en'
tmdb.debug = True

auth = Blueprint('auth', __name__)

@auth.route('/', methods=['GET', 'POST'])
@login_required
def home():
    return render_template("home.html")

@auth.route('/page/<name>', methods=['GET', 'POST'])
@login_required
def page(name):
    tv = TV()
    res_name = name
    show = tv.search(res_name)
    for res in show:
        rate = res.vote_average
        pos = res.poster_path
        name = res.name 
        ov = res.overview
    name_dt = name
    return render_template("page.html", user= current_user, dt = ov,n = name_dt, pos= pos,rate= rate)

@auth.route('/chat', methods=['GET', 'POST'])
def chat():
        if request.method == 'POST':
            data_s = request.form.get('data')
            name_anime = request.form.get('ani_name')
            new_note = Note(data=data_s, user_id = current_user.id, ani_name = name_anime)
            l_data = len(data_s)
            l_ani = len(name_anime)
            if l_ani and l_data != 0:
                flash('Comment Successful!', category= 'success')
                db.session.add(new_note)
                db.session.commit()
                
            else:
                flash('Comment again!', category= 'error')
        comm = Note.query.filter_by(user_id = User.id)
        name_use = User.query.filter_by(firstName =User.firstName)
        return render_template("chat.html", user= current_user, data = comm, name_use = name_use)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password,password):
                flash('Logged in Successfully!', category= 'success')

                login_user(user, remember=True)
                return redirect(url_for('auth.home'))
            else:
                flash('Incorect password, try again', category= 'error')
        else: 
            flash('Email does not exist.', category='error')
    return render_template("login.html")


@auth.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/admin', methods=['GET', 'POST'])
def admin():
        name_use = User.query.filter_by(id = User.id)
        return render_template("admin.html",user= name_use)


@auth.route('/signup', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()

        if user:
            flash('Email already exist.', category= 'error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(firstName) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, firstName=firstName, password=generate_password_hash(password1, method='sha256'),account = 'member')
            db.session.add(new_user)
            db.session.commit()


            flash('Account created!', category='success')
            return redirect(url_for('auth.home'))

    return render_template("signup.html", user= current_user)

@auth.route("/login/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
        return render_template("home.html")
    else:
        return "User email not available or not verified by Google.", 400
    user = User(
    id_=unique_id, name=users_name, email=users_email, profile_pic=picture
    )
    if not User.get(unique_id):
        User.create(unique_id, users_name, users_email, picture)

    # Begin user session by logging the user in
    login_user(user
    # Send user back to homepage
    return redirect(url_for("/"))
               
               
@auth.route("/login/google")
def google():
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri= "https://localhost:5000/login/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()
