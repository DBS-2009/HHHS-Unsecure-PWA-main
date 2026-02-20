from flask import Flask, render_template, request, redirect, session, send_file
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
import bcrypt
import sqlite3
import os
import time
from waitress import serve

app = Flask(__name__)
csrf = CSRFProtect(app)


# Secret key should be set securely in production
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_secret_key')

# Flask-WTF Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('login')

class SignUpForm(FlaskForm):
    fname = StringField('First Name', validators=[DataRequired()])
    lname = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('create account')


@app.route('/', methods=['GET'])
def login():
    form = LoginForm()
    return render_template('login.html', form=form)


@app.route('/login_validation', methods=['POST'])
def login_validation():
    form = LoginForm()
    if not form.validate_on_submit():
        return redirect('/')

    email = form.email.data
    password = form.password.data

    connection = sqlite3.connect('LoginData.db')
    cursor = connection.cursor()

    # ---------------------------------------------------------
    # SQL INJECTION VULNERABILITY
    # ---------------------------------------------------------
    # This query directly inserts user input into SQL.
    # An attacker could enter:
    # email: ' OR '1'='1
    # password: anything
    # This would log them in without knowing credentials.
    # ---------------------------------------------------------
    query = "SELECT * FROM USERS WHERE email = ?"
    user = cursor.execute(query, (email,)).fetchall()

    if user:
        stored_hash = user[0][3]
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            # Password matches
            pass
        else:
            user = []

    # ---------------------------------------------------------
    # SIDE CHANNEL ATTACK (Timing Attack)
    # ---------------------------------------------------------
    # This artificial delay creates measurable timing differences.
    # Attackers could measure response times to guess valid emails.
    # ---------------------------------------------------------
    # Removed artificial timing differences to prevent timing attacks

    if len(user) > 0:

        # ---------------------------------------------------------
        # BROKEN AUTHENTICATION
        # ---------------------------------------------------------
        # Passwords are stored in plain text.
        # No hashing, no salting.
        # If DB is leaked, all passwords are exposed.
        # ---------------------------------------------------------

        # ---------------------------------------------------------
        # SESSION MANAGEMENT VULNERABILITY
        # ---------------------------------------------------------
        # Storing email directly in session without regeneration.
        # Session fixation possible.
        # ---------------------------------------------------------
        session.clear()
        session['user'] = email

        return redirect(f'/home?fname={user[0][0]}&lname={user[0][1]}&email={user[0][2]}')
    else:
        return redirect('/')


@app.route('/signUp', methods=['GET'])
def signUp():
    form = SignUpForm()
    return render_template('signUp.html', form=form)


@app.route('/home')
def home():

    # ---------------------------------------------------------
    # BROKEN AUTHENTICATION
    # ---------------------------------------------------------
    # No check that a valid session exists.
    # Anyone can manually visit:
    # http://site/home?fname=Admin&lname=User&email=admin@email.com
    # and appear logged in.
    # ---------------------------------------------------------


    if 'user' not in session:
        return redirect('/')

    fname = request.args.get('fname')
    lname = request.args.get('lname')
    email = request.args.get('email')

    # ---------------------------------------------------------
    # CROSS-SITE SCRIPTING (XSS)
    # ---------------------------------------------------------
    # If home.html uses {{ fname|safe }} or similar unsafe rendering,
    # an attacker could pass:
    # ?fname=<script>alert('Hacked')</script>
    # This would execute JavaScript in the victim's browser.
    # ---------------------------------------------------------

    return render_template('home.html', fname=fname, lname=lname, email=email)


@app.route('/add_user', methods=['POST'])
def add_user():
    form = SignUpForm()
    if not form.validate_on_submit():
        return render_template('signUp.html', form=form)

    fname = form.fname.data
    lname = form.lname.data
    email = form.email.data
    password = form.password.data
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    hashed_password = hashed.decode('utf-8')

    connection = sqlite3.connect('LoginData.db')
    cursor = connection.cursor()

    # ---------------------------------------------------------
    # RACE CONDITION
    # ---------------------------------------------------------
    # This check-then-insert pattern is unsafe.
    # If two users register the same email simultaneously,
    # both may pass the check before either inserts.
    # This creates duplicate accounts.
    # Proper fix: UNIQUE constraint + transaction handling.
    # ---------------------------------------------------------
    ans = cursor.execute("SELECT * FROM USERS WHERE email = ?", (email,)).fetchall()

    if len(ans) > 0:
        connection.close()
        return render_template('login.html')
    else:

        # ---------------------------------------------------------
        # SQL INJECTION (again)
        # ---------------------------------------------------------
        # Attacker could inject SQL into fname/lname fields.
        # Example:
        # fname = Robert'); DROP TABLE USERS;--
        # ---------------------------------------------------------
        cursor.execute(
            "INSERT INTO USERS(first_name,last_name,email,password) VALUES (?, ?, ?, ?)",
            (fname, lname, email, hashed_password)
        )
        connection.commit()
        connection.close()

        return render_template('login.html')


@app.route('/redirect_me')
def redirect_me():

    # ---------------------------------------------------------
    # OPEN / INVALID REDIRECT
    # ---------------------------------------------------------
    # This blindly redirects to a user-supplied URL.
    # An attacker could craft:
    # /redirect_me?next=https://malicious-site.com
    # Victims trust the domain and get redirected to phishing site.
    # ---------------------------------------------------------
    from urllib.parse import urlparse, urljoin
    next_url = request.args.get('next')
    def is_safe_url(target):
        ref_url = urlparse(request.host_url)
        test_url = urlparse(urljoin(request.host_url, target))
        return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

    if next_url and is_safe_url(next_url):
        return redirect(next_url)
    return redirect('/')


@app.route('/download')
def download():

    # ---------------------------------------------------------
    # FILE ATTACK (Path Traversal)
    # ---------------------------------------------------------
    # User controls filename.
    # Attacker could request:
    # /download?file=../../../../etc/passwd
    # and retrieve sensitive server files.
    # ---------------------------------------------------------
    from werkzeug.utils import secure_filename
    filename = request.args.get('file')
    safe_dir = os.path.join(os.getcwd(), 'static')
    safe_filename = secure_filename(filename)
    file_path = os.path.join(safe_dir, safe_filename)
    if not os.path.isfile(file_path):
        return "File not found", 404
    return send_file(file_path)


@app.route('/transfer_money', methods=['POST'])
def transfer_money():

    # ---------------------------------------------------------
    # CROSS-SITE REQUEST FORGERY (CSRF)
    # ---------------------------------------------------------
    # No CSRF token validation.
    # If a logged-in user visits a malicious site,
    # that site could auto-submit a form to this endpoint
    # and perform actions without the user's consent.
    # ---------------------------------------------------------

    amount = request.form.get('amount')
    recipient = request.form.get('recipient')

    return f"Transferred ${amount} to {recipient}"


if __name__ == '__main__':
    app.run(debug=True)
