from flask import Flask, render_template, request, redirect, session, send_file
import sqlite3
import os
import time
from waitress import serve

app = Flask(__name__)

# ---------------------------------------------------------
# SESSION MANAGEMENT VULNERABILITY
# ---------------------------------------------------------
# Hardcoded secret key.
# If an attacker obtains this key, they can forge session cookies.
# Proper systems store this securely in environment variables. 
# ----------------------------------------------------------
app.secret_key = "insecure-secret-key"


@app.route('/')
def login():
    return render_template('login.html')


@app.route('/login_validation', methods=['POST'])
def login_validation():

    email = request.form.get('email')
    password = request.form.get('password')

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
    query = f"SELECT * FROM USERS WHERE email = '{email}' AND password = '{password}'"
    user = cursor.execute(query).fetchall()

    # ---------------------------------------------------------
    # SIDE CHANNEL ATTACK (Timing Attack)
    # ---------------------------------------------------------
    # This artificial delay creates measurable timing differences.
    # Attackers could measure response times to guess valid emails.
    # ---------------------------------------------------------
    if len(user) > 0:
        time.sleep(0.1)  # shorter delay
    else:
        time.sleep(1)  # longer delay reveals login failure timing

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
        session['user'] = email

        return redirect(f'/home?fname={user[0][0]}&lname={user[0][1]}&email={user[0][2]}')
    else:
        return redirect('/')


@app.route('/signUp')
def signUp():
    return render_template('signUp.html')


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

    fname = request.form.get('fname')
    lname = request.form.get('lname')
    email = request.form.get('email')
    password = request.form.get('password')

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
    ans = cursor.execute(f"SELECT * FROM USERS WHERE email = '{email}'").fetchall()

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
            f"INSERT INTO USERS(first_name,last_name,email,password) "
            f"VALUES('{fname}','{lname}','{email}','{password}')"
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
    next_url = request.args.get('next')
    return redirect(next_url)


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
    filename = request.args.get('file')
    return send_file(filename)


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
    serve(app, host="0.0.0.0", port=8000)
