from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
import sqlite3
from flask_bcrypt import Bcrypt
import datetime
import pdfkit
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this in production
bcrypt = Bcrypt(app)

# ========== DB FUNCTIONS ==========

def get_user_by_username(username):
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    conn.close()
    return user

def create_user(username, email, password_hash):
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, password_hash))
    conn.commit()
    conn.close()

def save_scan(user_id, url, result):
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute("INSERT INTO scans (user_id, url, result, scan_date) VALUES (?, ?, ?, ?)",
                (user_id, url, result, datetime.datetime.now()))
    conn.commit()
    conn.close()

def get_scans_by_user(user_id):
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans WHERE user_id = ? ORDER BY scan_date DESC", (user_id,))
    scans = cur.fetchall()
    conn.close()
    return scans

# ========== AUTH DECORATOR ==========

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# ========== ROUTES ==========

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user_by_username(username)
        if user and bcrypt.check_password_hash(user[3], password):
            session['user'] = {'id': user[0], 'username': user[1]}
            return redirect('/index')
        else:
            flash('Invalid username or password', 'danger')
            return redirect('/login')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        create_user(username, email, hashed)
        flash('Account created! You can now log in.', 'success')
        return redirect('/login')
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

@app.route('/index', methods=['GET'])
@login_required
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
@login_required
def scan():
    url = request.form['url']
    result = f"Scan complete for {url}. No major issues detected."  # Placeholder result
    save_scan(session['user']['id'], url, result)
    session['latest_result'] = result
    return redirect('/results')

@app.route('/results')
@login_required
def results():
    result = session.get('latest_result', 'No scan performed.')
    return render_template('results.html', result=result)

@app.route('/download_pdf')
@login_required
def download_pdf():
    result = session.get('latest_result', 'No scan performed.')
    filename = f"scan_result_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
    pdfkit.from_string(result, filename)
    return send_file(filename, as_attachment=True)

@app.route('/dashboard')
@login_required
def dashboard():
    scans = get_scans_by_user(session['user']['id'])
    return render_template('dashboard.html', scans=scans)

if __name__ == '__main__':
    app.run(debug=True)
