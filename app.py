from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'drillengine_secret_key'

# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///drillengine.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    scans = db.relationship('ScanResult', backref='user', lazy=True)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(200), nullable=False)
    result = db.Column(db.Text, nullable=False)
    scanned_on = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Routes
@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('signup'))

        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        session['user_id'] = user.id
        session['username'] = user.username
        return redirect(url_for('dashboard'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('landing'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    scans = ScanResult.query.filter_by(user_id=user_id).order_by(ScanResult.scanned_on.desc()).all()
    return render_template('dashboard.html', scans=scans)

@app.route('/index')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    url = request.form['url']
    dummy_result = f"Scan complete for {url}. No critical issues found."

    scan = ScanResult(url=url, result=dummy_result, user_id=session['user_id'])
    db.session.add(scan)
    db.session.commit()
    return redirect(url_for('results', scan_id=scan.id))

@app.route('/results/<int:scan_id>')
def results(scan_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    scan = ScanResult.query.get_or_404(scan_id)
    if scan.user_id != session['user_id']:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))
    return render_template('results.html', scan=scan)

@app.route('/download/<int:scan_id>')
def download(scan_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    scan = ScanResult.query.get_or_404(scan_id)
    if scan.user_id != session['user_id']:
        flash("Unauthorized", "danger")
        return redirect(url_for('dashboard'))

    filename = f"scan_report_{scan.id}.txt"
    filepath = os.path.join("temp", filename)
    os.makedirs("temp", exist_ok=True)
    with open(filepath, "w") as f:
        f.write(scan.result)

    return send_file(filepath, as_attachment=True)

# Initialize DB if not exists
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
