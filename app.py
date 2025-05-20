from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.utils import secure_filename
import os
import subprocess
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///drillengine.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB limit

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User and Scan models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    profile_pic = db.Column(db.String(200))
    email_alerts = db.Column(db.Boolean, default=True)
    using_2fa = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    target_url = db.Column(db.String(255))
    result = db.Column(db.Text)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

# Load user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def run_nmap_scan(target):
    try:
        result = subprocess.check_output(['nmap', '-F', target], stderr=subprocess.STDOUT).decode()
        return result
    except subprocess.CalledProcessError as e:
        return e.output.decode()

def send_email_alert(to_email, subject, body):
    try:
        from_email = os.getenv('ALERT_EMAIL_ADDRESS')
        password = os.getenv('ALERT_EMAIL_PASSWORD')
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = from_email
        msg['To'] = to_email

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(from_email, password)
            smtp.sendmail(from_email, to_email, msg.as_string())
    except Exception as e:
        print(f"Email error: {e}")

@app.route('/profile')
@login_required
def profile():
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()).all()
    return render_template('profile.html', user=current_user, scans=scans)

@app.route('/scan', methods=['POST'])
@login_required
def scan():
    try:
        target_url = request.form['target_url']
        scan_result = run_nmap_scan(target_url)
        new_scan = Scan(user_id=current_user.id, target_url=target_url, result=scan_result)
        db.session.add(new_scan)
        db.session.commit()

        if current_user.email_alerts:
            send_email_alert(current_user.email, "New Scan Completed", f"Scan of {target_url} completed.")

        flash('Scan completed successfully.', 'success')
    except Exception as e:
        flash(f'Scan failed: {str(e)}', 'danger')
    return redirect(url_for('profile'))

@app.route('/upload_picture', methods=['POST'])
@login_required
def upload_picture():
    if 'profile_pic' not in request.files:
        flash('No file selected.', 'danger')
        return redirect(url_for('profile'))

    file = request.files['profile_pic']
    if file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('profile'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)

        current_user.profile_pic = filename
        db.session.commit()
        flash('Profile picture updated.', 'success')
    else:
        flash('Invalid file type.', 'danger')
    return redirect(url_for('profile'))

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    current_user.first_name = request.form['first_name']
    current_user.last_name = request.form['last_name']
    current_user.phone = request.form['phone']
    current_user.address = request.form['address']
    db.session.commit()
    flash('Profile updated successfully.', 'success')
    return redirect(url_for('profile'))

@app.route('/update_security', methods=['POST'])
@login_required
def update_security():
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    current_user.email = email
    if password and password == confirm_password:
        current_user.password = password
    current_user.using_2fa = 'enable_2fa' in request.form
    db.session.commit()
    flash('Security settings updated.', 'success')
    return redirect(url_for('profile'))

@app.route('/update_settings', methods=['POST'])
@login_required
def update_settings():
    current_user.email_alerts = 'email_alerts' in request.form
    db.session.commit()
    flash('Settings updated.', 'success')
    return redirect(url_for('profile'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
