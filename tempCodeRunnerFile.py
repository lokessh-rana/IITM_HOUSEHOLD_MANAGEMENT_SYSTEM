from flask import Flask, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from forms import RegistrationForm, LoginForm
from models import db, User, Service, ServiceRequest
from config import Config
from functools import wraps

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

# Helper to check admin access
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in session and session.get('role') == 'admin':
            return f(*args, **kwargs)
        else:
            flash('Administrator access required to view this page.', 'warning')
            return redirect(url_for('login'))
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data, role=form.role.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash(f'Account created for {form.username.data}!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            session['username'] = user.username
            session['role'] = user.role
            flash(f'Welcome back, {user.username}!', 'success')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'service_professional':
                return redirect(url_for('service_professional_dashboard'))
            else:
                return redirect(url_for('customer_dashboard'))
        else:
            flash('Login unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/customer/dashboard')
def customer_dashboard():
    if 'username' in session and session.get('role') == 'customer':
        return render_template('customer_dashboard.html', username=session['username'])
    else:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

@app.route('/professional/dashboard')
def service_professional_dashboard():
    if 'username' in session and session.get('role') == 'service_professional':
        return render_template('professional_dashboard.html', username=session['username'])
    else:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
