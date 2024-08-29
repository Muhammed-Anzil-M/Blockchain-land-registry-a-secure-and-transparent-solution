from flask import Flask, render_template, url_for, flash, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, LoginManager, login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secrets.token_hex(16)'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/land_reg'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'buyer', 'seller', 'officer'

class LandRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.String(150), nullable=False)
    details = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='Pending')  # 'Pending', 'Approved', 'Rejected'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    file_url = db.Column(db.String(150), nullable=False)

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('buyer', 'Buyer'), ('seller', 'Seller'), ('officer', 'Officer')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class UploadForm(FlaskForm):
    details = TextAreaField('Land Details', validators=[DataRequired()])
    file_url = StringField('File URL', validators=[DataRequired()])
    submit = SubmitField('Upload')

# Routes
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html', title='Home')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, role=form.role.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if current_user.role == 'buyer' or current_user.role == 'seller':
        form = UploadForm()
        if form.validate_on_submit():
            record = LandRecord(owner=current_user.username, details=form.details.data, file_url=form.file_url.data, user_id=current_user.id)
            db.session.add(record)
            db.session.commit()
            flash('Land details uploaded successfully', 'success')
            return redirect(url_for('dashboard'))
        return render_template('upload.html', title='Upload Land Details', form=form)
    elif current_user.role == 'officer':
        records = LandRecord.query.filter_by(status='Pending').all()
        return render_template('dashboard.html', title='Dashboard', records=records)
    else:
        return redirect(url_for('home'))

@app.route('/approve/<int:record_id>')
@login_required
def approve(record_id):
    if current_user.role == 'officer':
        record = LandRecord.query.get_or_404(record_id)
        record.status = 'Approved'
        db.session.commit()
        flash('Record approved', 'success')
    return redirect(url_for('dashboard'))

@app.route('/reject/<int:record_id>')
@login_required
def reject(record_id):
    if current_user.role == 'officer':
        record = LandRecord.query.get_or_404(record_id)
        record.status = 'Rejected'
        db.session.commit()
        flash('Record rejected', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
