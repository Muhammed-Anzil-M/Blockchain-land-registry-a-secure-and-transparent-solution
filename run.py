from flask import Flask, render_template, url_for, flash, redirect, request
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, LoginManager, login_user, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo
from datetime import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secrets.token_hex(16)'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/land_registry'
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


class Request(db.Model):
    __tablename__ = 'request'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    land_record_id = db.Column(db.Integer, db.ForeignKey('landrecord.id'), nullable=False)  # Corrected table name
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='Pending')

    user = db.relationship('User', backref='requests', lazy=True)
    land_record = db.relationship('LandRecord', backref='requests', lazy=True,
                                  foreign_keys=[land_record_id])  # Explicitly specify the foreign key


class LandRecord(db.Model):
    __tablename__ = 'landrecord'
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.String(150), nullable=False)
    details = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='Pending')  # 'Pending', 'Approved', 'Rejected'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    file_url = db.Column(db.String(150), nullable=False)
    sellable = db.Column(db.Boolean, default=False)  # Add this line for the sellable column


# Forms
class RegistrationForm(FlaskForm):
    __tablename__ = 'user'
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
    if current_user.role == 'officer':
        # Government officers see all records
        records = LandRecord.query.all()
        return render_template('gov_dashboard.html', title='Available Land', records=records)
    else:
        # Regular users only see approved records
        records = LandRecord.query.filter_by(sellable=True).all()
        return render_template('dashboard.html', title='Available Land', records=records)


@app.route('/add_land', methods=['GET', 'POST'])
@login_required
def add_land():
    form = UploadForm()
    if form.validate_on_submit():
        record = LandRecord(owner=current_user.username, details=form.details.data, file_url=form.file_url.data, user_id=current_user.id)
        db.session.add(record)
        db.session.commit()
        flash('Land details added successfully', 'success')
        return redirect(url_for('sell'))
    return render_template('add_land.html', title='Add New Land', form=form)

@app.route('/sell', methods=['GET', 'POST'])
@login_required
def sell():
    records = LandRecord.query.filter_by(owner=current_user.username).all()
    return render_template('sell.html', title='Your Land Details', records=records)

@app.route('/sell_land/<int:record_id>')
@login_required
def update_sellable_to_true(record_id):
    record = LandRecord.query.get(record_id)
    if record:
        record.sellable = True
        db.session.commit()
        flash('Record approved', 'success')
    return redirect(url_for('sell'))



@app.route('/approve/<int:record_id>')
@login_required
def approve(record_id):
    if current_user.role == 'officer':
        record = LandRecord.query.get_or_404(record_id)
        record.status = 'Approved'
        db.session.commit()
        flash('Record approved', 'success')
    return redirect(url_for('dashboard'))

@app.route('/create_request/<int:record_id>', methods=['POST'])
@login_required
def create_request(record_id):
    land_record = LandRecord.query.get(record_id)
    if land_record:
        new_request = Request(user_id=current_user.id, land_record_id=record_id)
        db.session.add(new_request)
        db.session.commit()
        flash('Request has been sent.', 'success')
    return redirect(url_for('sell'))


@app.route('/profile')
@login_required
def profile():
    user = current_user
    lands = LandRecord.query.filter_by(owner=current_user.username).all()
    return render_template('profile.html', title='Your Profile', user=user, lands=lands)

@app.route('/reject/<int:record_id>', methods=['POST'])
@login_required
def reject(record_id):
    if current_user.role == 'officer':
        record = LandRecord.query.get_or_404(record_id)
        record.status = 'Rejected'
        comment = request.form.get('comment')
        if comment:
            record.comment = comment  # Assuming you have a comment field in your model
        db.session.commit()
        flash('Record rejected', 'danger')
    return redirect(url_for('dashboard'))



if __name__ == '__main__':
    app.run(debug=True)
