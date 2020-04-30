from flask import Flask, request, url_for, render_template, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, current_user, login_user, LoginManager, logout_user, login_required
# from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
# from base64 import b64encode
from flask_socketio import SocketIO, send
from flask_cors import CORS

BASEDIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, static_url_path='/static')
STATIC_FOLDER = os.path.join(BASEDIR, 'static')
PROFILE_PICTURE_PATH = os.path.join(STATIC_FOLDER, 'profile_pictures')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(BASEDIR, 'app.db')
app.secret_key = 'this is the key'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = PROFILE_PICTURE_PATH
db = SQLAlchemy(app)
login = LoginManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")
# migrate = Migrate(app, db)


@login.user_loader
def load_user(id):
    return User.query.get(int(id))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    profile_picture = db.Column(db.String(200))
    bio = db.Column(db.String(500))

    @property
    def name(self):
        return self.first_name+" "+self.last_name

    def set_profile_picture(self, picture):
        filename = secure_filename(picture.filename)
        extension = picture.filename.split('.')[-1]
        saved_name = self.email + "." + extension
        pic_path = os.path.join(PROFILE_PICTURE_PATH,
                                saved_name)
        picture.save(pic_path)
        self.profile_picture = saved_name

    def get_profile_picture(self):
        if self.profile_picture:
            return url_for('static', filename=f"profile_pictures/{self.profile_picture}")
        else:
            return url_for('static', filename=f"profile_pictures/no_profile_pic.webp")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_bio(self):
        return self.bio if self.bio else "Enter Bio"


db.create_all()


@app.route('/')
@app.route('/index/')
def index():
    if current_user.is_authenticated:
        first_name = current_user.first_name
        last_name = current_user.last_name
        image = current_user.get_profile_picture()
        return render_template('index.html', user=current_user)
    else:
        return redirect(url_for('login'))


@app.route('/change_profile', methods=['GET', 'POST'])
@login_required
def change_profile():
    if current_user.is_authenticated:
        if request.method == 'POST':
            if 'profile_pic' in request.files:
                current_user.set_profile_picture(request.files['profile_pic'])
            current_user.bio = request.form['bio']
            db.session.commit()
            return redirect(url_for('index'))
        return render_template('profile.html', user=current_user)


@app.route('/login/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user is None or not user.check_password(request.form['password']):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/signup/', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return render_template(url_for('index'))
    else:
        if(request.method == 'POST'):
            email = request.form['email']
            fname = request.form['first_name']
            lname = request.form['last_name']
            user = User(email=email, first_name=fname, last_name=lname)
            user.set_password(request.form['password'])
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('login.html')


@socketio.on('message')
def on_message(msg):
    print(f"message recieved {msg}")
    send(msg, broadcast=True)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == "__main__":
    socketio.run(app, debug=True)
