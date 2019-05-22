from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
import os
from sqlalchemy import MetaData
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from dotenv import load_dotenv
from flask_cors import CORS

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dasdsdadsadsadsadsadsddasdas'

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:%(pw)s@%(host)s:\
%(port)s/%(db)s' % POSTGRES
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False



db = SQLAlchemy(app)

login = LoginManager(app)
migrate = Migrate(app, db)
CORS(app)

@login.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route("/")
def index():
    return "documate homepage"


@app.route('/signin', methods=['POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        mail = data['mail']
        password = data['password']
        user = User.query.filter_by(mail=mail).first()

        if user is not None and user.check_password(password):
            login_user(user)
            return jsonify({
                "name": current_user.name,
            })
        else:
            return jsonify({
                "message": "somthing wrong"
            })


@app.route('/signup', methods=['POST'])
def signup():
    if request.method == 'POST':
        data = request.get_json()
        mail = data['mail']
        password = data['password']
        name = data['name']
        # avatar = data['avatar']

        if User.query.filter_by(mail=mail).first():
            return jsonify({
                'message': "mail already exist"
            })
        elif User.query.filter_by(name=name).first():
            return jsonify({
                'message': "username already exist"
            })
        else:
            user = User(name=name, mail=mail)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            return jsonify({
                'message': "signed up",
            })


@app.route('/upload', methods=['POST'])
def upload():
    data = request.get_json()
    if data['category'] is None:
        return jsonify({
                'message': "Please choose a category"
            })
    document = data['document']
    category = data['category']
    name = data['name']
    user_id = int(data['user_id'])

    document = Document(document=document, category=category, user_id=user_id, name=name)

    db.session.add(document)
    db.session.commit()

    return jsonify({
        'message': "uploaded file",
    })


@app.route('/profile')
def profile():
    return 'profile page'


@app.route('/signout')
def logout():
    logout_user()

    return jsonify({
                "message": "logged out!",
            })


@app.route('/documentlist/<category>', methods=['GET'])
def documentlist(category):
    if category == "all":
        documents = Document.query.all()
        documentList = []

        for document in documents:
            documentList.append({
                "document": document.document,
                "category": document.category,
                "user_id": document.user_id,
                "name": document.name,
            })

        return jsonify({
            "documentList": documentList
        })
        
    else: 
        documents = Document.query.filter_by(category=category).all()
        documentList = []

        for document in documents:
            documentList.append({
                "document": document.document,
                "category": document.category,
                "user_id": document.user_id,
                "name": document.name,
            })
        return jsonify({
            "documentList": documentList,
            "document category": category
        })


   



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    avatar = db.Column(db.String(750))
    mail = db.Column(db.String(80), index=True, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(80), index=True, unique=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document = db.Column(db.String(500), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)