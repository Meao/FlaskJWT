from datetime import datetime, timedelta
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import jwt
import os
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-would-not-believe-it'
app.config['SECRET_KEY'] = SECRET_KEY
basedir = os.path.abspath(os.path.dirname(__file__))
baseDB = os.path.join(basedir, 'userlist.db')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + baseDB
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)

class Users(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    username = db.Column(db.String(150), nullable=False)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(150))
    password = db.Column(db.String(50), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False)
    last_login = db.Column(db.DateTime, default=datetime.utcnow())
    is_superuser = db.Column(db.Boolean)

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']
        if not token:
            return jsonify({'message': 'a valid token is missing'}), 401
        try:
            data = jwt.decode(token, app.secret_key, algorithms=["HS256"])
            current_user = Users.query.filter_by(id=data['id']).first()
            return f(current_user, *args, **kwargs)
        except jwt.DecodeError:
            return jsonify({'message': 'DecodeError'}), 401
        except jwt.exceptions.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except:
            import sys
            print ("Unexpected error:", sys.exc_info())
            return jsonify({'message': 'the token is invalid'}), 401
    return decorator

@app.route('/register/', methods=['GET', 'POST'])
def signup_user():  
    if request.method == 'POST':
        data = request.get_json()  
        hashed_password = generate_password_hash(data['password'], method='sha256')
        new_user = Users(username=data['username'], password=hashed_password, is_active=True, is_superuser=False) 
        db.session.add(new_user)  
        db.session.commit()    
        return jsonify({'message': 'registered successfully'})
    else:
        return '<p>To sign up post a request body such as {"username" : "nickname", "password" : "password"}.</p>'

@app.route('/login/', methods=['GET', 'POST'])  
def login_user(): 
    auth = request.authorization   
    if auth:
        if not auth.username or not auth.password:  
            return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})
        user = Users.query.filter_by(username=auth.username).first()
        if check_password_hash(user.password, auth.password):  
            user.last_login = datetime.utcnow()
            db.session.merge(user)  
            db.session.commit() 
            token = jwt.encode({'id': user.id, 'exp' : datetime.utcnow() + timedelta(minutes=30)}, app.secret_key)  
            return jsonify({'token' : token}) 
    else:
        return '<p>To log in and get a token use Authorization Type Basic Auth.</p>'

@app.route('/users/', methods=['GET'])
@token_required
def get_all_users(current_user):  
    users = Users.query.all() 
    result = []   
    for user in users:   
        user_data = {}   
        user_data['username'] = user.username 
        user_data['first_name'] = user.first_name 
        user_data['last_name'] = user.last_name 
        user_data['is_active'] = user.is_active 
        user_data['last_login'] = user.last_login  
        user_data['is_superuser'] = user.is_superuser 
        result.append(user_data)   
    return jsonify({'users': result})

@app.route('/users/<id>', methods=['DELETE'])
@token_required
def delete_user(current_user, id):  
    if current_user.is_superuser:
        user_to_del = Users.query.filter_by(id=id).first()   
        if not user_to_del:   
            return jsonify({'message': 'user does not exist'})
        db.session.delete(user_to_del)  
        db.session.commit()   
        return jsonify({'message': 'user deleted'})
    else:
        return '<p>You know how to become a superuser, right?</p>'

@app.route('/users/<id>', methods=['PATCH'])
@token_required
def add_name_user(current_user, id): 
    data = request.get_json()  
    user_to_update = Users.query.filter_by(id=id).first() 
    if not user_to_update:   
        return jsonify({'message': 'user does not exist'})
    user_to_update.first_name = data['first_name']
    user_to_update.last_name = data['last_name']
    if current_user.is_superuser:
        user_to_update.is_active = data['is_active']
        user_to_update.is_superuser = data['is_superuser']
    db.session.merge(user_to_update)   
    db.session.commit() 
    return jsonify({'message': 'user info updated according to your access rights'})


if  __name__ == '__main__':  
    app.run(debug=True)