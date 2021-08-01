from datetime import datetime
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import jwt
import os
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'you-would-not-believe-it'
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
    password = db.Column(db.String(20))
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
            return jsonify({'message': 'a valid token is missing'})
        try:
            data = jwt.decode(token, app.config[SECRET_KEY])
            current_user = Users.query.filter_by(is_active=data['is_active']).first()
        except:
            return jsonify({'message': 'the token is invalid'})
            return f(current_user, *args, **kwargs)
    return decorator

@app.route('/register', methods=['GET', 'POST'])
def signup_user():  
    data = request.get_json()  
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = Users(username=data['username'], password=hashed_password, is_active=True, is_superuser=False) 
    db.session.add(new_user)  
    db.session.commit()    
    return jsonify({'message': 'registered successfully'})


# if __name__ == "__main__":
#     # db setup only! run once!
#     db.drop_all()  # destroy all the tables.
#     db.create_all()  # create all fresh new tables.