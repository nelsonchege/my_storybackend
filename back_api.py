from os import error
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from flask_cors import CORS


app = Flask(__name__)
cors = CORS(app)
cors = CORS(app, resources={r"/*": {"origins": "*"}})
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mystories.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80),unique=True)
    username = db.Column(db.String(50),unique=True)
    password = db.Column(db.String(80))

class UserProfile(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(100), unique=True)
  email = db.Column(db.String(200))
  first_name = db.Column(db.String(200))
  second_name = db.Column(db.String(200))
  gender = db.Column(db.String(200))
  birthday = db.Column(db.String(200))
  phone_number = db.Column(db.String(200))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(username=data['username']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated
#creating a new  user account
@app.route('/signup',methods=['POST'])
# @token_required
def create_user():
    # data = request.get_json()
    username = request.json['username_signup']
    password = request.json['password_signup']
    email = request.json['email_signup']
    hashed_password = generate_password_hash(password, method='sha256')

    new_user = User(username=username,email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user created!'})


#creating a new profile
@app.route('/createprofile',methods=['POST'])
@token_required
def create_user_profile(current_user):
    data = request.get_json()
    new_user = UserProfile(username=data['username'],gender=data['gender'],
    birthday=data['birthday'],phone_number=data['phone_number'],email=data['email'],
    first_name=data['first_name'],second_name=data['second_name'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message' : 'New profile created!'})


#getting all user
@app.route('/getalluser',methods=['GET'])
# @token_required
def get_all_user():
    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['username'] = user.username
        user_data['email'] = user.email
        user_data['password'] = user.password
        output.append(user_data)

    return jsonify({'users' : output})


#getting one user
@app.route('/getoneuser/<id>',methods=['GET'])
@token_required
def get_user(current_user,id):
    user = User.query.filter_by(id=id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})
    user_data = {}
    user_data['id'] = user.id
    user_data['username'] = user.username
    user_data['email'] = user.email
    user_data['password'] = user.password

    return jsonify({'users' : user_data})

#getting user profile
@app.route('/getprofile/<id>',methods=['GET'])
@token_required
def get_user_profile(current_user,id):
    userprofile = UserProfile.query.filter_by(id=id).first()

    if not userprofile:
        return jsonify({'message' : 'No profile found!'})
        
    user_data = {}
    user_data['id'] = userprofile.id
    user_data['username'] = userprofile.username
    user_data['email'] = userprofile.email
    user_data['first_name'] = userprofile.first_name
    user_data['second_name'] = userprofile.second_name
    user_data['gender'] = userprofile.gender
    user_data['birthday'] = userprofile.birthday
    user_data['phone_number'] = userprofile.phone_number

    return jsonify({'users' : user_data})


#updating profile
@app.route('/updateprofile',methods=['PUT'])
def update_user_profile():
    return 'testing heroku servers'

# login in and geting a token
@app.route('/login' ,methods=['POST'])
def login():
    username = request.json['username_login']
    password = request.json['password_login']
    
    user = User.query.filter_by(username=username).first()
    if (user.username==username):
        return jsonify(username=user.username,email=user.email)
    # else:
    #     return error({"message":error})
    # # if not auth or not auth.username or not auth.password:
    #     return make_response('Could not verify', 404, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    # user = User.query.filter_by(username=auth.username).first()

    # if not user:
    #     return make_response('Could not verify', 403, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    # if check_password_hash(user.password, auth.password):
    #     token = jwt.encode({'id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

    #     return jsonify({'token' : token})

    # return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
if __name__=='__main__':
    app.run(debug=True)
