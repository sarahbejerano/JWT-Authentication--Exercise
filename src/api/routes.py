"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_jwt_extended import create_access_token,jwt_required,get_jwt_identity
from argon2 import PasswordHasher


ph = PasswordHasher()

api = Blueprint('api', __name__)


@api.route('/hello', methods=['POST', 'GET'])
@jwt_required()
def handle_hello():
    current_user_id = get_jwt_identity()

    user = User.query.filter(User.id == current_user_id).first()

    response_body = {
        "message": f"Hello! I'm {user.email}"
    }
    return jsonify(response_body), 200


# we're creating a register endpoint (but all the endpoints have api in the beggining)

@api.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()

# Check if User exists

    if User.query.filter(User.email == data['email']).count() > 0:
        return 'user-exists', 400

#create a user using the user model 

    user = User (
        email=data['email'], 
        password=ph.hash(data['password']),
        is_active=True
    )

# we add the user to the session using db

    db.session.add(user)
    db.session.commit()

    return '', 204

@api.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    user = User.query.filter(User.email == data['email']).first()
    if user is None:
        return '', 404

    print(user.password)
    print(data['password'])

    try:
        ph.verify(user.password, data['password'])
    except:
        return 'wrong-password', 400
        

    access_token = create_access_token(identity=user.id)
    return jsonify({'token': access_token, 'user_id': user.id})

# No Content success status response this operation is succesful, and this don't return anything