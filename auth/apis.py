import re
from flask import Flask, request, jsonify, make_response
from common.bcrypt import bcrypt
from marshmallow import Schema, fields, ValidationError, validates
from auth.model import Auth
import jwt, os
from datetime import datetime, timedelta
from flask import Blueprint
from db import db

auth_blueprint = Blueprint('auth', __name__)

class AuthRegistrationSchema(Schema):
    username = fields.String(required=True)
    email = fields.String(required=True)
    role = fields.String(required=True)
    password = fields.String(required=True)

    @validates('email')
    def validate_email(self, value):
        if not re.match(r"[^@]+@[^@]+\.[^@]+", value):
            raise ValidationError("Your Email Format is Invalid")
        
@auth_blueprint.route('/registration', methods=['POST'])
def registration():
    data = request.get_json()
    schema = AuthRegistrationSchema()
    try:
        data = schema.load(data)
    except ValidationError as err:
        return {"error": err.messages}, 400
    
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = Auth(username=data['username'], email=data['email'], role=data['role'],password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return {
        'id': new_user.id,
        'username': new_user.username
    }

@auth_blueprint.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    username = data["username"]
    password = data["password"]

    user = Auth.query.filter_by(username=username).first()
    if not user:
        return {"error": "User or password is not valid"}, 400
    
    valid_password = bcrypt.check_password_hash(user.password, password)
    if not valid_password:
        return {"error": "User or password is not valid"}, 400
    
    payload = {
        'user_id': user.id,
        'username': user.username,
        'role': user.role,
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(minutes=60)
    }
    token = jwt.encode(payload, os.getenv('SECRET_KEY'), algorithm="HS256")
    
    response_data = {
        'id': user.id,
        'username': user.username,
        'token': token
    }

    response = make_response(jsonify(response_data))
    response.headers['Authorization'] = "Bearer" + token

    return response

blacklisted_tokens = set()

@auth_blueprint.route("/logout", methods=["GET"])
def logout():
    token = request.headers.get('Authorization')

    if not token or not token.startswith('Bearer '):
        return {"error": "Invalid token"}, 401

    token = token.split(' ')[1]
    blacklisted_tokens.add(token)
    return {"message": "Logout successful"}