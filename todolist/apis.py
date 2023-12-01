from enum import Enum
from flask import Blueprint, request
from marshmallow import Schema, fields, ValidationError, validates
from db import db
import jwt
import os
from todolist.model import Todo
from authMiddleware.apis import role_required

todo_blueprint = Blueprint('todo', __name__)

class TodoSchema(Schema):
    user_id = fields.Integer(required=False)
    todo = fields.String(required=True)
    status = fields.String(required=False)

class UserRole(Enum):
    ADMIN = 'admin'
    USER = 'user'

@todo_blueprint.route('', methods=['POST'])
@role_required(UserRole.USER.value)
def create_todo():
    token = request.headers.get('Authorization')
    
    if not token or not token.startswith('Bearer '):
        return {"error": "Invalid token format"}, 400

    token = token.split(' ')[1]

    try:
        secret_key = os.getenv('SECRET_KEY')
        decoded_token = jwt.decode(token, secret_key, algorithms=['HS256'])
        user_id = decoded_token.get('user_id')
        print("Decoded user_id:", user_id)
    except jwt.ExpiredSignatureError:
        print("Expired token")
        return {"error": "Token has expired"}, 401
    except jwt.InvalidTokenError:
        print("Invalid token")
        return {"error": "Invalid token"}, 401

    data = request.get_json()
    schema = TodoSchema()

    data.setdefault('status', 'incomplete')

    try:
        data['user_id'] = user_id
        print("Assigned user_id to data:", data['user_id'])
        data = schema.load(data)
        print("Data after schema load:", data)
    except ValidationError as err:
        return {"error": err.messages}, 400

    new_todo = Todo(user_id=data['user_id'], todo=data['todo'], status=data['status'])
    db.session.add(new_todo)
    db.session.commit()

    return {
        'id': new_todo.id,
        'todo': new_todo.todo,
        'user_id': new_todo.user_id,
        'status': new_todo.status
    }, 201

@todo_blueprint.route('', methods=['GET'])
@role_required(UserRole.USER.value)
def get_todo_byid():
    token_auth = request.headers.get('Authorization')
    if not token_auth or not token_auth.startswith('Bearer '):
        return {"error": "Invalid token format"}, 400

    token = token_auth.split(' ')[1]

    try:
        secret_key = os.getenv('SECRET_KEY')
        decoded_token = jwt.decode(token, secret_key, algorithms=['HS256'])
        user_id = decoded_token.get('user_id')
    except jwt.ExpiredSignatureError:
        return {"error": "Token has expired"}, 401
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}, 401
    
    todos = Todo.query.filter_by(user_id=user_id).all()

    if not todos:
        return {"error": "No todos found for the authenticated user"}, 404
    
    response_data = [{"id": todo.id, "todo": todo.todo, "status": todo.status, "user_id": todo.user_id} for todo in todos]

    return {"todolist": response_data}

@todo_blueprint.route('/update/<int:todo_id>', methods=['PUT'])
@role_required(UserRole.USER.value)
def update_todo(todo_id):
    token_auth = request.headers.get('Authorization')
    if not token_auth or not token_auth.startswith('Bearer '):
        return {"error": "Invalid token format"}, 400

    token = token_auth.split(' ')[1]

    try:
        secret_key = os.getenv('SECRET_KEY')
        decoded_token = jwt.decode(token, secret_key, algorithms=['HS256'])
        user_id = decoded_token.get('user_id')
    except jwt.ExpiredSignatureError:
        return {"error": "Token has expired"}, 401
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}, 401
    
    existing_todo = Todo.query.filter_by(id=todo_id, user_id=user_id).first()
    if not existing_todo:
        return {"error": "Todo not found or you do not have permission to update"}, 404
    
    data = request.get_json()
    schema = TodoSchema()

    try:
        data['user_id'] = user_id
        data = schema.load(data)
    except ValidationError as err:
        return {"error": err.messages}, 400
    
    existing_todo.todo = data['todo']
    existing_todo.status = data['status']
    db.session.commit()

    return {
        'id': existing_todo.id,
        'todo': existing_todo.todo,
        'status': existing_todo.status,
        'user_id': existing_todo.user_id
    }


@todo_blueprint.route('/delete/<int:todo_id>', methods=['DELETE'])
@role_required(UserRole.USER.value)
def delete_todo(todo_id):
    token_auth = request.headers.get('Authorization')
    if not token_auth or not token_auth.startswith('Bearer '):
        return {"error": "Invalid token format"}, 400

    token = token_auth.split(' ')[1]

    try:
        secret_key = os.getenv('SECRET_KEY')
        decoded_token = jwt.decode(token, secret_key, algorithms=['HS256'])
        user_id = decoded_token.get('user_id')
    except jwt.ExpiredSignatureError:
        return {"error": "Token has expired"}, 401
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}, 401
    
    todo_to_delete = Todo.query.filter_by(id=todo_id, user_id=user_id).first()
    if not todo_to_delete:
        return {"error": "Todo not found or you do not have permission to delete"}, 404

    db.session.delete(todo_to_delete)
    db.session.commit()

    return {"message": "Todo successfully deleted"}