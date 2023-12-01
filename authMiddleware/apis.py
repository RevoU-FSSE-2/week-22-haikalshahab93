from functools import wraps
import os
from flask import abort, request
import jwt


def role_required(required_role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get('Authorization')

            if auth_header is None:
                abort(401)

            token = auth_header.split(" ")[1]

            try:
                secret_key = os.getenv('SECRET_KEY')
                decoded_token = jwt.decode(token, secret_key, algorithms=['HS256'])
                if 'role' not in decoded_token or decoded_token['role'] != required_role:
                    abort(403)

                return func(*args, **kwargs)

            except jwt.ExpiredSignatureError:
                abort(401)
            except jwt.InvalidTokenError:
                abort(401)

        return wrapper
    return decorator
