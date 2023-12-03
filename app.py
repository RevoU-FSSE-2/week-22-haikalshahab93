import os
from flask import Flask
from db import db, db_init
from flask_cors import CORS
from common.bcrypt import bcrypt
from auth.apis import auth_blueprint
from todolist.apis import todo_blueprint
from firebase_admin import credentials,initialize_app

cred = credentials.Certificate("key.json")
default_app = initialize_app(cred)


app = Flask(__name__)

CORS(app)
cors = CORS(app, resources={r"/api/*": {"origins": "*"}})

@app.after_request
def add_secure_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com/; frame-ancestors 'self'"
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Permissions-Policy'] = "geolocation 'self'; microphone 'none'; camera 'none'"
    return response

database_url = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_DATABASE_URI'] = database_url

db.init_app(app)
bcrypt.init_app(app)

app.register_blueprint(auth_blueprint, url_prefix="/auth")
app.register_blueprint(todo_blueprint, url_prefix="/todolist")
