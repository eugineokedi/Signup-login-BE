import os
from flask import Flask
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_restful import Api

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# General Configurations
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'super-secret-key')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'super-secret-key')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Environment-based Database URI Configuration
env = os.getenv('FLASK_ENV', 'development')

if env == 'production':
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
else:
    # Default to SQLite for development and testing
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
cors = CORS(app)
api = Api(app)
