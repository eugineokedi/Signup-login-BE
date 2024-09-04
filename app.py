from flask import Flask, request, make_response, jsonify
from flask_restful import Api, Resource
from config import jwt, app, api, db
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from models import User
from werkzeug.utils import secure_filename
import os


# Ensure this directory exists
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# User identity lookup for JWT
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()


# User registration
class Signup(Resource):
    def post(self):
        try:
            # Get form data
            first_name = request.form.get("first_name")
            last_name = request.form.get("last_name")
            email = request.form.get("email")
            password = request.form.get("password")

            # Get profile picture file
            profile_picture = request.files.get("profile_picture")

            # Check if email already exists
            user = User.query.filter_by(email=email).first()
            if user:
                return make_response({'error': "Email already registered, kindly log in"}, 401)
            
            # Handle profile picture upload
            if profile_picture:
                filename = secure_filename(profile_picture.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                profile_picture.save(filepath)
            else:
                filepath = None

            # Create new user and hash the password
            user = User(
                first_name=first_name,
                last_name=last_name,
                email=email,
                profile_picture=filepath
            )
            user.password_hash =password
            db.session.add(user)
            db.session.commit()

            # Generate access token
            access_token = create_access_token(identity=user.id)

            # Return response
            return make_response({"user": user.to_dict(), 'access_token': access_token}, 201)

        except Exception as e:
            return make_response({"message": str(e)}, 500)    

api.add_resource(Signup, '/signup')

# User login
class UserLogin(Resource):
    def post(self):
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        user = User.query.filter_by(email=email).first()

        if user and user.authenticate(password):
            access_token = create_access_token(identity=user.id)
            return make_response({"user": user.to_dict(), 'access_token': access_token}, 201)
        
        else:
            return make_response({'error': 'Invalid credentials'}, 401)

api.add_resource(UserLogin, '/login')        

if __name__ == '__main__':
    app.run(debug=True) 