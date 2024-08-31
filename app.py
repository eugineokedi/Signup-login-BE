from flask import Flask, request, make_response, jsonify
from flask_restful import Api, Resource
from config import jwt, app, api, db
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from models import User


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
        data = request.get_json()
        first_name = data.get("first_name")
        last_name = data.get("last_name")
        email = data.get("email")
        profile_picture = data.get("profile_picture")
        password = data.get("password")

        user = User.query.filter_by(email=email).first()

        if not user:
            try:
                user = User(
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    profile_picture=profile_picture
                )
                user.password_hash = password
                db.session.add(user)
                db.session.commit()

                # Generate access token for the new user
                access_token = create_access_token(identity=user.id)
                return make_response({"user": user.to_dict(), 'access_token': access_token}, 201)
            except Exception as e:
                return make_response({"message": str(e)}, 500)

        else:
            return make_response({'error': "Email already registered, kindly log in"}, 401)    

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