from flask import request, jsonify
from flask_restx import Resource, Namespace, reqparse
from implemented import user_service
from dao.model.user import User, UserSchema
user_ns = Namespace('user')
user_schema: UserSchema = UserSchema()


@user_ns.route('/')
class UserView(Resource):
    def get(self):
        user = user_service.get_user_by_token(request.headers.get('Authorization'))
        if not user:
            return jsonify({"error": "Invalid token"}), 401
        return jsonify(user), 200

    def patch(self):
        user = user_service.get_user_by_token(request.headers.get('Authorization'))
        if not user:
            return jsonify({"error": "Invalid token"}), 401
        req_json = request.json
        first_name = req_json.get('first_name')
        last_name = req_json.get('last_name')
        favorite_genre = req_json.get('favorite_genre')
        user_service.update_user(user, first_name, last_name, favorite_genre)
        return jsonify({'message': 'User updated successfully'}), 200


@user_ns.route('/password')
class PasswordView(Resource):
    def put(self):
        user = user_service.get_user_by_token(request.headers.get('Authorization'))
        if not user:
            return jsonify({"error": "Invalid token"}), 401
        req_json = request.json
        password_1 = req_json.get('password_1')
        password_2 = req_json.get('password_2')
        if not password_1 or not password_2:
            return jsonify({"error": "Both password_1 and password_2 are required"}), 400
        if password_1 != password_2:
            return jsonify({"error": "password_1 and password_2 must match"}), 400
            user_
