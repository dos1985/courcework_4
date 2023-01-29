from flask import request, jsonify
from flask_restx import Resource, Namespace


from implemented import user_service

auth_ns = Namespace('auth')

@auth_ns.route('/register', methods=['POST'])
class RegisterView(Resource):
    def post(self):
        email = request.json.get("email")
        password = request.json.get("password")
        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400
        user = user_service.create_user(email, password)
        if not user:
            return jsonify({"error": "User already exists."}), 400
        return jsonify({"message": "User created successfully."}), 201



@auth_ns.route('/login')
class LoginView(Resource):
    def post(self):
        if not request.is_json:
            return jsonify({"error": "Missing JSON in request"}), 400
        req_json = request.json
        email = req_json.get('email')
        password = req_json.get('password')
        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400
        user = user_service.authenticate(email, password)
        if not user:
            return jsonify({"error": "Invalid email or password"}), 401
        access_token, refresh_token = user_service.create_tokens(user)
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token
        }), 200

@auth_ns.route('/refresh')
class RefreshView(Resource):
    def put(self):
        req_json = request.json
        refresh_token = req_json.get('refresh_token')
        if not refresh_token:
            return jsonify({"error": "refresh_token is required"}), 400
            user = user_service.get_user_by_token(refresh_token)
        if not user:
            return jsonify({"error": "Invalid refresh_token"}), 401
        access_token, new_refresh_token = user_service.create_tokens(user)
        return jsonify({
                "access_token": access_token,
                "refresh_token": new_refresh_token
            }), 200