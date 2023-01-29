import calendar
import datetime
import base64
import hashlib
import hmac
from typing import Dict, Any, List

import jwt
from flask_restx import abort

from config import Config
from dao.model.user import User

from dao.user import UserDAO



class UserService:
    dao: UserDAO

    def __init__(self, dao: UserDAO) -> None:
        self.dao = dao

    def get_one(self, user_id: int) -> User:
        return self.dao.get_one(user_id)

    def get_by_email(self, email: str) -> User:
        return self.dao.get_by_email(email)

    def get_all(self) -> List[User]:
        return self.dao.get_all()

    def update(self, user_id: int, data: Dict[str, Any]) -> User:
        user_by_id: User = self.dao.get_one(user_id)
        for k, v in data.items():
            if k == "password":
                setattr(user_by_id, k, self.encode_password(v))
            else:
                setattr(user_by_id, k, v)
        return self.dao.update(user_by_id)

    def update_password(self, user_id: int, data: Dict[str, Any]) -> User:
        user_by_id: User = self.dao.get_one(user_id)
        password_1 = data.get('password_1')
        password_2 = data.get('password_2')

        if password_1 is None or password_2 is None:
            abort(401)

        if not self.compare_passwords(user_by_id.password, password_1):
            raise abort(400)

        if password_1 == password_2:
            abort(401)

        new_password: str = self.encode_password(password_2)
        user_by_id.password = new_password
        return self.dao.update(user_by_id)


    def create_user(self, data: Dict[str, Any]) -> User:

        if self.dao.get_by_email(data['email']) is not None:
            abort(400)

        encoded_password: str = self.encode_password(data['password'])
        data['password'] = encoded_password

        user: User = User(data)
        return self.dao.create(user)


    def delete(self, user_id: int) -> None:
        self.dao.delete(user_id)

    def encode_password(self, password: str) -> str:
        return base64.b64encode(hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            Config.PWD_HASH_SALT, Config.PWD_HASH_ITERATIONS
        )).decode("utf-8")

    def compare_passwords(self, password_hash: str, other_password: str) -> bool:

        return hmac.compare_digest(
            base64.b64decode(password_hash.encode('utf-8')),
            hashlib.pbkdf2_hmac('sha256', other_password.encode('utf-8'),
                                Config.PWD_HASH_SALT, Config.PWD_HASH_ITERATIONS)
        )

    def generate_access_token(self, data: Dict[str, Any]) -> str:
        min30: datetime.datetime = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data["exp"] = calendar.timegm(min30.timetuple())
        return jwt.encode(data, Config.JWT_SECRET, algorithm=Config.JWT_ALGO)

    def generate_refresh_token(self, data: Dict[str, Any]) -> str:
        day130: datetime.datetime = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data["exp"] = calendar.timegm(day130.timetuple())
        return jwt.encode(data, Config.JWT_SECRET, algorithm=Config.JWT_ALGO)

# import calendar
# import datetime
# import base64
# import hashlib
# import hmac
# from typing import Dict, Any, List
#
# import jwt
# from flask_restx import abort
# from config import Config
# from dao.model.user import User
#
# from dao.user import UserDAO
#
#
# class UserService:
#     dao: UserDAO
#
#     def __init__(self, dao: UserDAO) -> None:
#         self.dao = dao
#
#     def get_one(self, user_id: int) -> User:
#         return self.dao.get_one(user_id)
#
#     def get_by_name(self, username: str) -> User:
#         return self.dao.get_by_name(username)
#
#     def get_all(self) -> List[User]:
#         return self.dao.get_all()
#
#     def update(self, user_id: int, data: Dict[str, Any]) -> User:
#         user_by_id: User = self.dao.get_one(user_id)
#         for k, v in data.items():
#             if k == "password":
#                 setattr(user_by_id, k, self.encode_password(v))
#             else:
#                 setattr(user_by_id, k, v)
#         return self.dao.update(user_by_id)
#
#
#     def create(self, data: Dict[str, Any]) -> User:
#
#         encoded_password: str = self.encode_password(data['password'])
#         data['password'] = encoded_password
#
#         user: User = User(**data)
#         return self.dao.create(user)
#
#     def delete(self, user_id: int) -> None:
#         self.dao.delete(user_id)
#
#     def encode_password(self, password: str) -> str:
#         return base64.b64encode(hashlib.pbkdf2_hmac(
#             'sha256',
#             password.encode('utf-8'),
#             Config.PWD_HASH_SALT, Config.PWD_HASH_ITERATIONS
#         )).decode("utf-8")
#
#     def compare_passwords(self, password_hash: str, other_password: str) -> bool:
#
#         return hmac.compare_digest(
#             base64.b64decode(password_hash.encode('utf-8')),
#             hashlib.pbkdf2_hmac('sha256', other_password.encode('utf-8'),
#                                 Config.PWD_HASH_SALT, Config.PWD_HASH_ITERATIONS)
#         )
#
#     def generate_access_token(self, data: Dict[str, Any]) -> str:
#         min30: datetime.datetime = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
#         data["exp"] = calendar.timegm(min30.timetuple())
#         return jwt.encode(data, Config.JWT_SECRET, algorithm=Config.JWT_ALGO)
#
#     def generate_refresh_token(self, data: Dict[str, Any]) -> str:
#         day130: datetime.datetime = datetime.datetime.utcnow() + datetime.timedelta(days=130)
#         data["exp"] = calendar.timegm(day130.timetuple())
#         return jwt.encode(data, Config.JWT_SECRET, algorithm=Config.JWT_ALGO)
#
    def get_user_by_token(token, decode_token=None):
        # Decode token and get user ID
        try:
            user_id = decode_token(token)
        except Exception as e:
            return None

        # Get user by ID
        from implemented import user_service
        return user_service.get_one(user_id)