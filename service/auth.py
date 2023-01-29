from typing import Optional, Dict

from flask_restx import abort
import jwt

from config import Config
from dao.model.user import User
from service.user import UserService


class AuthService:
    user_service: UserService

    def __init__(self, user_service: UserService) -> None:
        self.user_service = user_service

    def generate_tokens(self, email: str, password: Optional[str], is_refresh: bool = False) -> Dict[str, str]:
        user: User = self.user_service.get_by_email(email)

        if user is None:
            raise abort(404)

        if not is_refresh:
            if not self.user_service.compare_passwords(user.password, password):
                raise abort(400)

        data: Dict[str, str] = {
            'email': user.email,
            'role': user.role
        }

        access_token: str = self.user_service.generate_access_token(data)
        refresh_token: str = self.user_service.generate_refresh_token(data)

        return {'access_token': access_token,
                'refresh_token': refresh_token}

    def approve_refresh_taken(self, refresh_token: str):
        data: Dict[str, str] = jwt.decode(jwt=refresh_token, key=Config.JWT_SECRET, algorithms=[Config.JWT_ALGO, ])
        email: Optional[str] = data.get('email', None)
        if email is None:
            raise abort(400)
        return self.generate_tokens(email, None, is_refresh=True)