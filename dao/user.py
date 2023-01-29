from typing import List
from sqlalchemy.orm import scoped_session
from dao.model.user import User


class UserDAO:
    session = scoped_session

    def __init__(self, session: scoped_session) -> None:
        self.session = session

    def get_one(self, uid: int) -> User:
        return self.session.query(User).get(uid)

    def get_by_name(self, name: str) -> User:
        return self.session.query(User).filter(User.name == name).one()

    def get_all(self) -> List[User]:
        return self.session.query(User).all()

    def create(self, user: User) -> User:
        self.session.add(user)
        self.session.commit()
        return user

    def delete(self, uid: int) -> None:
        user: User = self.get_one(uid)
        self.session.delete(user)
        self.session.commit()

    def update(self, user_by_id: User) -> User:
        self.session.add(user_by_id)
        self.session.commit()
        return user_by_id




