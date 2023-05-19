from typing import Union
import datetime
from typing import List
from pydantic import BaseModel

import sqlalchemy
from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from passlib.context import CryptContext
from jose import JWTError, jwt

Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class UserIn(BaseModel):
    username: str
    password: str


class User(Base):
    __tablename__ = "Users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String)
    hash_password = Column(String)
    enabled = Column(Boolean)

class ChatIn(BaseModel):
    title: str
    user_id: int


class Chat(Base):
    __tablename__ = "Chats"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    created_at = Column(DateTime)
    user_id = Column(Integer)

class MessageIn(BaseModel):
    chat_id: int
    content: str

class Message(Base):
    __tablename__ = "Messages"
    id = Column(Integer, primary_key=True, index=True)
    chat_id = Column(Integer)
    created_at = Column(DateTime)
    content = Column(String)


class Database:

    def __init__(self, database_url):
        self.engine = sqlalchemy.create_engine(database_url)
        self.Session = sessionmaker(autocommit=False, bind=self.engine)


    def get_user_by_username(self, username: str):
        session = self.Session()
        try:
            return session.query(User).filter( User.username == username ).first()
        except:
            return {"status": "error", "message": "system error"}
        finally:
            session.close()

    def get_user_by_credencials(self, user: UserIn):
        session = self.Session()
        try:
            userInDb = session.query(User).filter( User.username == user.username ).first()

            if (userInDb != None):
                if (not pwd_context.verify(user.password, userInDb.hash_password)):
                    return {"status": "error", "message": "Bad Credentials", "access_token": "", "token_type": ""}
                else:
                    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
                    access_token = self.create_access_token(
                        data={"sub": user.username, "scopes": ['me', 'chats', 'messages']},
                        expires_delta=access_token_expires,
                    )
                    return {"status": "ok", "access_token": access_token, "token_type": "bearer"}
            else:
                 {"status": "error", "message": "User not Exist", "access_token": "", "token_type": ""}
        except:
            return {"status": "error", "message": "system error", "access_token": "", "token_type": ""}
        finally:
            session.close()

    def create_access_token(data: dict, expires_delta: Union[datetime.timedelta, None] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + datetime.timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    def create_user(self, user: UserIn):
        session = self.Session()
        try:
            
            if (session.query(User).filter( User.username == user.username ).first() == None):

                hash = pwd_context.hash(user.password)

                new_user = User(username=user.username, hash_password=hash, enabled=True)
                session.add(new_user)
                session.commit()
                return {"status": "ok", "message": "User Created"}
            else:
                return {"status": "error", "message": "User Exist"}
            
        except:
            session.rollback()
            return {"status": "error", "message": "system error"}
        finally:
            session.close()

    def create_chat(self, chat: ChatIn):

        session = self.Session()
        try:
            
            new_chat = Chat(title=chat.title, created_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id=chat.user_id)
            session.add(new_chat)
            session.commit()
            return {"status": "ok", "message": "Chat Created"}
            
        except:
            session.rollback()
            return {"status": "error", "message": "system error"}
        finally:
            session.close()

    def get_chats_by_userid(self, user_id: int):
        session = self.Session()
        try:
            return session.query(Chat).filter(Chat.user_id == user_id).order_by(Chat.created_at.desc()).all()
        except:
            return {"status": "error", "message": "system error"}
        finally:
            session.close()

    def create_message(self, message: MessageIn):

        session = self.Session()
        try:
            
            new_message = Message(title=message.chat_id, created_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'), content=message.content)
            session.add(new_message)
            session.commit()
            return {"status": "ok", "message": "Message Created"}
            
        except:
            session.rollback()
            return {"status": "error", "message": "system error"}
        finally:
            session.close()

    def get_messages_by_chatid(self, chat_id: int):
        session = self.Session()
        try:
            return session.query(Message).filter(Message.chat_id == chat_id).order_by(Message.created_at.desc()).all()
        except:
            return {"status": "error", "message": "system error"}
        finally:
            session.close()