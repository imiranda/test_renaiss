from typing import Annotated, List, Union

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    SecurityScopes,
)
from jose import JWTError, jwt
from pydantic import BaseModel, ValidationError

from database import ChatIn, Database, MessageIn, User, UserIn

app = FastAPI()

DATABASE_URL = "mysql://admin:admin..2023!.@renaiss.c2kt3ukuwyi4.us-east-2.rds.amazonaws.com/test1"

db = Database(DATABASE_URL)

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes={"me": "about the current user.", "messages": "read messages", "chats": "list chats"},
)

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class Token(BaseModel):
    status: str
    message: str
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Union[str, None] = None
    scopes: List[str] = []

async def get_current_user(
    security_scopes: SecurityScopes, token: Annotated[str, Depends(oauth2_scheme)]
):
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = "Bearer"
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_scopes = payload.get("scopes", [])
        token_data = TokenData(scopes=token_scopes, username=username)
    except (JWTError, ValidationError):
        raise credentials_exception
    user = db.get_user_by_username(token_data.username)
    if user is None:
        raise credentials_exception
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=401,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )
    return user

async def get_current_active_user(current_user: Annotated[User, Security(get_current_user, scopes=["me", "chats", "messages"])]):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@app.get("/")
def read_root():
    return {"api_status": "Running...", "message": "please visit http://127.0.0.1:8000/docs"}

@app.post("/user/login", response_model=Token)
def user_login(user: UserIn):
    return db.get_user_by_credencials(user)

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = UserIn(username=form_data.username, password=form_data.password)
    return db.get_user_by_credencials(user)

@app.post("/user/create")
def user_create(user: UserIn):
    return db.create_user(user)

@app.get("/user/details/{user_name}")
def user_details(user_name: str):
    return db.get_user_by_username(user_name)

@app.post("/chats/create")
def chat_create(chat: ChatIn, current_user: Annotated[User, Security(get_current_active_user, scopes=["chats"])]):
    return db.create_chat(chat)

@app.get("/chats/{user_id}")
def get_chats(user_id: int, current_user: Annotated[User, Security(get_current_active_user, scopes=["chats"])]):
    return db.get_chats_by_userid(user_id)

@app.post("/messages/create")
def message_create(message: MessageIn, current_user: Annotated[User, Security(get_current_active_user, scopes=["messages"])]):
    return db.create_message(message)

@app.get("/messages/{chat_id}")
def read_messages(chat_id: int, current_user: Annotated[User, Security(get_current_active_user, scopes=["messages"])]):
    return db.get_messages_by_chatid(chat_id)

