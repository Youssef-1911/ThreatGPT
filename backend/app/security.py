import os
import datetime as dt
from typing import Optional
from passlib.context import CryptContext
from jose import jwt, JWTError

PWD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")

JWT_SECRET = os.getenv("JWT_SECRET", "dev_secret_change_me")
JWT_ALG = "HS256"
JWT_EXPIRES_DAYS = 7

class TokenError(Exception):
    pass

def hash_password(password: str) -> str:
    return PWD_CONTEXT.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    return PWD_CONTEXT.verify(password, password_hash)

def create_access_token(user_id: str) -> str:
    exp = dt.datetime.utcnow() + dt.timedelta(days=JWT_EXPIRES_DAYS)
    payload = {"sub": user_id, "exp": exp}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def decode_access_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        sub = payload.get("sub")
        if not sub:
            raise TokenError("Invalid token")
        return sub
    except JWTError as exc:
        raise TokenError("Invalid token") from exc
