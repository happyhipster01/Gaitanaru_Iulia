from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import HTTPException

# Configurație JWT
SECRET_KEY = "secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Configurație pentru hashing parole
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Simulare bază de date utilizatori
fake_users_db = {
    "user": {
        "username": "user",
        "password": "$2b$12$K03nqx5vpNw3PnZQ4NM5w.TEOXb0MfAvdzset8BHkF1Gb7ppl9Yce",  # Hash pentru "password"
    }
}

# Funcție pentru hashing parola (pentru generare hash o dată)
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

# Funcție pentru verificarea parolei
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# Funcție pentru obținerea utilizatorului din baza de date
def get_user(username: str):
    return fake_users_db.get(username)

# Funcție pentru autentificarea utilizatorului
def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user or not verify_password(password, user["password"]):
        return None
    return user

# Funcție pentru generarea token-ului JWT
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Funcție pentru validarea token-ului JWT
def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
