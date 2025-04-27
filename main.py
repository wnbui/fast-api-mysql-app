from fastapi import FastAPI, HTTPException, Depends, Request, Response, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, field_validator, ConfigDict, Field
from sqlalchemy import create_engine, Column, Integer, String, Date, Numeric, select
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from starlette.middleware.sessions import SessionMiddleware
import datetime as dt
from datetime import date
import jwt
import re
import os
from dotenv import load_dotenv
from typing import List

# Load environmentals and variables
load_dotenv()
SECRET_KEY = os.getenv('JWT_SECRET_KEY')
SESSION_SECRET_KEY = os.getenv('SESSION_SECRET_KEY')
ALGORITHM = os.getenv('JWT_ALGORITHM')
ACCESS_TOKEN_EXPIRY = int(os.getenv('ACCESS_TOKEN_EXPIRY', 30))
SESSION_MAX_AGE = int(os.getenv('SESSION_MAX_AGE', 3600))
DATABASE_URL = os.getenv('DATABASE_HOST')

if not SECRET_KEY or not ALGORITHM or not SESSION_SECRET_KEY:
    raise RuntimeError("Environmental variables JWT_SECRET_KEY, JWT_ALGORITHM, and SESSION_SECRET_KEY must be set in .env")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

# Database setup
engine = create_engine(DATABASE_URL, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)
Base = declarative_base()

# App and middleware
app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET_KEY,
    session_cookie="session",
    max_age=SESSION_MAX_AGE,
    same_site='lax',
    path="/",
    https_only=False
)
security = HTTPBearer()

# Database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally: 
        db.close()

# SQLAlchemy Models
class Item(Base):
    __tablename__ = "inventory"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(String(50), nullable=False)
    name = Column(String(50), nullable=False)
    description = Column(String(250), nullable=False)
    price = Column(Numeric(10,2), nullable=False)
    quantity = Column(Integer, nullable=False)
    condition = Column(String(15), nullable=False)
    last_updated = Column(String(10), nullable=False)

class User(Base):
    __tablename__ = "users"

    # id is automatically added by MySQL
    username = Column(String(50), nullable=False, primary_key=True, index=True)
    password = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    role = Column(String(10), nullable=False)

# To clear database
# Base.metadata.drop_all(bind=engine)
# To initialize database
Base.metadata.create_all(bind=engine)

# Pydantic Schemas
class UserCreate(BaseModel):
    username: str = Field(..., min_length=5, max_length=50)
    password: str = Field(..., min_length=8, max_length=255)
    email: EmailStr
    role: str = Field(..., pattern="^(user|admin)$", description="Must be either 'user' or 'admin'")

    @field_validator('password', mode='after')
    @classmethod
    def password_validation(cls, password: str) -> str:
        if not re.search(r'\d', password):
            raise ValueError("Password must contain at least one digit.")
        if not re.search(r'[A-Z]', password):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', password):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not re.search(r'[\W_]', password):
            raise ValueError("Password must contain at least one special character.")
        return password
    
class UserOut(BaseModel):
    username: str
    password: str # Ideally you want to hide this
    email: EmailStr # Ideally you want to hide this
    role: str # Ideally you want to hide this

    model_config = ConfigDict(from_attributes=True)

class UserRead(BaseModel):
    username: str
    password: str

class ItemCreate(BaseModel):
    user_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1, max_length=50)
    description: str = Field(..., min_length=1, max_length=250)
    price: float = Field(gt=0, description="The price must be greater than zero.")
    quantity: int = Field(gt=0, description="The quantity must be greater than zero.")
    condition: str = Field(..., pattern="^(new|used|refurbished)$", description="Must be one of: new, used or refurbished.")
    last_updated: date = Field(..., description="The date must be in format YYY-MM-DD")

class ItemOut(BaseModel):
    id: int
    user_id: str
    name: str
    description: str
    price: float
    quantity: int
    condition: str
    last_updated: str

    model_config = ConfigDict(from_attributes=True)

# JWT
def create_access_token(data: dict, expires_delta: dt.timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = dt.datetime.now(dt.timezone.utc) + (expires_delta or dt.timedelta(minutes=ACCESS_TOKEN_EXPIRY))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# JWT Dependency
def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security), db: Session = Depends(get_db)) -> dict:
    token = credentials.credentials
    if not token:
        raise HTTPException(status_code=401, detail="Token is missing.")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        username: str = payload.get("username")
        role: str = payload.get("role")
        if not username or not role:
            raise HTTPException(status_code=401, detail="Invalid token payload.")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token.")
    return {"username": username, "role": role}

# /register POST
@app.post("/register", response_model=UserOut, status_code=201)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.scalars(select(User).filter_by(username=user.username)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists.")
    
    new_user = User(username=user.username, password=user.password, email=user.email, role=user.role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# /login POST
@app.post("/login", status_code=200)
def login_user(request: Request, response: Response, user: UserRead, db: Session = Depends(get_db)):
    db_user = db.scalars(select(User).filter_by(username=user.username)).first()
    if not db_user or db_user.password != user.password:
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    
    access_token = create_access_token({"username": db_user.username, "role": db_user.role})

    request.session["username"] = db_user.username
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRY*60
    )

    return {"message": "Login successful", "access_token": access_token, "token_type": "bearer"}

# /logout POST
@app.post("/logout", status_code=200)
def logout(request: Request, response: Response):
    request.session.clear()
    response.delete_cookie("session")
    return {"message": "Logged out successfully"}

## User Routes
# /inventory GET
@app.get("/inventory", response_model=List[ItemOut], status_code=200)
def get_all_items(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    items = db.scalars(select(Item).filter_by(user_id=current_user["username"])).all()
    return items

# /inventory/item_id GET
@app.get("/inventory/{item_id}", response_model=ItemOut, status_code=200)
def get_item(item_id: int, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    item = db.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found.")
    if item.user_id != current_user["username"]:
        raise HTTPException(status_code=403, detail="Not authorized to access item.")
    return item

# /inventory POST
@app.post("/inventory", response_model=ItemOut, status_code=201)
def add_item(item_in: ItemCreate, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    if hasattr(item_in, 'user_id') and item_in.user_id != current_user["username"]:
        raise HTTPException(status_code=403, detail="Cannot create item for another user.")
    new_item = Item(**item_in.model_dump())
    new_item.user_id = current_user["username"]
    db.add(new_item)
    db.commit()
    db.refresh(new_item)
    return new_item

# /inventory/item_id PUT
@app.put("/inventory/{item_id}", response_model=ItemOut, status_code=200)
def update_item(item_id: int, updated_item: ItemCreate, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    item = db.get(Item, item_id)

    if not item:
        raise HTTPException(status_code=404, detail="Item not found.")
    if item.user_id != current_user["username"]:
        raise HTTPException(status_code=403, detail="Not authorized to edit an item of another user.")
    for key, value in updated_item.model_dump().items():
        setattr(item, key, value)
    db.commit()
    db.refresh(item)
    return item

# /inventory/item_id DELETE
@app.delete("/inventory/{item_id}")
def delete_item(item_id: int, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    item = db.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found.")
    if item.user_id != current_user["username"]:
        raise HTTPException(status_code=403, detail="Not authorized to edit an item of another user.")
    db.delete(item)
    db.commit()
    return {"message": "Item deleted successfully"}

## Admin Routes
# /admin/inventory GET

# /admin/inventory/user GET

# /admin/inventory/user/item_id GET

# /admin/inventory/user POST

# /admin/inventory/user/item_id PUT

# /admin/inventory/user/item_id DELETE