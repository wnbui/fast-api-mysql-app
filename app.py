from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, field_validator, ConfigDict
from sqlalchemy import create_engine, Column, Integer, String, Float, Date
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
import jwt
import re
import os
from dotenv import load_dotenv

# Load environmentals and variables
load_dotenv()
DATABASE_URL = os.getenv('DATABASE_HOST')
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

# Database setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# App and middleware
app = FastAPI()
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

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), nullable=False)
    description = Column(String(250), nullable=False)
    quantity = Column(Integer, nullable=False)
    price = Column(Float(precision=2), nullable=False)
    last_update = Column(Date, nullable=False)

class User(Base):
    __tablename__ = "users"

    # id is automatically added by MySQL
    username = Column(String(50), nullable=False, primary_key=True, index=True)
    password = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    role = Column(String(10), nullable=False)

Base.metadata.create_all(bind=engine)

# Pydantic Schemas
class UserCreate(BaseModel):
    username: str
    password: str
    email: EmailStr
    role: str

    @field_validator('password', mode='after')
    @classmethod
    def password_validation(cls, password: str) -> str:
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not re.search(r'\d', password):
            raise ValueError("Password must contain at least one digit.")
        if not re.search(r'[A-Z]', password):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', password):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not re.search(r'[\W_]', password):
            raise ValueError("Password must contain at least one special character.")
        return password
    
    @field_validator('role', mode='after')
    @classmethod
    def has_role(cls, role: str) -> str:
        if not (role == "user" or role == "admin"):
            raise ValueError("Role must be 'user' or 'admin'")
        return role
    
class UserOut(BaseModel):
    username: str
    password: str # Ideally you want to hide this
    email: EmailStr # Ideally you want to hide this
    role: str # Ideally you want to hide this

    model_config = ConfigDict(from_attributes=True)

class UserRead(BaseModel):
    username: str
    password: str

    model_config = ConfigDict(from_attributes=True)

class ItemCreate(BaseModel):
    id: int
    name: str
    description: str
    price: float
    quantity: int
    last_update: str

    @field_validator('quantity', mode='after')
    @classmethod
    def is_not_negative(cls, value: float) -> float:
        if value < 0:
            raise ValueError(f'{value} is not zero or a positive floating point number.')
        return float
    
    @field_validator('last_update', mode='after')
    @classmethod
    def is_valid_date(clas, date: str) -> str:
        if not re.match(r'^(0[1-9]|1[0-2])/([0][1-9]|[12][0-9]|3[01])/(\d{4})$', date):
            raise ValueError('Date must be in format MM/DD/YYYY')
        return date

class ItemOut(BaseModel):
    id: int
    name: str
    description: str
    price: float
    quantity: int
    last_update: str

    model_config = ConfigDict(from_attributes=True)

# JWT decorator

# /register POST
    # Add JWT
@app.post("/register", response_model=UserOut)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists.")
    
    new_user = User(username=user.username, password=user.password, email=user.email, role=user.role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# /login POST
@app.post("/login")
def login_user(user: UserRead, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or db_user.password != user.password:
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    return {"message": "Login successful."}

# /logout POST

## User Routes

# /inventory GET

# /invetory/item_id GET

# /inventory POST

# /inventory/item_id PUT

# /inventory/item_id DELETE

## Admin Routes

# /admin/inventory GET

# /admin/inventory/user GET

# /admin/inventory/user/item_id GET

# /admin/inventory/user POST

# /admin/inventory/user/item_id PUT

# /admin/inventory/user/item_id DELETE