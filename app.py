from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr, ValidationError, field_validator
from sqlalchemy import create_engine, Column, Integer, String, Float, Date
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import re
import os

app = FastAPI()

DATABASE_URL = os.environ.get('DATABASE_HOST')
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoFlush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally: 
        db.close()

# SQLAlchemy 
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

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), nullable=False)
    password = Column(String(255), nullable=False)
    email = Column(String, nullable=False)
    role = Column(String(10), nullable=False)

Base.metadata.create_all(bind=engine)

class UserCreate(BaseModel):
    id: int
    username: str
    password: str
    email: str
    role: str

    @field_validator('password', mode='after')
    @classmethod
    def password_validation(cls, password: String) -> String:
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

    @field_validator('email', mode='after')
    @classmethod
    def is_valid_email(cls, email: String) -> String:
        if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
            raise ValueError("'Email is not in format user@email.com'")
        return email
    
    @field_validator('role', mode='after')
    @classmethod
    def has_role(cls, role: String) -> String:
        if not (role == "user" or role == "admin"):
            raise ValidationError('User is missing role (user or admin)')
        return role
    
class UserOut(BaseModel):
    id: int
    username: str
    password: str
    email: str
    role: str

    class Config:
        orm_mode = True

class ItemCreate(BaseModel):
    id: int
    name: str
    description: String
    price: float
    quantity: int
    last_update: String

    @field_validator('quantity', mode='after')
    @classmethod
    def is_not_negative(cls, value: float) -> float:
        if value < 0:
            raise ValueError(f'{value} is not zero or a positive floating point number.')
        return float
    
    @field_validator('last_update', mode='after')
    @classmethod
    def is_valid_date(clas, date: String) -> String:
        if not re.match(r'^(0[1-9]|1[0-2])/([0][1-9]|[12][0-9]|3[01])/(\d{4})$', date):
            raise ValueError('Date must be in format MM/DD/YYYY')
        return date
   
# /register POST

# /login POST

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