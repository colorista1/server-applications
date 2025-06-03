from datetime import date
from pydantic import BaseModel, EmailStr, Field, validator
from email_validator import validate_email, EmailNotValidError

#Класс для авторизации пользователя
class AuthRequest(BaseModel):
     username: str
     password: str

# Класс для получения данных при регистрации
class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=7, regex=r'^[A-Z][a-zA-Z]*$')
    email: EmailStr
    password: str = Field(..., min_length=8, regex=r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
    confirm_password: str
    birthdate: date
    
    @validator('email')
    def validate_email_address(cls, v):
        try:
            validate_email(v)
            return v
        except EmailNotValidError:
            raise ValueError('Invalid email')

class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    birthdate: date 
    
    class Config:
        orm_mode = True
        
class TokenModel(BaseModel):
    access_token: str
    token_type: str
    
class TokenResponse(BaseModel):
    session_id: str

    class Config:
        orm_mode = True

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8, regex=r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
    confirm_new_password: str = Field(..., min_length=8, regex=r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
    
class NewPasswordResponse(BaseModel):
    username: str
    old_password: str
    new_password: str
    
    class Config:
        orm_mode = True