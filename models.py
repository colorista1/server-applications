from datetime import date
from typing import List
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
        from_attributes = True
        
class TokenModel(BaseModel):
    access_token: str
    token_type: str
    
class TokenResponse(BaseModel):
    session_id: str

    class Config:
        from_attributes = True

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8, regex=r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
    confirm_new_password: str = Field(..., min_length=8, regex=r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
    
class NewPasswordResponse(BaseModel):
    username: str
    old_password: str
    new_password: str
    
    class Config:
        from_attributes = True
        
class RoleRequest(BaseModel):
    name: str
    description: str
    code: str
    
class RoleResponse(BaseModel):
    name: str
    description: str
    
    class Config:
        from_attributes = True
        
class RoleUpdateRequest(BaseModel):
    id: int
    name: str
    description: str
    code: str
    
class PermissionRequest(BaseModel):
    name: str
    description: str
    code: str
    
class PermissionResponse(BaseModel):
    name: str
    description: str
    
    class Config:
        from_attributes = True
        
class RolePermission(BaseModel):
    id: int
    description: str
    permissions : List[PermissionResponse]
    
    class Config:
        from_attributes: True
        
class PermissionUpdateRequest(BaseModel):
    id: int
    name: str
    description: str
    code: str
    
class AssignRolesRequest(BaseModel):
    user_id: int
    role_ids: List[int]