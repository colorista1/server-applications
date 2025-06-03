import os
import uuid
from fastapi import HTTPException, status
from jose import JWTError
from models import RegisterRequest, AuthRequest, ChangePasswordRequest
from db.chemas import User, Token
from security import *
from db.database import SessionLocal
from routes import *
from datetime import timedelta

max_tokens = int(os.getenv("MAX_ACTIVE_TOKENS", 5))
max_minutes = int(os.getenv("MAX_ACTIVE_MINUTES", 30))
max_days = int(int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 30)))

class UserController:
    def __init__(self):
        self.db = SessionLocal
    
    def register_user(self, data: RegisterRequest):     
        # Проверка уникальности email и username
        user_username = self.db.query(User).filter(User.username == data.username).first()
        user_email = self.db.query(User).filter(User.email == data.email).first()
        
        if user_email:
            raise HTTPException(status_code=400, detail="Такой адрес электронной почты уже зарегистрирован")
        if user_username:
            raise HTTPException(status_code=400, detail="Такое имя пользователя уже занято")
        
        hashed_password = pwd_context.hash(data.password)
        
        new_user = User(
            email=data.email,
            username=data.username,
            password=hashed_password,
            birthdate=data.birthdate
        )
        self.db.add(new_user)
        self.db.commit()
        self.db.refresh(new_user)
 
        return new_user
    
    def login_user(self, data: AuthRequest):
        # Поиск пользователя
        user = self.db.query(User).filter(User.username == data.username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        # Проверка пароля
        if not pwd_context.verify(data.password, user.password):
            raise HTTPException(status_code=401, detail="Incorrect password.")

        # Создаем новый токен
        session_id = str(uuid.uuid4())
        access_token_expires = timedelta(minutes=max_minutes)
        access_token = create_access_token(data={"sub": session_id}, expires_delta=access_token_expires)
        if isinstance(access_token, bytes):
            access_token = access_token.decode('utf-8')
        if self.db.query(Token).filter(Token.user_id == user.id, Token.is_active == True).count() > max_tokens:
            raise HTTPException(status_code=403, detail="Too many login attempts")

        # Сохраняем новый токен в базе данных
        new_token = Token(user_id=user.id, session_id=session_id)
        self.db.add(new_token)
        self.db.commit()

        return access_token

    def get_user_by_token(self, token):
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        return current_user
    
    def revoke_token(self, token):
        payload = jwt.decode(token, "secret_key", algorithms=["HS256"])
        session_id: str = payload.get("sub")
        
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        
        token_record = self.db.query(Token).filter(Token.user_id == current_user.id, Token.session_id == session_id, Token.is_active == True).first()
        if token_record:
            token_record.is_active = False
            SessionLocal.commit()
        return {"detail": "Logout successful"}
        
    def get_active_tokens(self, token):       
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        tokens = SessionLocal.query(Token).filter(Token.user_id == current_user.id, Token.is_active == True).all()
        return tokens
    
    def revoke_all_tokens(self, token):
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        tokens = self.db.query(Token).filter(Token.user_id == current_user.id, Token.is_active == True).all()
        for token_record in tokens:
            token_record.is_active = False
        self.db.commit()
        return {"detail": "All tokens revoked"}
        
    def change_password(self, data: ChangePasswordRequest, token):
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        if not verify_password(data.old_password, current_user.password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect old password",
            )
        current_user.password = get_password_hash(data.new_password)
        SessionLocal.commit()
        return {"detail": "Password changed"}
    
    def refresh_user_token(self, token):
        credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token is not valid",
        headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            token_user = TokenModel(access_token=token, token_type="bearer")
            current_user = get_current_user(token_user)
            
            session_id = str(uuid.uuid4())

            access_token_expires = timedelta(minutes=max_days)
            access_token = create_refresh_token(
                data={"sub": session_id}, expires_delta=access_token_expires
            )
            if isinstance(access_token, bytes):
                access_token = access_token.decode('utf-8')
                
            payload = jwt.decode(token, "secret_key", algorithms=["HS256"])
            old_session_id: str = payload.get("sub")
            token_record = self.db.query(Token).filter(Token.session_id == old_session_id, Token.is_active == True).first()
            if token_record is None:
                raise credentials_exception
            
            token_record.session_id = session_id  
            token_record.is_active = True
            self.db.commit()
            self.db.refresh(token_record)
            
            return {"access_token": access_token, "token_type": "bearer"}

        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )