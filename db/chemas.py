from sqlalchemy import Column, Date, Integer, String, Boolean, ForeignKey
from db.database import Base
from sqlalchemy.orm import relationship

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    birthdate = Column(Date, nullable=False)

    tokens = relationship("Token", back_populates="user")  # Связь с моделью Token
    
class Token(Base):
    __tablename__ = 'tokens'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))  # Привязка к пользователю
    session_id = Column(String, index=True)
    is_active = Column(Boolean, default=True)  # Поле для состояния токена
    
    user = relationship("User", back_populates="tokens")  # Связь с пользователем