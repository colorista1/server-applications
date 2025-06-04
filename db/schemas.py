from sqlalchemy import Column, Date, DateTime, Integer, String, Boolean, ForeignKey, func
from db.database import Base
from sqlalchemy.orm import relationship

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    birthdate = Column(Date, nullable=False)

    # Связь с моделью Token
    tokens = relationship("Token", back_populates="user")  

    # Связь с таблицей "UsersAndRoles"
    roles = relationship("UsersAndRoles", back_populates="user")
    
    def get_roles(self):
        return self.roles
    
    
class Token(Base):
    __tablename__ = 'tokens'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))  # Привязка к пользователю
    session_id = Column(String, index=True)
    is_active = Column(Boolean, default=True)  # Поле для состояния токена
    
    user = relationship("User", back_populates="tokens")  # Связь с пользователем
    
# Таблица для ролей
class Role(Base):
    __tablename__ = "roles"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(String)
    code = Column(String, unique=True, nullable=False)
    
    # Служебные поля
    created_at = Column(DateTime, default=func.now())  # Время создания
    created_by = Column(Integer, nullable=False)  # ID пользователя, создавшего запись
    deleted_at = Column(DateTime, nullable=True)  # Время мягкого удаления
    deleted_by = Column(Integer, nullable=True)  # ID пользователя, удалившего запись

    # Связь с таблицей "RolesAndPermissions"
    permissions = relationship("RolesAndPermissions", back_populates="role")
    # Связь с таблицей "UsersAndRoles"
    users = relationship("UsersAndRoles", back_populates="role")
    
    def get_permissions(self):
        return [perm.permission for perm in self.permissions]  # Возвращает все разрешения, связанные с ролью

# Таблица для разрешений
class Permission(Base):
    __tablename__ = "permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(String)
    code = Column(String, unique=True, nullable=False)
    
    # Служебные поля
    created_at = Column(DateTime, default=func.now())
    created_by = Column(Integer, nullable=False)
    deleted_at = Column(DateTime, nullable=True)
    deleted_by = Column(Integer, nullable=True)

    # Связь с таблицей "RolesAndPermissions"
    roles = relationship("RolesAndPermissions", back_populates="permission")

# Таблица для связи пользователей и ролей (многие ко многим)
class UsersAndRoles(Base):
    __tablename__ = "users_roles"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)  # Ссылка на пользователя
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)  # Ссылка на роль
    
    # Служебные поля
    created_at = Column(DateTime, default=func.now())
    created_by = Column(Integer, nullable=False)
    deleted_at = Column(DateTime, nullable=True)
    deleted_by = Column(Integer, nullable=True)

    # Связь с пользователями и ролями
    user = relationship("User", back_populates="roles")
    role = relationship("Role", back_populates="users")

# Таблица для связи ролей и разрешений (многие ко многим)
class RolesAndPermissions(Base):
    __tablename__ = "roles_permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)  # Ссылка на роль
    permission_id = Column(Integer, ForeignKey("permissions.id"), nullable=False)  # Ссылка на разрешение
    
    # Служебные поля
    created_at = Column(DateTime, default=func.now())
    created_by = Column(Integer, nullable=False)
    deleted_at = Column(DateTime, nullable=True)
    deleted_by = Column(Integer, nullable=True)

    # Связь с ролями и разрешениями
    role = relationship("Role", back_populates="permissions")
    permission = relationship("Permission", back_populates="roles")
