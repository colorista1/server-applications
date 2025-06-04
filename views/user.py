from datetime import datetime
from fastapi import HTTPException
from db.database import SessionLocal
from db.schemas import Role, User, UsersAndRoles
from models import AssignRolesRequest, TokenModel, UserResponse
from utils import get_current_user, has_permission

class UserController:
    def __init__(self):
        self.db = SessionLocal
        
    def get_users(self, token):
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        has_permission("get-list-user", current_user)
        
        users = self.db.query(User).all()
        
        user_list = []
        for user in users:
            user_list.append(UserResponse(id=user.id, username=user.username, email=user.email, birthdate=user.birthdate))

        return user_list
    
    def get_user_roles(self, token, user_id: int):
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        has_permission("read-user", current_user)
        
        # Получаем связи пользователя с ролями
        user_roles = self.db.query(UsersAndRoles).filter(UsersAndRoles.user_id == user_id, UsersAndRoles.deleted_at.is_(None)).all()
        
        if not user_roles:
            raise HTTPException(status_code=404, detail="No roles found for this user")

        # Извлекаем роли
        roles = [self.db.query(Role).filter(Role.id == user_role.role_id).first().name for user_role in user_roles]

        return roles
    
    def assign_roles(self, data: AssignRolesRequest, token):
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        
        # Получаем пользователя
        user = self.db.query(User).filter(User.id == data.user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail=f"User not found")

        # Получаем роли
        roles = self.db.query(Role).filter(Role.id.in_(data.role_ids)).all()
        if not roles:
            raise HTTPException(status_code=404, detail="Roles not found")

        # Удаляем старые связи
        self.db.query(UsersAndRoles).filter(UsersAndRoles.user_id == user.id).delete()

        # Создаем новые связи
        for role in roles:
            user_role = UsersAndRoles(
                user_id=user.id,
                role_id=role.id,
                created_by=current_user.id
            )
            self.db.add(user_role)

        self.db.commit()
        return {"message": "Roles assigned successfully"}
    
    def remove_role_from_user(self, token, user_id, role_id):
        token = TokenModel(access_token=token, token_type="bearer")
        get_current_user(token)
        
        # Находим связь между пользователем и ролью
        user_role = self.db.query(UsersAndRoles).filter(
            UsersAndRoles.user_id == user_id,
            UsersAndRoles.role_id == role_id,
            UsersAndRoles.deleted_at.is_(None)
        ).first()

        if not user_role:
            raise HTTPException(status_code=404, detail="Role not found for this user")

        # Удаляем связь
        self.db.delete(user_role)
        self.db.commit()
        
    def soft_delete_role_from_user(self, token, user_id, role_id):
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        
        # Находим связь между пользователем и ролью
        user_role = self.db.query(UsersAndRoles).filter(
            UsersAndRoles.user_id == user_id,
            UsersAndRoles.role_id == role_id,
            UsersAndRoles.deleted_at.is_(None)
        ).first()

        if not user_role:
            raise HTTPException(status_code=404, detail="Role not found for this user")

        # Устанавливаем поле deleted_at на текущее время
        user_role.deleted_at = datetime.now()
        user_role.deleted_by = current_user.id

        self.db.commit()
        
    def restore_role_to_user(self, token, user_id, role_id):
        token = TokenModel(access_token=token, token_type="bearer")
        get_current_user(token)
        
        # Находим связь между пользователем и ролью
        user_role = self.db.query(UsersAndRoles).filter(
            UsersAndRoles.user_id == user_id,
            UsersAndRoles.role_id == role_id,
            UsersAndRoles.deleted_at.isnot(None)  # Убедимся, что связь была мягко удалена
        ).first()

        if not user_role:
            raise HTTPException(status_code=404, detail="Soft-deleted role not found for this user")

        # Восстанавливаем связь, устанавливая deleted_at и deleted_by в None
        user_role.deleted_at = None
        user_role.deleted_by = None 

        self.db.commit()

        return {"detail": "Role restored successfully"}