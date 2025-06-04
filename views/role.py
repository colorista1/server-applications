from datetime import datetime
from typing import List
from fastapi import HTTPException
from db.database import SessionLocal
from db.schemas import Role
from models import RoleRequest, RoleUpdateRequest, TokenModel
from utils import check_role_unique, get_current_user, has_permission

class RoleController:
    def __init__(self):
        self.db = SessionLocal
        
    def create_role(self, data: RoleRequest, token):
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        has_permission("create-role", current_user)
        
        # Проверка уникальности при создании роли
        check_role_unique(name=data.name, code=data.code)
        
        # Создание новой роли
        new_role = Role(
            name=data.name,
            description=data.description,
            code=data.code,
            created_by=current_user.id
        )
        self.db.add(new_role)
        self.db.commit()
        self.db.refresh(new_role)
        return new_role
    
    def update_role(self, data: RoleUpdateRequest, token):
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        has_permission("update-role", current_user)
        
        existing_role = self.db.query(Role).filter(Role.id == data.id).first()
        if not existing_role:
            raise HTTPException(status_code=404, detail="Role not found")
        
        if any([data.name, data.code]):
            check_role_unique(name=data.name if data.name else None, code=data.code if data.code else None)
            
        # Обновление данных
        if data.name:
            existing_role.name = data.name
        if data.description:
            existing_role.description = data.description
        if data.code:
            existing_role.code = data.code

        # Обновляем запись
        self.db.commit()
        self.db.refresh(existing_role)
        return existing_role
    
    def get_all_roles(self, token) -> List[Role]:
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        has_permission("get-list-role", current_user)
        
        roles = self.db.query(Role).filter(Role.deleted_at.is_(None)).all()
    
        if not roles:
            raise HTTPException(status_code=404, detail="No roles found")
        
        return roles
        
    def get_role_by_id(self, role_id: int, token) -> Role:
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        has_permission("read-role", current_user)
        
        role = self.db.query(Role).filter(Role.id == role_id, Role.deleted_at.is_(None)).first()
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        return role
    
    def delete_role(self, role_id: int, token) -> None:
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        has_permission("delete-role", current_user)
        
        role = self.db.query(Role).filter(Role.id == role_id, Role.deleted_at.is_(None)).first()
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        
        self.db.delete(role)
        self.db.commit()
        
    def soft_delete_role(self, role_id: int, token) -> None:
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        has_permission("delete-role", current_user)
        
        role = self.db.query(Role).filter(Role.id == role_id, Role.deleted_at.is_(None)).first()
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        
        role.deleted_at = datetime.now()
        role.deleted_by = current_user.id
        self.db.commit()  
        
    def restore_role(self, role_id: int, token) -> None:
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        has_permission("restore-role", current_user)
        
        role = self.db.query(Role).filter(Role.id == role_id).first()
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        
        if role.deleted_at is None:
            raise HTTPException(status_code=400, detail="Role is not deleted")
        
        role.deleted_at = None
        role.deleted_by = None 
        self.db.commit()  