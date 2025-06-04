from datetime import datetime
from typing import List
from fastapi import HTTPException
from db.database import SessionLocal
from db.schemas import Permission
from models import PermissionRequest, PermissionUpdateRequest, TokenModel
from utils import check_permission_unique, get_current_user, has_permission

class PermissionController:
    def __init__(self):
        self.db = SessionLocal
        
    def create_permission(self, data: PermissionRequest, token):
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        has_permission("create-permission", current_user)
        
        # Проверка уникальности при создании роли
        check_permission_unique(name=data.name, code=data.code)
        
        # Создание новой роли
        new_permission = Permission(
            name=data.name,
            description=data.description,
            code=data.code,
            created_by=current_user.id 
        )
        self.db.add(new_permission)
        self.db.commit()
        self.db.refresh(new_permission)
        return new_permission
    
    def update_permission(self, data: PermissionUpdateRequest, token):
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        has_permission("update-permission", current_user)
        
        existing_permission = self.db.query(Permission).filter(Permission.id == data.id).first()
        if not existing_permission:
            raise HTTPException(status_code=404, detail="Permission not found")
        
        if any([data.name, data.code]):
            check_permission_unique(name=data.name if data.name else None, code=data.code if data.code else None)
            
        # Обновление данных
        if data.name:
            existing_permission.name = data.name
        if data.description:
            existing_permission.description = data.description
        if data.code:
            existing_permission.code = data.code

        # Обновляем запись
        self.db.commit()
        self.db.refresh(existing_permission)
        return existing_permission
    
    def get_all_permissions(self, token) -> List[Permission]:
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        has_permission("get-list-permission", current_user)
        
        permissions = self.db.query(Permission).filter(Permission.deleted_at.is_(None)).all()
    
        if not permissions:
            raise HTTPException(status_code=404, detail="No permissions found")
        
        return permissions
        
    def get_permission_by_id(self, permission_id: int, token) -> Permission:
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        has_permission("read-permission", current_user)
        
        permission = self.db.query(Permission).filter(Permission.id == permission_id, Permission.deleted_at.is_(None)).first()
        if not permission:
            raise HTTPException(status_code=404, detail="Permission not found")
        return permission
    
    def delete_permission(self, permission_id: int, token) -> None:
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        has_permission("delete-permission", current_user)
        
        permission = self.db.query(Permission).filter(Permission.id == permission_id, Permission.deleted_at.is_(None)).first()
        if not permission:
            raise HTTPException(status_code=404, detail="Permission not found")
        
        self.db.delete(permission)
        self.db.commit()
        
    def soft_delete_permission(self, permission_id: int, token) -> None:
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        has_permission("delete-permission", current_user)
        
        permission = self.db.query(Permission).filter(Permission.id == permission_id, Permission.deleted_at.is_(None)).first()
        if not permission:
            raise HTTPException(status_code=404, detail="Permission not found")
        
        permission.deleted_at = datetime.now()
        permission.deleted_by = current_user.id
        self.db.commit()
        
    def restore_permission(self, permission_id: int, token) -> None:
        token = TokenModel(access_token=token, token_type="bearer")
        current_user = get_current_user(token)
        has_permission("restore-permission", current_user)
        
        permission = self.db.query(Permission).filter(Permission.id == permission_id).first()
        if not permission:
            raise HTTPException(status_code=404, detail="Permission not found")
        
        if permission.deleted_at is None:
            raise HTTPException(status_code=400, detail="Permission is not deleted")
        
        permission.deleted_at = None
        permission.deleted_by = None
        self.db.commit()