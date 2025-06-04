from sqlalchemy.orm import Session
from db.schemas import Permission
from datetime import datetime

# Список разрешений для сидирования
permissions_seed = [
    # Разрешения для User
    {"name": "Get List User", "code": "get-list-user", "description": "Получить список пользователей"},
    {"name": "Read User", "code": "read-user", "description": "Читать данные пользователя"},
    {"name": "Create User", "code": "create-user", "description": "Создать пользователя"},
    {"name": "Update User", "code": "update-user", "description": "Обновить данные пользователя"},
    {"name": "Delete User", "code": "delete-user", "description": "Удалить пользователя"},
    {"name": "Restore user", "code": "restore-user", "description": "Восстановить пользователя"},

    # Разрешения для Role
    {"name": "Get List Role", "code": "get-list-role", "description": "Получить список ролей"},
    {"name": "Read Role", "code": "read-role", "description": "Читать данные роли"},
    {"name": "Create Role", "code": "create-role", "description": "Создать роль"},
    {"name": "Update Role", "code": "update-role", "description": "Обновить данные роли"},
    {"name": "Delete Role", "code": "delete-role", "description": "Удалить роль"},
    {"name": "Restore Role", "code": "restore-role", "description": "Восстановить роль"},

    # Разрешения для Permission
    {"name": "Get List Permission", "code": "get-list-permission", "description": "Получить список разрешений"},
    {"name": "Read Permission", "code": "read-permission", "description": "Читать данные разрешения"},
    {"name": "Create Permission", "code": "create-permission", "description": "Создать разрешение"},
    {"name": "Update Permission", "code": "update-permission", "description": "Обновить данные разрешения"},
    {"name": "Delete Permission", "code": "delete-permission", "description": "Удалить разрешение"},
    {"name": "Restore Permission", "code": "restore-permission", "description": "Восстановить разрешение"},
]

def seed_permissions(db: Session):
    for permission_data in permissions_seed:
        permission = db.query(Permission).filter_by(code=permission_data["code"]).first()
        if not permission:  # Если разрешения с таким кодом нет, добавляем
            new_permission = Permission(
                name=permission_data["name"],
                code=permission_data["code"],
                description=permission_data["description"],
                created_at=datetime.now(),
                created_by=1  # Предполагается, что сиды выполняются администратором с ID 1
            )
            db.add(new_permission)
    db.commit()