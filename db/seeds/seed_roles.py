from sqlalchemy.orm import Session
from db.schemas import Role
from datetime import datetime

# Список ролей для сидирования
roles_seed = [
    {"name": "Admin", "description": "Administrator role with full permissions", "code": "ADMIN"},
    {"name": "User", "description": "Regular user role", "code": "USER"},
    {"name": "Guest", "description": "Guest role with limited access", "code": "GUEST"},
]

def seed_roles(db: Session):
    for role_data in roles_seed:
        role = db.query(Role).filter_by(code=role_data["code"]).first()
        if not role:  # Если роли с таким кодом нет, добавляем
            new_role = Role(
                name=role_data["name"],
                description=role_data["description"],
                code=role_data["code"],
                created_at=datetime.now(),
                created_by=1  # Предполагается, что сиды выполняются администратором с ID 1
            )
            db.add(new_role)
    db.commit()