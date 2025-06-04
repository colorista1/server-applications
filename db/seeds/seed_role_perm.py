from sqlalchemy.orm import Session
from db.schemas import Role, Permission, RolesAndPermissions

def seed_role_permissions(db: Session):
    # Получение ролей
    admin_role = db.query(Role).filter_by(code="ADMIN").first()
    user_role = db.query(Role).filter_by(code="USER").first()
    guest_role = db.query(Role).filter_by(code="GUEST").first()

    # Получение всех разрешений
    all_permissions = db.query(Permission).all()

    # 1. Связка для Admin - администратор может все
    for permission in all_permissions:
        role_permission = RolesAndPermissions(role_id=admin_role.id, permission_id=permission.id, created_by=1)
        db.add(role_permission)

    # 2. Связка для User - пользователь может получить список пользователей, читать и обновлять свои данные
    user_permissions = db.query(Permission).filter(
        Permission.code.in_(["get-list-user", "read-user", "update-user"])
    ).all()

    for permission in user_permissions:
        role_permission = RolesAndPermissions(role_id=user_role.id, permission_id=permission.id, created_by=1)
        db.add(role_permission)

    # 3. Связка для Guest - гость может только получить список пользователей
    guest_permissions = db.query(Permission).filter(
        Permission.code == "get-list-user"
    ).all()

    for permission in guest_permissions:
        role_permission = RolesAndPermissions(role_id=guest_role.id, permission_id=permission.id, created_by=1)
        db.add(role_permission)

    db.commit()