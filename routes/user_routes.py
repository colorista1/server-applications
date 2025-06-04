from typing import List
from fastapi import APIRouter
from models import AssignRolesRequest, UserResponse
from views.user import UserController

router = APIRouter()
user_controller = UserController()

router = APIRouter(
    prefix="/api/ref/user",
    tags=["user"],
    responses={404: {"description": "Not found"}},
)

@router.get("/", response_model=List[UserResponse])
def get_all_users(token: str):
    return user_controller.get_users(token)

@router.get("/{user_id}/role")
def get_user_roles(token: str, user_id: str):
    return user_controller.get_user_roles(token, user_id)

@router.post("/{id}/role")
def assign_roles(request: AssignRolesRequest, token: str):
    return user_controller.assign_roles(request, token)

@router.delete("/{id}/role/{role_id}", status_code=204)
def delete_role(token: str, user_id: str, role_id: str):
    return user_controller.remove_role_from_user(token, user_id, role_id)

@router.delete("/{id}/role/{role_id}/soft", status_code=204)
def soft_delete_role(token: str, user_id: str, role_id: str):
    return user_controller.soft_delete_role_from_user(token, user_id, role_id)

@router.post("/{id}/role/{role_id}/restore")
def restore_deleted_role(token: str, user_id: str, role_id: str):
    return user_controller.restore_role_to_user(token, user_id, role_id)