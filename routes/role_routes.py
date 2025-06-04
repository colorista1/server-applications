from typing import List
from fastapi import APIRouter
from models import RoleRequest, RoleResponse, RoleUpdateRequest
from views.role import RoleController

router = APIRouter()
role_controller = RoleController()

router = APIRouter(
    prefix="/api/ref/policy/role",
    tags=["role"],
    responses={404: {"description": "Not found"}},
)

@router.get("/", response_model=List[RoleResponse])
async def get_roles(token: str):
    return role_controller.get_all_roles(token)

@router.get("/{role_id}", response_model=RoleResponse)
async def get_role(role_id: int, token: str):
    return role_controller.get_role_by_id(role_id, token)

@router.post("/", response_model=RoleResponse)
def create_new_role(request: RoleRequest, token: str):
    new_role = role_controller.create_role(request, token)
    return new_role

@router.put("/{role_id}", response_model=RoleResponse)
def update_role(request: RoleUpdateRequest, token: str):
    updated_role = role_controller.update_role(request, token)
    return updated_role

@router.delete("/{role_id}", status_code=204)
async def remove_role(role_id: int, token: str):
    role_controller.delete_role(role_id, token)
    return

@router.delete("/{role_id}/soft", status_code=204)
async def remove_role(role_id: int, token: str):
    role_controller.soft_delete_role(role_id, token)
    return

@router.post("/{role_id}/restore")
async def res_role(role_id: int, token: str):
    role_controller.restore_role(role_id, token)
    return {"messege": "Role restore"}