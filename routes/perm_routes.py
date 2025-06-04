from typing import List
from fastapi import APIRouter
from models import PermissionRequest, PermissionResponse, PermissionUpdateRequest 
from views.perm import PermissionController

router = APIRouter()
permission_controller = PermissionController()

router = APIRouter(
    prefix="/api/ref/policy/permission",
    tags=["permission"],
    responses={404: {"description": "Not found"}},
)

@router.get("/", response_model=List[PermissionResponse])
async def get_permissions(token: str):
    return permission_controller.get_all_permissions(token)

@router.get("/{permission_id}", response_model=PermissionResponse)
async def get_permission(permission_id: int, token: str):
    return permission_controller.get_permission_by_id(permission_id, token)

@router.post("/", response_model=PermissionResponse)
def create_new_permission(request: PermissionRequest, token: str):
    new_permission = permission_controller.create_permission(request, token)
    return new_permission

@router.put("/{permission_id}", response_model=PermissionResponse)
def update_permission(request: PermissionUpdateRequest, token: str):
    updated_permission = permission_controller.update_permission(request, token)
    return updated_permission

@router.delete("/{permission_id}", status_code=204)
async def remove_permission(permission_id: int, token: str):
    permission_controller.delete_permission(permission_id, token)
    return

@router.delete("/{permission_id}/soft", status_code=204)
async def remove_permission_soft(permission_id: int, token: str):
    permission_controller.soft_delete_permission(permission_id, token)
    return

@router.post("/{permission_id}/restore")
async def res_permission(permission_id: int, token: str):
    permission_controller.restore_permission(permission_id, token)
    return {"messege": "permission restore"}