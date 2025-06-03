from fastapi import APIRouter, HTTPException, Header, status
from fastapi.responses import JSONResponse
from db import init_db
from models import *
from views import UserController

router = APIRouter()
controller = UserController()

@router.on_event("startup")
def on_startup():
    init_db()

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def registration(request: RegisterRequest):
    # Проверка подтверждения пароля
    if request.password != request.confirm_password:
        JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": "Пароли не совпадают"})
    
    try:
        new_user = controller.register_user(request)
        return new_user

    except HTTPException as e:
        return JSONResponse(status_code=e.status_code, content={"message": e.detail})
    
@router.post("/login", response_model=TokenModel, status_code=status.HTTP_200_OK)
async def login(request: AuthRequest):
    access_token = controller.login_user(request)

    if access_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Некорректное имя пользователя или пароль",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/me", response_model=UserResponse)
async def read_me(token: str = Header(...)):
    user = controller.get_user_by_token(token)
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "birthdate": user.birthdate,
    }
    
@router.post("/out")
async def logout(token: str = Header(...)):
    out = controller.revoke_token(token)
    return out

@router.get("/tokens", response_model=list[TokenResponse])
def get_active_tokens(token: str = Header(...)):
    tokens = controller.get_active_tokens(token)
    return tokens

@router.post("/out_all", status_code=status.HTTP_200_OK)
async def logout_all(token: str = Header(...)):
    out_all = controller.revoke_all_tokens(token)
    return out_all

@router.post("/change-password")
def change_password(request: ChangePasswordRequest, token: str = Header(...)):
    new_password = controller.change_password(request, token)
    return new_password

@router.post("/refresh", response_model=TokenModel)
def refresh_token(token: str = Header(...)):
    new_token = controller.refresh_user_token(token)
    return new_token