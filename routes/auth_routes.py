from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from models import AuthRequest, ChangePasswordRequest, RegisterRequest, TokenModel, TokenResponse, UserResponse
from views.auth import AuthController

router = APIRouter()
auth_controller = AuthController()

router = APIRouter(
    prefix="/api/auth",
    tags=["auth"],
    responses={404: {"description": "Not found"}},
)

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def registration(request: RegisterRequest):
    # Проверка подтверждения пароля
    if request.password != request.confirm_password:
        JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"message": "Пароли не совпадают"})
    
    try:
        new_user = auth_controller.register_user(request)
        return new_user

    except HTTPException as e:
        return JSONResponse(status_code=e.status_code, content={"message": e.detail})
    
@router.post("/login", response_model=TokenModel, status_code=status.HTTP_200_OK)
async def login(request: AuthRequest):
    access_token = auth_controller.login_user(request)

    if access_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Некорректное имя пользователя или пароль",
            Paths={"WWW-Authenticate": "Bearer"},
        )

    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/me", response_model=UserResponse)
async def read_me(token: str):
    user = auth_controller.get_user_by_token(token)
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "birthdate": user.birthdate,
    }
    
@router.post("/out")
async def logout(token: str):
    out = auth_controller.revoke_token(token)
    return out

@router.get("/tokens", response_model=list[TokenResponse])
def get_active_tokens(token: str):
    tokens = auth_controller.get_active_tokens(token)
    return tokens

@router.post("/out-all", status_code=status.HTTP_200_OK)
async def logout_all(token: str):
    out_all = auth_controller.revoke_all_tokens(token)
    return out_all

@router.post("/change-password")
def change_password(request: ChangePasswordRequest, token: str):
    new_password = auth_controller.change_password(request, token)
    return new_password

@router.post("/refresh-token", response_model=TokenModel)
def refresh_token(token: str):
    new_token = auth_controller.refresh_user_token(token)
    return new_token
