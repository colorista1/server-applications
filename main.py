from fastapi import FastAPI
from requests import Session
from db import init_db
from db.database import SessionLocal
from db.seeds.seed_perm import seed_permissions
from db.seeds.seed_role_perm import seed_role_permissions
from db.seeds.seed_roles import seed_roles
from routes import auth_routes, role_routes, perm_routes, user_routes, logs_routes

app = FastAPI()
app.include_router(auth_routes.router)
app.include_router(role_routes.router)
app.include_router(perm_routes.router)
app.include_router(user_routes.router)
app.include_router(logs_routes.router)

# Вызов функции сидирования при инициализации
def init_seeds():
    db: Session = SessionLocal
    seed_roles(db)
    seed_permissions(db)
    seed_role_permissions(db)
    db.close()

@app.on_event("startup")
def on_startup():
    init_db()
    init_seeds()