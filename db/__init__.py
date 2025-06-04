from db import schemas
from db.database import engine

def init_db():
    schemas.Base.metadata.create_all(bind=engine)
