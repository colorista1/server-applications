from db import chemas
from db.database import engine

def init_db():
    chemas.Base.metadata.create_all(bind=engine)
