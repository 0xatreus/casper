from fastapi import FastAPI

from scanner.config import get_settings
from scanner.api.routes import router
from scanner.core.db import init_db

settings = get_settings()
app = FastAPI(title=settings.app_name)
app.include_router(router)


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/")
def root() -> dict:
    return {"service": settings.app_name}
