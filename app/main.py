from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.routes import build_router
from app.core.config import settings
from app.core.db import initialise_database

ROOT = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(ROOT / "api" / "templates"))


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialise_database(settings.database_path)
    yield


app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(ROOT / "api" / "static")), name="static")
app.include_router(build_router(settings.database_path))


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "dashboard.html", {"app_name": settings.app_name})
