from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.check import router as check_router
from app.api.document import router as document_router
from app.api.email import router as email_router
from app.config import settings
from app.db import init_db


@asynccontextmanager
async def _lifespan(app: FastAPI):
    # Creates the gmail_accounts table if it doesn't exist yet. Safe to
    # call on every startup -- create_all is a no-op for tables that
    # already exist.
    await init_db()
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=_lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(check_router)
app.include_router(document_router)
app.include_router(email_router)

@app.get("/v1/health")
async def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "safecheck-api",
        "version": settings.app_version,
    }

@app.get("/")
async def root() -> dict[str, str]:
    return {
        "message": "SafeCheck API is running",
        "docs": "/docs",
    }
