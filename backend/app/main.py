from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.check import router as check_router
from app.config import settings

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(check_router)

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
