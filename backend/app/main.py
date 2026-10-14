import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import config
from .api.v1 import health, endpoints
from app.models.database import init_db, purge_old_scans

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    removed = await asyncio.to_thread(purge_old_scans, config.HISTORY_RETENTION_DAYS)
    if removed:
        logger.info("Deleted %s scans older than %s days", removed, config.HISTORY_RETENTION_DAYS)
    yield


_prod = config.APP_ENV == "production"
app = FastAPI(
    title="CyberGuardian API",
    lifespan=lifespan,
    docs_url=None if _prod else "/docs",
    redoc_url=None if _prod else "/redoc",
    openapi_url=None if _prod else "/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=False,  # no cookies are used, and "*" + credentials is invalid in browsers anyway
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "X-Visitor-Id"],
)

app.include_router(health.router, prefix="/api/v1")
app.include_router(endpoints.router, prefix="/api/v1")


@app.get("/")
def read_root():
    return {"message": "CyberGuardian API is running", "docs": None if _prod else "/docs"}