import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.v1 import health, endpoints
from app.models.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="CyberGuardian API", lifespan=lifespan)

# Comma-separated list in .env, e.g.
# CORS_ORIGINS=http://localhost:5173,http://192.168.56.1:5173
origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,  # no cookies are used, and "*" + credentials is invalid in browsers anyway
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

app.include_router(health.router, prefix="/api/v1")
app.include_router(endpoints.router, prefix="/api/v1")


@app.get("/")
def read_root():
    return {"message": "CyberGuardian API is running", "docs": "/docs"}