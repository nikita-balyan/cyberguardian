from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api.v1 import health, endpoints
from app.models.database import init_db

app = FastAPI(title="CyberGuardian API")

@app.on_event("startup")
def on_startup():
    init_db()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development; refine for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health.router, prefix="/api/v1")
app.include_router(endpoints.router, prefix="/api/v1")

@app.get("/")
async def root():
    return {"message": "Welcome to CyberGuardian API"}
