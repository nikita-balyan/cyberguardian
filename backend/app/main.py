from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api.v1 import health, endpoints

app = FastAPI(title="CyberGuardian API")

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
