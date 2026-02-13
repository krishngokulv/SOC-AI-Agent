"""FastAPI server entry point for SOC-AI-Agent."""

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from config import config
from database.db import get_db
from api.routes import router


app = FastAPI(
    title="SOC-AI-Agent",
    description="Autonomous SOC Analyst Agent — Automated alert investigation and threat intelligence platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router)


@app.on_event("startup")
async def startup():
    """Initialize database and configuration on startup."""
    config.init()
    db = await get_db()
    await db.init_db()


@app.on_event("shutdown")
async def shutdown():
    """Clean up resources on shutdown."""
    db = await get_db()
    await db.close()


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "SOC-AI-Agent",
        "version": "1.0.0",
    }


# Mount reports directory for static file serving
reports_dir = Path(config.REPORT_DIR)
reports_dir.mkdir(parents=True, exist_ok=True)
app.mount("/reports", StaticFiles(directory=str(reports_dir)), name="reports")


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=config.HOST,
        port=config.PORT,
        reload=config.DEBUG,
        ws_ping_interval=30,
        ws_ping_timeout=30,
    )
