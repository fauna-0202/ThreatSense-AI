"""ThreatSense AI — Core FastAPI Application."""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from threatsense.config import settings
from threatsense.logging import logger
from threatsense.storage.database import init_db
from threatsense.api.routes import (
    health,
    sensor,
    events,
    alerts,
    analyze,
    models,
    metrics,
    export,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing ThreatSense AI database and services...")
    init_db()
    logger.info("ThreatSense AI backend ready for requests.")
    yield
    logger.info("ThreatSense AI backend shutting down.")


app = FastAPI(
    title=settings.app.name,
    description="Intelligent Network Threat Detection with Explainable AI and Uncertainty Awareness",
    version=settings.app.version,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware with strictly configured trusted origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


# Global Exception Handler to prevent information leakage
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception during {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "INTERNAL_SERVER_ERROR",
            "message": "An internal processing error occurred. Check system logs for details.",
        },
    )


# Include Routers
app.include_router(health.router)
app.include_router(sensor.router, prefix=settings.api.prefix)
app.include_router(events.router, prefix=settings.api.prefix)
app.include_router(alerts.router, prefix=settings.api.prefix)
app.include_router(analyze.router, prefix=settings.api.prefix)
app.include_router(models.router, prefix=settings.api.prefix)
app.include_router(metrics.router, prefix=settings.api.prefix)
app.include_router(export.router, prefix=settings.api.prefix)


if __name__ == "__main__":
    uvicorn.run(
        "threatsense.api.main:app",
        host=settings.api.host,
        port=settings.api.port,
        reload=settings.app.debug,
    )
