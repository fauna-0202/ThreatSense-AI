"""API dependencies: Database session and authentication."""

from typing import Optional
from fastapi import Header, HTTPException, status
from threatsense.config import settings
from threatsense.storage.database import SessionLocal
from threatsense.logging import logger


def get_db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key")
) -> bool:
    """Verifies API key for mutating or sensitive actions.
    
    In production mode:
      - Requires a valid non-empty X-API-Key header matching THREATSENSE_API_KEY.
      - Fails closed if the configured server key is missing or set to an insecure default.
    In development mode:
      - Accepts matching key if provided.
      - Permits local requests if no key was passed, enabling rapid local dashboard interaction.
    """
    is_prod = (not settings.app.debug) or (settings.app.env == "production")

    if is_prod:
        if not settings.api.api_key or settings.api.api_key.startswith("dev-") or settings.api.api_key == "ts-demo-api-key-2026":
            logger.error("Security failure: Production mode enabled without a strong THREATSENSE_API_KEY configured.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Server configuration error: Secure API key not configured for production mode.",
            )
        if x_api_key == settings.api.api_key:
            return True
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key in X-API-Key header",
        )

    # In development mode:
    if x_api_key is not None and x_api_key == settings.api.api_key:
        return True

    if settings.app.debug and x_api_key is None:
        return True

    # If key was explicitly passed in dev but didn't match:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API key in X-API-Key header",
    )
