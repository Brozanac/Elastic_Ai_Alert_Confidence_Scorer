import hmac
import os

from app_logging import logger
from dotenv import load_dotenv
from errors import unauthorized
from fastapi import Header

load_dotenv()


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    expected_api_key = os.getenv("APP_API_KEY")

    if not expected_api_key:
        # Fail closed: without a configured key, protected endpoints are locked,
        # unless a developer explicitly opts out for local work.
        if os.getenv("ALLOW_UNAUTHENTICATED", "false").lower() == "true":
            logger.warning("api_key_check_disabled_by_allow_unauthenticated")
            return
        logger.error("app_api_key_not_configured")
        raise unauthorized("Invalid or missing API key.")

    if not x_api_key or not hmac.compare_digest(
        x_api_key.encode(), expected_api_key.encode()
    ):
        logger.warning("invalid_or_missing_api_key_for_history_endpoint")
        raise unauthorized("Invalid or missing API key.")