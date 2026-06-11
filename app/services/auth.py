import secrets

from fastapi import Request

from app.config import API_TOKEN

PUBLIC_PATHS = {"/", "/status", "/healthz"}


def is_public_path(path: str) -> bool:
    return path in PUBLIC_PATHS or path.startswith("/docs") or path.startswith("/openapi")


def is_authorized(request: Request) -> bool:
    if not API_TOKEN:
        return True

    auth_header = request.headers.get("authorization", "")
    bearer_prefix = "Bearer "
    bearer_token = (
        auth_header[len(bearer_prefix):].strip()
        if auth_header.startswith(bearer_prefix)
        else ""
    )
    header_token = request.headers.get("x-api-token", "").strip()

    return (
        secrets.compare_digest(bearer_token, API_TOKEN)
        or secrets.compare_digest(header_token, API_TOKEN)
    )
