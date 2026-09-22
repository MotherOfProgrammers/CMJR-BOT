import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from database.database import get_connection, initialize_database
from config import validate_config
from webhook.routes import router
from admin.routes import router as admin_router

logging.basicConfig(level=logging.INFO)

logger = logging.getLogger("cmjr.app")

validate_config()

app = FastAPI(title="WhatsApp Security Bot")


@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
):
    if request.url.path.startswith("/webhook"):
        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_PAYLOAD",
                "message": "Request validation failed",
            },
        )
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()},
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(
    request: Request,
    exc: HTTPException,
):
    if request.url.path.startswith("/webhook"):
        if isinstance(exc.detail, dict) and "error" in exc.detail:
            return JSONResponse(
                status_code=exc.status_code,
                content=exc.detail,
            )
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": "HTTP_ERROR",
                "message": str(exc.detail),
            },
        )
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(
    request: Request,
    exc: Exception,
):
    logger.exception(
        "Unhandled exception during %s %s",
        request.method,
        request.url.path,
    )
    if request.url.path.startswith("/webhook"):
        return JSONResponse(
            status_code=500,
            content={
                "error": "INTERNAL_ERROR",
                "message": "Internal server error",
            },
        )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


initialize_database()

app.include_router(router, prefix="/webhook")
app.include_router(admin_router, prefix="/admin")


@app.get("/")
async def root():
    return {"status": "online"}


@app.get("/health")
async def health():
    try:
        connection = get_connection()
        connection.execute("SELECT 1").fetchone()
        connection.close()
    except Exception:
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "database": "unreachable"},
        )

    return {"status": "ok", "database": "ok"}