from fastapi import HTTPException


def webhook_error(
    status_code: int,
    error_code: str,
    message: str,
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={
            "error": error_code,
            "message": message,
        },
    )