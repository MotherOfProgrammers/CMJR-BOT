import logging

security_logger = logging.getLogger("cmjr.security")


def log_security_event(
    event: str,
    status_code: int | None = None,
    error_code: str | None = None,
) -> None:
    fields = {"event": event}

    if status_code is not None:
        fields["status_code"] = status_code

    if error_code is not None:
        fields["error_code"] = error_code

    security_logger.warning(fields)