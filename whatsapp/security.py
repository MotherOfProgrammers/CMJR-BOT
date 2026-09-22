import hmac


def verify_token(
    provided_token: str,
    expected_token: str,
) -> bool:
    if not provided_token or not expected_token:
        return False

    return hmac.compare_digest(
        provided_token,
        expected_token,
    )
