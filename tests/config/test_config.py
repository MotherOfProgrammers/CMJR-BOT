from config import validate_config
import config


def set_config(monkeypatch, **values):
    monkeypatch.setattr(config, "PROVIDER", "generic")
    monkeypatch.setattr(config, "MAX_PAYLOAD_BYTES", 100000)
    monkeypatch.setattr(config, "WEBHOOK_TOKEN", "secret-token")
    monkeypatch.setattr(config, "ADMIN_TOKEN", "admin-secret")

    for name, value in values.items():
        monkeypatch.setattr(config, name, value)


def test_valid_generic_config_passes(monkeypatch, caplog):
    set_config(monkeypatch)

    with caplog.at_level("WARNING", logger="cmjr.config"):
        validate_config()

    assert not any(
        record.levelno >= 30
        for record in caplog.records
    )


def test_invalid_provider_raises(monkeypatch):
    set_config(monkeypatch, PROVIDER="telegram")

    try:
        validate_config()
        raised = False
    except ValueError as exc:
        raised = True
        assert "CMJR_PROVIDER" in str(exc)

    assert raised


def test_placeholder_tokens_warn(monkeypatch, caplog):
    set_config(
        monkeypatch,
        WEBHOOK_TOKEN="change-this-token",
        ADMIN_TOKEN="change-this-admin-token",
    )

    with caplog.at_level("WARNING", logger="cmjr.config"):
        validate_config()

    assert any(
        "placeholder" in record.getMessage()
        for record in caplog.records
    )


def test_missing_tokens_warn(monkeypatch, caplog):
    set_config(
        monkeypatch,
        WEBHOOK_TOKEN=None,
        ADMIN_TOKEN=None,
    )

    with caplog.at_level("WARNING", logger="cmjr.config"):
        validate_config()

    assert any(
        "not set" in record.getMessage()
        for record in caplog.records
    )


def test_small_max_payload_warns(monkeypatch, caplog):
    set_config(monkeypatch, MAX_PAYLOAD_BYTES=100)

    with caplog.at_level("WARNING", logger="cmjr.config"):
        validate_config()

    assert any(
        "very small" in record.getMessage()
        for record in caplog.records
    )


def test_meta_missing_credentials_warn(monkeypatch, caplog):
    set_config(monkeypatch, PROVIDER="meta")
    monkeypatch.setattr(config, "META_APP_SECRET", None)
    monkeypatch.setattr(config, "META_ACCESS_TOKEN", None)
    monkeypatch.setattr(config, "META_PHONE_NUMBER_ID", None)
    monkeypatch.setattr(config, "META_VERIFY_TOKEN", None)

    with caplog.at_level("WARNING", logger="cmjr.config"):
        validate_config()

    assert any(
        "CMJR_META_ACCESS_TOKEN" in record.getMessage()
        for record in caplog.records
    )


def test_meta_complete_credentials_no_warning(monkeypatch, caplog):
    set_config(monkeypatch, PROVIDER="meta")
    monkeypatch.setattr(config, "META_APP_SECRET", "s")
    monkeypatch.setattr(config, "META_ACCESS_TOKEN", "t")
    monkeypatch.setattr(config, "META_PHONE_NUMBER_ID", "p")
    monkeypatch.setattr(config, "META_VERIFY_TOKEN", "v")

    with caplog.at_level("WARNING", logger="cmjr.config"):
        validate_config()

    assert not any(
        "credentials are incomplete" in record.getMessage()
        for record in caplog.records
    )