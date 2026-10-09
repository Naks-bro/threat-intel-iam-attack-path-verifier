"""Remove connection secrets from text that might be logged."""

import logging
import re

_URL = re.compile(r"postgres(?:ql)?(?:\+[a-z]+)?:\/\/[^\s'\"\\]+", re.IGNORECASE)
_USERINFO = re.compile(r"://[^/\s@]+@")
_SUPABASE_HOST = re.compile(
    r"\b(?:[a-z0-9-]+\.)*(?:supabase\.co|pooler\.supabase\.com)\b",
    re.IGNORECASE,
)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}\b", re.IGNORECASE)


def redact(value: str) -> str:
    """Replace database URLs and managed-host names with fixed tokens."""

    cleaned = _URL.sub("postgresql://redacted", value)
    cleaned = _USERINFO.sub("://redacted@", cleaned)
    cleaned = _SUPABASE_HOST.sub("database-host", cleaned)
    cleaned = _IPV4.sub(
        lambda match: match.group(0) if match.group(0).startswith("127.") else "redacted-address",
        cleaned,
    )
    return _IPV6.sub("redacted-address", cleaned)


class RedactingFilter(logging.Filter):
    """Rewrite log records before they reach a handler."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(_redact_arg(item) for item in record.args)
        elif isinstance(record.args, dict):
            record.args = {key: _redact_arg(item) for key, item in record.args.items()}
        if record.exc_info:
            record.exc_text = redact(logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


def install_redaction() -> None:
    """Attach one redaction filter to the loggers that see database failures."""

    redactor = RedactingFilter()
    for name in ("", "sqlalchemy", "sqlalchemy.engine", "uvicorn", "uvicorn.error", "alembic"):
        logger = logging.getLogger(name)
        if not any(isinstance(item, RedactingFilter) for item in logger.filters):
            logger.addFilter(redactor)


def _redact_arg(value: object) -> object:
    if isinstance(value, str):
        return redact(value)
    return value
