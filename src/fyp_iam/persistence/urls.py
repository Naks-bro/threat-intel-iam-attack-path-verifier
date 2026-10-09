"""Choose a PostgreSQL URL. Host vendors stay outside the foundry domain."""

import os
import socket
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fyp_iam.persistence.dotenv import load_local_env

_TRANSACTION_PORT = 6543


def application_database_url() -> str | None:
    """Return the URL the API should use, or None when persistence is unset."""

    load_local_env()
    direct = os.environ.get("FYP_DATABASE_DIRECT_URL", "").strip()
    session = os.environ.get("FYP_DATABASE_SESSION_URL", "").strip()
    if direct and session:
        chosen = direct if _ipv6_reaches(direct) else session
    else:
        chosen = os.environ.get("FYP_DATABASE_URL", "").strip()
    return chosen or None


def migration_database_url() -> str | None:
    """Return the Alembic URL. It falls back to the application URL."""

    load_local_env()
    override = os.environ.get("FYP_MIGRATION_DATABASE_URL", "").strip()
    if override:
        return override
    return application_database_url()


def prepare_url(url: str) -> tuple[str, str | None]:
    """Normalize SSL and reject endpoints that cannot serve this process.

    The error code is a fixed token. The returned URL is for the driver only.
    """

    if url.startswith("sqlite"):
        return url, "sqlite_rejected"
    parts = urlsplit(url)
    if parts.scheme not in {"postgresql", "postgresql+psycopg"}:
        return url, "unsupported_driver"
    port = parts.port or 5432
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    if port == _TRANSACTION_PORT or query.get("pool_mode") == "transaction":
        return url, "transaction_pooler_rejected"
    host = parts.hostname or ""
    certificate = os.environ.get("FYP_DATABASE_SSLROOTCERT", "").strip()
    if certificate:
        if not os.path.isfile(certificate):
            return url, "ssl_certificate_missing"
        query["sslmode"] = "verify-full"
        query["sslrootcert"] = certificate
    elif _managed_host(host):
        mode = query.get("sslmode", "")
        if mode in {"", "disable", "allow", "prefer"}:
            query["sslmode"] = "require"
    rebuilt = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
    return rebuilt, None


def _managed_host(host: str) -> bool:
    lowered = host.lower().rstrip(".")
    return lowered.endswith(".supabase.co") or lowered.endswith(".pooler.supabase.com")


def _ipv6_reaches(url: str) -> bool:
    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        return False
    port = parts.port or 5432
    try:
        addresses = socket.getaddrinfo(host, port, socket.AF_INET6, socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    for _family, _type, _proto, _canon, sockaddr in addresses:
        host_address = sockaddr[0]
        host_port = sockaddr[1]
        if not isinstance(host_address, str) or not isinstance(host_port, int):
            continue
        try:
            with socket.create_connection((host_address, host_port), timeout=2):
                return True
        except OSError:
            continue
    return False
