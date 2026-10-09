"""Alembic environment. Migrations use FYP_MIGRATION_DATABASE_URL when it is set."""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool, text

from fyp_iam.engine1.foundry.models import Base
from fyp_iam.engine2.schema import metadata as inventory_metadata
from fyp_iam.persistence.redact import install_redaction
from fyp_iam.persistence.urls import migration_database_url, prepare_url

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)
install_redaction()

target_metadata = [Base.metadata, inventory_metadata]


def _url() -> str:
    raw = migration_database_url()
    if not raw:
        raise RuntimeError("not_configured")
    prepared, error = prepare_url(raw)
    if error:
        raise RuntimeError(error)
    return prepared


def run_migrations_offline() -> None:
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        version_table_schema="foundry",
        include_schemas=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _url()
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        connection.execute(text("CREATE SCHEMA IF NOT EXISTS foundry"))
        connection.commit()
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table_schema="foundry",
            include_schemas=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
