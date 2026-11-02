
"""
ThreatForge - Alembic Migration Environment

Loads PostgreSQL connection settings from the project .env.

Supports online and offline migrations without storing
database credentials in alembic.ini.

SQLAlchemy model metadata will be registered when the
database models are implemented.
"""

import os
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from dotenv import load_dotenv
from sqlalchemy import create_engine, pool
from sqlalchemy.engine import URL


config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(
    PROJECT_ROOT / ".env",
    override=True,
)


def get_database_url() -> URL:
    """Build the connection URL without exposing credentials."""

    required = (
        "DB_HOST",
        "DB_PORT",
        "DB_NAME",
        "DB_USER",
        "DB_PASSWORD",
    )

    missing = [
        name for name in required
        if not os.getenv(name)
    ]

    if missing:
        raise ValueError(
            "Missing database configuration: "
            + ", ".join(missing)
        )

    return URL.create(
        drivername="postgresql+psycopg",
        username=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        host=os.environ["DB_HOST"],
        port=int(os.environ["DB_PORT"]),
        database=os.environ["DB_NAME"],
    )


# Register SQLAlchemy model metadata here once our
# database models have been implemented.
target_metadata = None


def run_migrations_offline() -> None:
    """Configure migrations without a database connection."""

    url = get_database_url()

    context.configure(
        url=url.render_as_string(hide_password=False),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations using the PostgreSQL connection."""

    engine = create_engine(
        get_database_url(),
        poolclass=pool.NullPool,
        connect_args={"connect_timeout": 5},
    )

    try:
        with engine.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                compare_type=True,
            )

            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
