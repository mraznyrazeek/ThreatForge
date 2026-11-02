
"""
ThreatForge - Alembic Migration Environment

Connects Alembic to the local PostgreSQL database and
registers SQLAlchemy model metadata for migrations.

Database credentials are loaded from the project .env.
Importing models does not create database tables.
"""

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from dotenv import load_dotenv
from sqlalchemy import create_engine, pool
from sqlalchemy.engine import URL


config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


# Project structure:
# ThreatForge/
#   .env
#   data-engineering/
#     alembic/
#       env.py
#     src/
#       models/
#         database_models.py

DATA_ENGINEERING_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = DATA_ENGINEERING_ROOT.parent
MODELS_DIR = DATA_ENGINEERING_ROOT / "src" / "models"

sys.path.insert(0, str(MODELS_DIR))

from database_models import Base  # noqa: E402


load_dotenv(
    PROJECT_ROOT / ".env",
    override=True,
)


def get_database_url() -> URL:
    """Build a PostgreSQL URL using environment settings."""

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


# Alembic now knows about all five database tables.
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Configure SQL migrations without connecting."""

    context.configure(
        url=get_database_url().render_as_string(
            hide_password=False
        ),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Configure migrations using a live PostgreSQL connection."""

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
