
"""
ThreatForge - PostgreSQL Connection Verification

Loads local database settings from the project's .env file
and verifies connectivity through SQLAlchemy.

Read-only connection test. No tables or data are modified.
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import SQLAlchemyError


PROJECT_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(PROJECT_ROOT / ".env", override=True)


def create_database_engine():
    """Create a PostgreSQL engine without exposing credentials."""

    required = [
        "DB_HOST",
        "DB_PORT",
        "DB_NAME",
        "DB_USER",
        "DB_PASSWORD",
    ]

    missing = [key for key in required if not os.getenv(key)]

    if missing:
        raise ValueError(
            "Missing database configuration: "
            + ", ".join(missing)
        )

    url = URL.create(
        drivername="postgresql+psycopg",
        username=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        host=os.environ["DB_HOST"],
        port=int(os.environ["DB_PORT"]),
        database=os.environ["DB_NAME"],
    )

    return create_engine(
        url,
        pool_pre_ping=True,
        connect_args={"connect_timeout": 5},
    )


def main():
    engine = None

    try:
        engine = create_database_engine()

        with engine.connect() as connection:
            result = connection.execute(
                text(
                    """
                    SELECT
                        current_database() AS database_name,
                        current_user AS database_user,
                        current_setting('server_version') AS version
                    """
                )
            ).mappings().one()

            print("\n=== THREATFORGE DATABASE CONNECTION ===")
            print("Connection status: SUCCESS")
            print(f"Database: {result['database_name']}")
            print(f"User: {result['database_user']}")
            print(f"PostgreSQL version: {result['version']}")

            assert result["database_name"] == os.environ["DB_NAME"]
            assert result["database_user"] == os.environ["DB_USER"]

            print("Database identity verification: PASSED")
            print("\nNo tables or records were modified.")

    except (SQLAlchemyError, ValueError, AssertionError) as exc:
        print("\n=== THREATFORGE DATABASE CONNECTION ===")
        print("Connection status: FAILED")
        print(f"Error category: {type(exc).__name__}")
        raise SystemExit(1) from None

    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    main()
