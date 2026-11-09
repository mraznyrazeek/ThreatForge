
"""
ThreatForge - PostgreSQL Ingestion Monitoring

Read-only operational monitoring.

Reports:
- Observations stored per source.
- Completed, failed and running ingestion jobs.
- Recent ingestion-run outcomes.
- Potentially stale running jobs.

Never displays IOC values or credentials.
"""

import os
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEVELOPMENT_DATABASE = "threatforge_db"


def create_monitoring_engine():
    load_dotenv(
        PROJECT_ROOT / ".env",
        override=True,
    )

    if os.getenv("DB_NAME") != DEVELOPMENT_DATABASE:
        raise ValueError(
            "Monitoring requires threatforge_db"
        )

    if not os.getenv("DB_USER") or not os.getenv("DB_PASSWORD"):
        raise ValueError(
            "Missing database credentials"
        )

    url = URL.create(
        "postgresql+psycopg",
        username=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "5432")),
        database=DEVELOPMENT_DATABASE,
    )

    return create_engine(
        url,
        pool_pre_ping=True,
    )


def monitor(engine):
    with engine.connect() as connection:
        connection.execute(
            text("SET TRANSACTION READ ONLY")
        )

        actual_db = connection.execute(
            text("SELECT current_database()")
        ).scalar_one()

        if actual_db != DEVELOPMENT_DATABASE:
            raise ValueError(
                "Unexpected monitoring database"
            )

        print("=== THREATFORGE INGESTION MONITOR ===")
        print(
            "Checked UTC:",
            datetime.now(timezone.utc).isoformat(
                timespec="seconds"
            ),
        )
        print("Database:", actual_db)

        source_rows = connection.execute(
            text(
                """
                SELECT
                    s.name,
                    COUNT(o.id) AS observation_count
                FROM intelligence_sources s
                LEFT JOIN indicator_observations o
                    ON o.source_id = s.id
                GROUP BY s.id, s.name
                ORDER BY s.name
                """
            )
        ).mappings().all()

        print("\n=== SOURCE OBSERVATIONS ===")

        for row in source_rows:
            print(
                f"{row['name']}: "
                f"{row['observation_count']}"
            )

        status_rows = connection.execute(
            text(
                """
                SELECT
                    s.name,
                    r.status,
                    COUNT(*) AS run_count
                FROM ingestion_runs r
                JOIN intelligence_sources s
                    ON s.id = r.source_id
                GROUP BY s.name, r.status
                ORDER BY s.name, r.status
                """
            )
        ).mappings().all()

        print("\n=== INGESTION RUN STATUS ===")

        for row in status_rows:
            print(
                f"{row['name']} | "
                f"{row['status']}: "
                f"{row['run_count']}"
            )

        recent_rows = connection.execute(
            text(
                """
                SELECT
                    r.id,
                    s.name AS source_name,
                    r.status,
                    r.records_received,
                    r.records_normalized,
                    r.records_rejected,
                    r.started_at,
                    r.completed_at,
                    CASE
                        WHEN r.status = 'running'
                         AND r.started_at <
                             clock_timestamp()
                             - INTERVAL '15 minutes'
                        THEN TRUE
                        ELSE FALSE
                    END AS potentially_stale
                FROM ingestion_runs r
                JOIN intelligence_sources s
                    ON s.id = r.source_id
                ORDER BY r.id DESC
                LIMIT 10
                """
            )
        ).mappings().all()

        print("\n=== RECENT INGESTION RUNS ===")

        for row in recent_rows:
            print(
                f"Run #{row['id']} | "
                f"{row['source_name']} | "
                f"{row['status']} | "
                f"received={row['records_received']} | "
                f"normalized={row['records_normalized']} | "
                f"rejected={row['records_rejected']}"
            )

            if row["potentially_stale"]:
                print(
                    "  WARNING: Run has been active "
                    "for more than 15 minutes"
                )

        print("\nMonitoring completed (read-only).")


def main() -> int:
    engine = None

    try:
        engine = create_monitoring_engine()
        monitor(engine)
        return 0

    except Exception as exc:
        print(
            "Monitoring failed: "
            f"{type(exc).__name__}"
        )
        return 1

    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
