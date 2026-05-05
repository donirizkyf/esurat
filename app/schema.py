import sqlite3

from app.database import DATABASE_PATH


def _column_names(connection: sqlite3.Connection, table_name: str) -> set[str]:
    rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row[1] for row in rows}


def sync_schema() -> None:
    connection = sqlite3.connect(DATABASE_PATH)
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "users" in tables:
            columns = _column_names(connection, "users")
            migrations: list[str] = []

            if "company_name" not in columns:
                migrations.append("ALTER TABLE users ADD COLUMN company_name VARCHAR(255)")
            if "email" not in columns:
                migrations.append("ALTER TABLE users ADD COLUMN email VARCHAR(255)")
            if "business_id" not in columns:
                migrations.append("ALTER TABLE users ADD COLUMN business_id VARCHAR(100)")
            if "pic_name" not in columns:
                migrations.append("ALTER TABLE users ADD COLUMN pic_name VARCHAR(255)")
            if "staff_role" not in columns:
                migrations.append("ALTER TABLE users ADD COLUMN staff_role VARCHAR(50)")
            if "section_name" not in columns:
                migrations.append("ALTER TABLE users ADD COLUMN section_name VARCHAR(150)")
            if "account_status" not in columns:
                migrations.append("ALTER TABLE users ADD COLUMN account_status VARCHAR(20) DEFAULT 'ACTIVE'")

            for statement in migrations:
                connection.execute(statement)

            current_columns = _column_names(connection, "users")
            if "email" in current_columns:
                legacy_rows = connection.execute(
                    "SELECT id, username, email FROM users"
                ).fetchall()
                for user_id, username, email in legacy_rows:
                    if email:
                        continue
                    username_value = username or f"user{user_id}"
                    normalized = username_value.lower()
                    fallback_email = normalized if "@" in normalized else f"{normalized}@legacy.local"
                    connection.execute(
                        "UPDATE users SET email = ? WHERE id = ?",
                        (fallback_email, user_id),
                    )

            if "account_status" in current_columns:
                connection.execute(
                    "UPDATE users SET account_status = 'ACTIVE' WHERE account_status IS NULL OR TRIM(account_status) = ''"
                )
            if "role" in current_columns:
                connection.execute(
                    "UPDATE users SET role = 'admin' WHERE role = 'monitoring'"
                )

            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users (email)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS ix_users_account_status ON users (account_status)"
            )

        if "document_submissions" in tables:
            submission_columns = _column_names(connection, "document_submissions")
            if "bagian" not in submission_columns:
                connection.execute(
                    "ALTER TABLE document_submissions ADD COLUMN bagian VARCHAR(100) DEFAULT 'Perijinan Cukai'"
                )
            if "agenda_number" not in submission_columns:
                connection.execute(
                    "ALTER TABLE document_submissions ADD COLUMN agenda_number VARCHAR(100)"
                )
            if "assigned_section" not in submission_columns:
                connection.execute(
                    "ALTER TABLE document_submissions ADD COLUMN assigned_section VARCHAR(150)"
                )
            if "assigned_staff_role" not in submission_columns:
                connection.execute(
                    "ALTER TABLE document_submissions ADD COLUMN assigned_staff_role VARCHAR(50)"
                )
            connection.execute(
                "UPDATE document_submissions SET bagian = 'Perijinan Cukai' WHERE bagian IS NULL OR TRIM(bagian) = ''"
            )
            current_submission_columns = _column_names(connection, "document_submissions")
            if "assigned_section" in current_submission_columns:
                connection.execute(
                    "UPDATE document_submissions SET assigned_section = bagian WHERE assigned_section IS NULL OR TRIM(assigned_section) = ''"
                )
            if "assigned_staff_role" in current_submission_columns:
                connection.execute(
                    "UPDATE document_submissions SET assigned_staff_role = 'OA' WHERE assigned_staff_role IS NULL OR TRIM(assigned_staff_role) = ''"
                )
            if "status" in current_submission_columns:
                connection.execute(
                    "UPDATE document_submissions SET status = 'MENUNGGU_VERIFIKASI_PIC' WHERE status = 'DIVERIFIKASI'"
                )
                connection.execute(
                    "UPDATE document_submissions SET status = 'TERDISTRIBUSI_KE_STAFF' WHERE status IN ('DITERIMA', 'DIPROSES')"
                )
        connection.commit()
    finally:
        connection.close()
