import sqlite3
from pathlib import Path
from threading import Lock
from app.core.config import get_settings
from app.models.security import SecurityEvent


class AuditService:
    def __init__(self, database_url: str | None = None) -> None:
        database_url = database_url or get_settings().database_url
        database_path = self._path_from_sqlite_url(database_url)
        self.database_path = Path(database_path)
        self._lock = Lock()
        self._init_db()

    @staticmethod
    def _path_from_sqlite_url(database_url: str) -> str:
        if database_url.startswith("sqlite:///"):
            return database_url.removeprefix("sqlite:///")
        return database_url

    def _connect(self) -> sqlite3.Connection:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.database_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    agent_id TEXT,
                    rule TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )

    def record(self, event: SecurityEvent) -> SecurityEvent:
        payload = event.model_dump_json()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO audit_events
                (id, timestamp, type, title, severity, decision, agent_id, rule, confidence, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.timestamp.isoformat(),
                    event.type.value,
                    event.title,
                    event.severity.value,
                    event.decision.value,
                    event.agent_id,
                    event.rule,
                    event.confidence,
                    payload,
                ),
            )
        return event

    def recent(self, limit: int = 50) -> list[SecurityEvent]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM audit_events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [SecurityEvent.model_validate_json(row["payload"]) for row in rows]

    def analytics(self) -> dict:
        events = self.recent(250)
        blocked = sum(1 for event in events if event.decision.value == "blocked")
        by_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for event in events:
            by_type[event.type.value] = by_type.get(event.type.value, 0) + 1
            by_severity[event.severity.value] = by_severity.get(event.severity.value, 0) + 1
        return {
            "total_events": len(events),
            "blocked_events": blocked,
            "block_rate": round(blocked / len(events), 2) if events else 0,
            "by_type": by_type,
            "by_severity": by_severity,
        }


audit_service = AuditService()
