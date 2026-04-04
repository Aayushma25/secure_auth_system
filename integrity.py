
# 

import time
from dataclasses import dataclass, field
from typing import Optional

from database import db_cursor
from security import verify_record_hmac
from audit import log_event


@dataclass
class IntegrityReport:
    timestamp: float = field(default_factory=time.time)
    table: str = ""
    total_checked: int = 0
    passed: int = 0
    failed: int = 0
    failed_ids: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.failed == 0

    def summary(self) -> str:
        status = "PASS" if self.ok else "FAIL"
        return (
            f"Table '{self.table}': {self.total_checked} records checked | "
            f"{self.passed} passed | {self.failed} failed | Status: {status}"
        )


def _verify_table(table: str, id_column: str = "id") -> IntegrityReport:
    report = IntegrityReport(table=table)
    with db_cursor() as cur:
        cur.execute(f"SELECT * FROM {table}")    # nosec — table name is hardcoded, not user input
        rows = cur.fetchall()

    for row in rows:
        record = dict(row)
        report.total_checked += 1
        if verify_record_hmac(record):
            report.passed += 1
        else:
            report.failed += 1
            report.failed_ids.append(record.get(id_column, "?"))

    return report


def run_full_integrity_check() -> list[IntegrityReport]:

 """
    Run HMAC verification on all protected tables.
    Returns one IntegrityReport per table.
    Logs INTEGRITY_FAIL events for any tampered rows.
    """
    reports = []
    tables = [
        ("users", "id"),
        ("customers", "id"),
        ("employees", "id"),
        ("audit_log", "id"),
    ]

    any_failure = False
    for table, id_col in tables:
        try:
            report = _verify_table(table, id_col)
            reports.append(report)
            if not report.ok:
                any_failure = True
                for rid in report.failed_ids:
                    log_event(
                        "INTEGRITY_FAIL", "failure",
                        detail=f"table={table} record_id={rid}"
                    )
    if not any_failure:
        log_event("INTEGRITY_CHECK", "success", detail="all_tables_passed")

    return reports