
# 

import time
from dataclasses import dataclass, field
from typing import Optional

from database import db_cursor
from security import verify_record_hmac
from audit import log_event



# The IntegrityReport dataclass is used to store the results of an integrity check on a database table. 
# It includes fields for the timestamp of the check, the name of the table, the total number of records checked, the number of records that passed and failed the integrity check, and a list of IDs for any records that failed. 
# The class also has a property method ok to determine if all records passed and a summary method to provide a formatted string summarizing the results of the integrity check.

@dataclass  
class IntegrityReport:
    timestamp: float = field(default_factory=time.time)
    table: str = ""
    total_checked: int = 0
    passed: int = 0
    failed: int = 0
    failed_ids: list = field(default_factory=list)

    # The @property decorator is used to define a method that can be accessed like an attribute. 
    # In this case, the ok method is defined as a property, allowing you to check if all records passed the integrity check by simply accessing report.ok instead of calling it as a method (report.ok()). 
    # This makes the code more readable and intuitive when checking the integrity status.

    @property 
    def ok(self) -> bool:  # The ok property checks if the number of failed records is zero, indicating that all records passed the integrity check. 
        return self.failed == 0     # It returns True if there are no failed records and False otherwise.

    def summary(self) -> str:                      # The summary method generates a formatted string that summarizes the results of the integrity check for a specific table.
        status = "PASS" if self.ok else "FAIL"
        return (
            f"Table '{self.table}': {self.total_checked} records checked | "      # The summary includes the name of the table, the total number of records checked, the number of records that passed and failed, and an overall status indicating whether the integrity check passed or failed.
            f"{self.passed} passed | {self.failed} failed | Status: {status}"
        )


# The _verify_table function performs an integrity check on a specified database table by retrieving all records,
    #  verifying their HMACs, and generating an IntegrityReport with the results.
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



# The run_full_integrity_check function runs integrity checks on multiple database tables,
#  collects the results in a list of IntegrityReport objects, and logs any integrity failures.
def run_full_integrity_check() -> list[IntegrityReport]:

    """
    Run HMAC verification on all protected tables.
    Returns one IntegrityReport per table.
    Logs INTEGRITY_FAIL events for any tampered rows.
    """
    reports = []   # Define the tables to check and their ID columns (used for logging failed records)
    tables = [
        ("users", "id"),
        ("customers", "id"),
        ("employees", "id"),
        ("audit_log", "id"),
    ]

    any_failure = False    # Run checks for each table and collect reports. If any failures are found, log them.
    for table, id_col in tables:
        try:
            report = _verify_table(table, id_col)   
            reports.append(report)
            if not report.ok:
                any_failure = True     # If the integrity check for a table fails, set the any_failure flag to True and log an INTEGRITY_FAIL event for each failed record, including the table name and record ID in the event details.
                for rid in report.failed_ids:
                    log_event(
                        "INTEGRITY_FAIL", "failure",
                        detail=f"table={table} record_id={rid}"
                    )
        except Exception as exc:   
            # Even if a table check fails, continue with the others
            r = IntegrityReport(table=table)
            r.failed = -1   # sentinel for "check error"
            reports.append(r)

    if not any_failure:
        log_event("INTEGRITY_CHECK", "success", detail="all_tables_passed")

    return reports


def verify_single_user(user_id: int) -> tuple[bool, list[str]]:
    """
    Verify the integrity of a single user and their profile record.
    Returns (all_ok: bool, list_of_issues).
    """
    issues = []

    # Check users row
    # This function verifies the integrity of a single user record
    #  and its associated profile record (either customer or employee) by checking the HMACs of the records.
    with db_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
    if not row:
        return False, ["User not found."]
    user = dict(row)
    if not verify_record_hmac(user):
        issues.append(f"users.id={user_id} — HMAC mismatch (record may have been tampered with)")

 # Check profile row (customer )
    role = user.get("role")   # The function retrieves the user's role from the user record and checks the corresponding profile table (customers for "customer" role and employees for "employee" role) to verify the integrity of the profile record. If the profile record is found, it checks the HMAC and adds any issues to the list of issues if there is a mismatch.
    if role == "customer":
        with db_cursor() as cur:
            cur.execute("SELECT * FROM customers WHERE user_id = ?", (user_id,))
            row = cur.fetchone()
        if row:
            cust = dict(row)
            if not verify_record_hmac(cust):
                issues.append(f"customers.user_id={user_id} — HMAC mismatch")
# Check profile row (employee)
    elif role == "employee":
        with db_cursor() as cur:
            cur.execute("SELECT * FROM employees WHERE user_id = ?", (user_id,))
            row = cur.fetchone()
        if row:
            emp = dict(row)
            if not verify_record_hmac(emp):
                issues.append(f"employees.user_id={user_id} — HMAC mismatch")

    return len(issues) == 0, issues







