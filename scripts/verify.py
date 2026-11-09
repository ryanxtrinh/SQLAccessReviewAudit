"""
Checks that every audit query finds exactly the issues planted in the data
(data/planted_issues.json): no misses, no false positives.

Usage:  python scripts/run_audit.py && python scripts/verify.py
"""
import json
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
conn = sqlite3.connect(ROOT / "output" / "audit.db")
planted = json.loads((ROOT / "data" / "planted_issues.json").read_text())


def run(name):
    sql = (ROOT / "sql" / "tests" / name).read_text()
    cur = conn.execute(sql)
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def accts(ids):
    q = f"SELECT system_id, username FROM accounts WHERE account_id IN ({','.join('?' * len(ids))})"
    return {tuple(r) for r in conn.execute(q, ids)}


def emps(ids):
    q = f"SELECT first_name || ' ' || last_name FROM employees WHERE employee_id IN ({','.join('?' * len(ids))})"
    return {r[0] for r in conn.execute(q, ids)}


checks = [
    ("AR-01", accts(planted["terminated_enabled_accounts"]),
     {(r["system_id"], r["username"]) for r in run("01_terminated_users_active.sql")}),
    ("AR-02", accts(planted["post_termination_login_accounts"]),
     {(r["system_id"], r["username"]) for r in run("02_logins_after_termination.sql")}),
    ("AR-03", emps([p["employee_id"] for p in planted["sod_conflict_employees"]]),
     {r["employee"] for r in run("03_sod_conflicts.sql")}),
    ("AR-04", accts(planted["dormant_accounts"]),
     {(r["system_id"], r["username"]) for r in run("04_dormant_accounts.sql")}),
    ("AR-05", accts(planted["privileged_non_it_accounts"]),
     {(r["system_id"], r["username"]) for r in run("05_privileged_access_outside_it.sql")}),
    ("AR-06", accts(planted["orphaned_accounts"]),
     {(r["system_id"], r["username"]) for r in run("06_orphaned_accounts.sql")}),
    ("AR-07", accts(planted["generic_accounts"]),
     {(r["system_id"], r["username"]) for r in run("07_shared_generic_accounts.sql")}),
    ("AR-08", accts(planted["off_hours_privileged_accounts"]),
     {(r["system_id"], r["username"]) for r in run("08_off_hours_privileged_logins.sql")}),
]

ok = True
for tid, expected, found in checks:
    missed, extra = expected - found, found - expected
    status = "OK" if not missed and not extra else "MISMATCH"
    ok &= status == "OK"
    print(f"{tid}: {status}  expected {len(expected)}, found {len(found)}"
          + (f"  missed={sorted(missed)}" if missed else "") + (f"  extra={sorted(extra)}" if extra else ""))
print("\nAll tests match the planted issues." if ok else "\nSome tests do not match.")
raise SystemExit(0 if ok else 1)
