"""
Runs the access review: builds the SQLite database, executes every test in
sql/tests/, and writes the results.

  output/audit.db               the database (open it in DB Browser for SQLite)
  output/findings/AR-0X.csv     every exception for each test
  output/audit_report.md        the audit report

Usage:  python scripts/run_audit.py
Only the Python standard library is needed.
"""
import csv
import re
import sqlite3
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "output"
SEV_ORDER = {"High": 0, "Medium": 1, "Low": 2}
MAX_ROWS_IN_REPORT = 10


def build_db() -> sqlite3.Connection:
    OUT.mkdir(exist_ok=True)
    db = OUT / "audit.db"
    if db.exists():
        db.unlink()
    conn = sqlite3.connect(db)
    conn.executescript((ROOT / "sql" / "schema.sql").read_text())
    conn.executescript((ROOT / "data" / "seed.sql").read_text())
    return conn


def parse_test(path: Path) -> dict:
    sql = path.read_text()
    meta = dict(re.findall(r"^--\s*@(\w+):\s*(.+)$", sql, flags=re.M))
    meta["sql"] = sql
    meta["file"] = path.name
    return meta


def md_table(cols, rows) -> str:
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        out.append("| " + " | ".join("" if v is None else str(v).replace("|", "/") for v in r) + " |")
    return "\n".join(out)


def main():
    conn = build_db()
    (OUT / "findings").mkdir(exist_ok=True)

    population = {
        "employees": conn.execute("SELECT COUNT(*) FROM employees").fetchone()[0],
        "terminated": conn.execute("SELECT COUNT(*) FROM employees WHERE termination_date IS NOT NULL").fetchone()[0],
        "accounts": conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0],
        "enabled": conn.execute("SELECT COUNT(*) FROM accounts WHERE status='enabled'").fetchone()[0],
        "grants": conn.execute("SELECT COUNT(*) FROM account_roles").fetchone()[0],
        "logins": conn.execute("SELECT COUNT(*) FROM login_events").fetchone()[0],
        "systems": ", ".join(r[0] for r in conn.execute("SELECT system_name FROM systems ORDER BY system_id")),
    }

    results = []
    for path in sorted((ROOT / "sql" / "tests").glob("*.sql")):
        t = parse_test(path)
        cur = conn.execute(t["sql"])
        cols = [c[0] for c in cur.description]
        rows = cur.fetchall()
        with open(OUT / "findings" / f"{t['id']}.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(cols)
            w.writerows(rows)
        results.append((t, cols, rows))
        status = "EXCEPTIONS" if rows else "PASS"
        print(f"  {t['id']}  {t['severity']:<6}  {status:<10}  {len(rows):>3}  {t['title']}")

    exceptions = [r for r in results if r[2]]
    high = sum(1 for t, _, rows in results if rows and t["severity"] == "High")

    lines = [
        "# IT Access Review Audit Report",
        "",
        "**Entity:** Ridgeline Logistics *(fictional company, generated data)*  ",
        "**Review period:** 2026-05-01 to 2026-10-31  ",
        f"**Report generated:** {date.today().isoformat()}  ",
        "**Framework:** NIST CSF 2.0 (Identity Management & Access Control) and ISO/IEC 27001:2022 Annex A",
        "",
        "## 1. Scope",
        f"- **Systems:** {population['systems']}",
        f"- **Population:** {population['employees']} employees ({population['terminated']} who left the company in 2026), "
        f"{population['accounts']} accounts ({population['enabled']} enabled), {population['grants']} role assignments, "
        f"{population['logins']:,} login events",
        "- **Approach:** 100% of the population was tested with SQL queries (no sampling). Each test compares system "
        "access data against HR records and the company's access policies.",
        "",
        "## 2. Executive Summary",
        "",
        f"{len(results)} access controls were tested. **{len(exceptions)} had exceptions**, including "
        f"**{high} high-risk** findings. The most serious issue is that access was not removed when employees left, "
        "and in some cases those accounts were used after termination. That should be treated as a possible security "
        "incident, not only a control gap.",
        "",
        md_table(["ID", "Control tested", "Risk", "Exceptions", "Result"],
                 [(t["id"], t["title"], t["severity"], len(rows), "Exception" if rows else "Pass")
                  for t, _, rows in results]),
        "",
        "## 3. Detailed Findings",
        "",
    ]

    ordered = sorted(exceptions, key=lambda r: (SEV_ORDER.get(r[0]["severity"], 9), r[0]["id"]))
    for t, cols, rows in ordered:
        lines += [
            f"### {t['id']}: {t['title']}  ({t['severity']} risk)",
            "",
            f"**Condition:** {len(rows)} exception(s) found. "
            + (f"The full list is in `output/findings/{t['id']}.csv`." if len(rows) <= MAX_ROWS_IN_REPORT
               else f"The first {MAX_ROWS_IN_REPORT} are shown below; the full list is in `output/findings/{t['id']}.csv`."),
            "",
            md_table(cols, rows[:MAX_ROWS_IN_REPORT]),
            "",
            f"**Criteria:** {t['criteria']}",
            "",
            f"**Risk:** {t['risk']}",
            "",
            f"**Recommendation:** {t['recommendation']}",
            "",
            f"**Framework:** NIST CSF {t['nist']} · ISO 27001 {t['iso']}  ",
            f"**Test query:** [`sql/tests/{t['file']}`](../sql/tests/{t['file']})",
            "",
        ]

    lines += [
        "## 4. Limitations",
        "- Point-in-time review of exported data; changes made after the export are not reflected.",
        "- Login data covers the review period only, so dormancy is measured within that window.",
        "- Exceptions are leads for follow-up with system owners. Some (e.g. an approved change window for off-hours admin "
        "work) may turn out to be justified, and would then be documented as accepted exceptions.",
        "",
    ]
    (OUT / "audit_report.md").write_text("\n".join(lines))
    print(f"\n{len(exceptions)} of {len(results)} tests had exceptions ({high} high-risk).")
    print(f"Report:   {OUT / 'audit_report.md'}")
    print(f"Database: {OUT / 'audit.db'}")


if __name__ == "__main__":
    main()
