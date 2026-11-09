"""
Generates the fictional Ridgeline Logistics dataset (data/seed.sql).

All people, usernames and IP addresses are invented. The data is deterministic
(fixed random seed), so every run produces the same file and the same findings.

A realistic access-review dataset is mostly clean. A small number of control
failures are planted on purpose, the kind an IT auditor actually finds:
  - terminated employees whose accounts were never disabled
  - logins after termination
  - segregation-of-duties conflicts
  - dormant accounts
  - admin rights outside IT
  - orphaned accounts with no owner
  - shared / generic accounts
  - privileged logins at odd hours
The ground truth is written to data/planted_issues.json so the audit queries
can be checked against it (scripts/verify.py).

Usage:  python scripts/generate_data.py
"""
import json
import random
from datetime import date, datetime, timedelta
from pathlib import Path

random.seed(2026)
ROOT = Path(__file__).resolve().parent.parent
AUDIT_DATE = date(2026, 10, 31)
PERIOD_START = date(2026, 5, 1)

FIRST = ["James", "Maria", "Robert", "Linda", "Michael", "Priya", "David", "Aisha", "Daniel", "Sofia",
         "Kevin", "Grace", "Brian", "Nina", "Carlos", "Hannah", "Jason", "Olivia", "Marcus", "Chloe",
         "Andre", "Leah", "Victor", "Megan", "Omar", "Rachel", "Luis", "Kayla", "Derek", "Yuna",
         "Patrick", "Imani", "Gavin", "Alicia", "Noah", "Fatima", "Ethan", "Bianca", "Owen", "Jada"]
LAST = ["Miller", "Garcia", "Johnson", "Nguyen", "Brown", "Patel", "Davis", "Wilson", "Lopez", "Clark",
        "Lewis", "Walker", "Hall", "Young", "King", "Wright", "Scott", "Green", "Baker", "Adams",
        "Nelson", "Hill", "Campbell", "Mitchell", "Roberts", "Carter", "Phillips", "Turner", "Parker", "Collins",
        "Morris", "Murphy", "Cook", "Rogers", "Morgan", "Cooper", "Reed", "Bailey", "Bell", "Kelly",
        "Howard", "Ward", "Cox", "Diaz", "Richardson", "Wood", "Watson", "Brooks", "Bennett", "Gray"]

DEPTS = {  # department: (headcount, titles)
    "IT": (20, ["IT Manager", "Systems Administrator", "Help Desk Technician", "Network Engineer", "Security Analyst"]),
    "Finance": (30, ["Controller", "Accounts Payable Clerk", "AP Manager", "Procurement Specialist", "Financial Analyst"]),
    "HR": (15, ["HR Manager", "HR Specialist", "Payroll Specialist", "Recruiter"]),
    "Operations": (75, ["Operations Manager", "Dispatcher", "Warehouse Supervisor", "Logistics Coordinator", "Driver Lead"]),
    "Sales": (40, ["Sales Manager", "Account Executive", "Sales Representative", "Customer Success Rep"]),
}
DEPT_OCTET = {"IT": 10, "Finance": 20, "HR": 30, "Operations": 40, "Sales": 50}

SYSTEMS = [("AD", "Active Directory", "High"), ("ERP", "ERP Financials", "High"),
           ("PAYROLL", "Payroll System", "High"), ("CRM", "Customer CRM", "Medium"),
           ("VPN", "Remote Access VPN", "Medium")]

ROLES = [  # role_id, system, name, privileged
    ("AD_USER", "AD", "Domain User", 0), ("AD_DOMAIN_ADMIN", "AD", "Domain Administrator", 1),
    ("IAM_USER_CREATE", "AD", "Create User Accounts", 0), ("IAM_ACCESS_APPROVE", "AD", "Approve Access Requests", 0),
    ("ERP_READ", "ERP", "ERP Read Only", 0), ("ERP_VENDOR_CREATE", "ERP", "Create/Modify Vendors", 0),
    ("ERP_PAYMENT_APPROVE", "ERP", "Approve Payments", 0), ("ERP_INVOICE_ENTER", "ERP", "Enter Invoices", 0),
    ("ERP_PAYMENT_RELEASE", "ERP", "Release Payment Runs", 0), ("ERP_SYSADMIN", "ERP", "ERP System Administrator", 1),
    ("PAY_VIEW", "PAYROLL", "View Payroll", 0), ("PAY_EDIT", "PAYROLL", "Edit Pay Rates", 0),
    ("PAY_APPROVE", "PAYROLL", "Approve Payroll Run", 0), ("PAY_ADMIN", "PAYROLL", "Payroll System Administrator", 1),
    ("CRM_USER", "CRM", "CRM User", 0), ("CRM_ADMIN", "CRM", "CRM Administrator", 1),
    ("VPN_USER", "VPN", "VPN Access", 0),
]
SOD_RULES = [
    ("SOD-01", "ERP_VENDOR_CREATE", "ERP_PAYMENT_APPROVE", "Creating vendors and approving payments lets one person pay a fake vendor"),
    ("SOD-02", "ERP_INVOICE_ENTER", "ERP_PAYMENT_RELEASE", "Entering invoices and releasing payment runs lets one person pay their own invoice"),
    ("SOD-03", "PAY_EDIT", "PAY_APPROVE", "Editing pay rates and approving payroll lets one person raise their own pay"),
    ("SOD-04", "IAM_USER_CREATE", "IAM_ACCESS_APPROVE", "Creating accounts and approving access lets one person grant themselves any access"),
]

employees, accounts, account_roles, logins = [], [], [], []
planted = {k: [] for k in ["terminated_enabled_accounts", "post_termination_login_accounts", "sod_conflict_employees",
                           "dormant_accounts", "privileged_non_it_accounts", "orphaned_accounts",
                           "generic_accounts", "off_hours_privileged_accounts"]}
usernames = set()
next_acct = [1000]
next_event = [1]


def d(x): return x.isoformat()


def rand_date(a, b):
    return a + timedelta(days=random.randint(0, (b - a).days))


def uname(first, last):
    base = (first[0] + last).lower()
    u, n = base, 2
    while u in usernames:
        u, n = f"{base}{n}", n + 1
    usernames.add(u)
    return u


def add_account(system, username, emp_id, created, status="enabled", acct_type="user"):
    aid = next_acct[0]
    next_acct[0] += 1
    accounts.append(dict(account_id=aid, system_id=system, username=username, employee_id=emp_id,
                         account_type=acct_type, status=status, created_date=d(created)))
    return aid


def grant(aid, role, when):
    account_roles.append(dict(account_id=aid, role_id=role, granted_date=d(when)))


def login(aid, ts, ip, success=1):
    logins.append(dict(event_id=next_event[0], account_id=aid, login_time=ts.strftime("%Y-%m-%d %H:%M:%S"),
                       source_ip=ip, success=success))
    next_event[0] += 1


def business_time(day):
    return datetime(day.year, day.month, day.day, random.randint(7, 17), random.randint(0, 59), random.randint(0, 59))


def weekday_on_or_before(day):
    while day.weekday() >= 5:
        day -= timedelta(days=1)
    return day


def normal_logins(aid, ips, start, end, recent=True):
    """Roughly 1-2 logins a week on weekdays during business hours."""
    start = max(start, PERIOD_START)
    if start > end:
        return
    day = start
    while day <= end:
        for _ in range(random.choice([1, 1, 2])):
            dd = day + timedelta(days=random.randint(0, 4))
            if dd > end:
                continue
            dd = weekday_on_or_before(dd)
            if dd < start:
                continue
            if random.random() < 0.04:  # occasional typo'd password
                login(aid, business_time(dd), random.choice(ips), success=0)
            login(aid, business_time(dd), random.choice(ips))
        day += timedelta(days=7)
    if recent and end == AUDIT_DATE:   # guarantee activity in the last two weeks
        login(aid, business_time(weekday_on_or_before(AUDIT_DATE - timedelta(days=random.randint(0, 12)))), ips[0])


# ------------------------------------------------------------------ employees
emp_id = 1
by_dept = {}
for dept, (count, titles) in DEPTS.items():
    head = emp_id
    for i in range(count):
        first, last = random.choice(FIRST), random.choice(LAST)
        title = titles[0] if i == 0 else random.choice(titles[1:])
        hire = rand_date(date(2015, 1, 5), date(2026, 6, 30))
        employees.append(dict(employee_id=emp_id, first_name=first, last_name=last, department=dept, job_title=title,
                              manager_id=None if i == 0 else head, hire_date=d(hire), termination_date=None))
        by_dept.setdefault(dept, []).append(emp_id)
        emp_id += 1

E = {e["employee_id"]: e for e in employees}

# 14 leavers during the review period (never a department head)
leavers = random.sample([e for e in employees if e["manager_id"] is not None and e["hire_date"] < "2026-01-01"], 14)
for e in leavers:
    e["termination_date"] = d(rand_date(date(2026, 3, 1), date(2026, 10, 15)))

# ------------------------------------------------------------------ accounts + roles
emp_accounts = {}   # employee_id -> {system: account_id}
for e in employees:
    first, last, dept, title = e["first_name"], e["last_name"], e["department"], e["job_title"]
    hire = date.fromisoformat(e["hire_date"])
    term = date.fromisoformat(e["termination_date"]) if e["termination_date"] else None
    status = "disabled" if term else "enabled"
    u = uname(first, last)
    systems = ["AD", "VPN"]
    if dept == "Finance" or (dept == "Operations" and random.random() < 0.3):
        systems.append("ERP")
    if dept == "HR":
        systems.append("PAYROLL")
    if dept == "Sales":
        systems.append("CRM")
    emp_accounts[e["employee_id"]] = {}
    for s in systems:
        aid = add_account(s, u, e["employee_id"], hire, status)
        emp_accounts[e["employee_id"]][s] = aid
        base = {"AD": "AD_USER", "VPN": "VPN_USER", "ERP": "ERP_READ", "PAYROLL": "PAY_VIEW", "CRM": "CRM_USER"}[s]
        grant(aid, base, hire)
    # job-specific roles (each person holds at most one side of any SoD pair)
    acc = emp_accounts[e["employee_id"]]
    role = {"Procurement Specialist": "ERP_VENDOR_CREATE", "Controller": "ERP_PAYMENT_APPROVE",
            "Accounts Payable Clerk": "ERP_INVOICE_ENTER", "AP Manager": "ERP_PAYMENT_RELEASE",
            "Payroll Specialist": "PAY_EDIT", "HR Manager": "PAY_APPROVE",
            "Help Desk Technician": "IAM_USER_CREATE", "IT Manager": "IAM_ACCESS_APPROVE"}.get(title)
    if role:
        sysid = next(r[1] for r in ROLES if r[0] == role)
        if sysid not in acc:
            acc[sysid] = add_account(sysid, u, e["employee_id"], hire, status)
            grant(acc[sysid], {"ERP": "ERP_READ", "PAYROLL": "PAY_VIEW", "AD": "AD_USER"}[sysid], hire)
        grant(acc[sysid], role, hire + timedelta(days=random.randint(0, 30)))

# Legitimate admins: all in IT
it_staff = [i for i in by_dept["IT"] if not E[i]["termination_date"]]
sysadmins = [i for i in it_staff if E[i]["job_title"] == "Systems Administrator"][:2] or it_staff[1:3]
admin_assignments = [(sysadmins[0], "AD", "AD_DOMAIN_ADMIN"), (sysadmins[-1], "AD", "AD_DOMAIN_ADMIN"),
                     (it_staff[3], "ERP", "ERP_SYSADMIN"), (it_staff[4], "PAYROLL", "PAY_ADMIN"),
                     (it_staff[5], "CRM", "CRM_ADMIN")]
for eid, sysid, role in admin_assignments:
    acc = emp_accounts[eid]
    if sysid not in acc:
        acc[sysid] = add_account(sysid, accounts[[a["account_id"] for a in accounts].index(acc["AD"])]["username"],
                                 eid, date.fromisoformat(E[eid]["hire_date"]))
    grant(acc[sysid], role, date(2025, 1, 15))


def emp_username(eid):
    return next(a["username"] for a in accounts if a["account_id"] == emp_accounts[eid]["AD"])


def ensure_account(eid, sysid):
    acc = emp_accounts[eid]
    if sysid not in acc:
        acc[sysid] = add_account(sysid, emp_username(eid), eid, date.fromisoformat(E[eid]["hire_date"]))
        grant(acc[sysid], {"ERP": "ERP_READ", "PAYROLL": "PAY_VIEW", "AD": "AD_USER", "CRM": "CRM_USER"}[sysid],
              date.fromisoformat(E[eid]["hire_date"]))
    return acc[sysid]


active = [e for e in employees if not e["termination_date"] and e["manager_id"] is not None]
used = set(sysadmins + it_staff[:6])


def pick(dept, title=None):
    pool = [e["employee_id"] for e in active if e["department"] == dept and e["employee_id"] not in used
            and (title is None or e["job_title"] == title)]
    if not pool:
        pool = [e["employee_id"] for e in active if e["department"] == dept and e["employee_id"] not in used]
    eid = random.choice(pool)
    used.add(eid)
    return eid


# ------------------------------------------------------------------ PLANTED ISSUES
# 1. SoD conflicts (4 people)
for rule, role_a, role_b, _ in SOD_RULES:
    dept = {"SOD-01": "Finance", "SOD-02": "Finance", "SOD-03": "HR", "SOD-04": "IT"}[rule]
    title = {"SOD-01": "Procurement Specialist", "SOD-02": "Accounts Payable Clerk",
             "SOD-03": "Payroll Specialist", "SOD-04": "Help Desk Technician"}[rule]
    eid = pick(dept, title)
    sysid = next(r[1] for r in ROLES if r[0] == role_a)
    aid = ensure_account(eid, sysid)
    have = {r["role_id"] for r in account_roles if r["account_id"] == aid}
    for role in (role_a, role_b):
        if role not in have:
            grant(aid, role, date(2026, random.randint(1, 8), random.randint(1, 28)))
    planted["sod_conflict_employees"].append({"employee_id": eid, "rule": rule})

# 2. Admin rights outside IT (3 accounts)
for dept, sysid, role in [("Finance", "ERP", "ERP_SYSADMIN"), ("Operations", "AD", "AD_DOMAIN_ADMIN"), ("Sales", "CRM", "CRM_ADMIN")]:
    eid = pick(dept)
    aid = ensure_account(eid, sysid)
    grant(aid, role, date(2026, random.randint(2, 7), random.randint(1, 28)))
    planted["privileged_non_it_accounts"].append(aid)
ops_admin_acct = planted["privileged_non_it_accounts"][1]

# 3. Terminated employees whose access was never removed (4 people, 6 accounts)
missed = random.sample(leavers, 4)
for e in missed:
    for sysid, aid in emp_accounts[e["employee_id"]].items():
        if sysid in ("AD", "VPN") or (sysid in ("ERP", "CRM", "PAYROLL") and e is missed[0]):
            next(a for a in accounts if a["account_id"] == aid)["status"] = "enabled"
            planted["terminated_enabled_accounts"].append(aid)
planted["terminated_enabled_accounts"] = planted["terminated_enabled_accounts"][:6]
for a in accounts:  # re-disable anything beyond the 6 we keep
    if a["employee_id"] in {m["employee_id"] for m in missed} and a["account_id"] not in planted["terminated_enabled_accounts"]:
        a["status"] = "disabled"

# 4. Dormant accounts for active employees (5 stale + 2 never used)
dormant_stale = [ensure_account(pick(random.choice(["Operations", "Sales", "Finance"])), "VPN") for _ in range(5)]
dormant_never = []
for _ in range(2):
    eid = pick("Operations")
    while "ERP" in emp_accounts[eid]:   # needs someone who doesn't already have ERP access
        eid = pick("Operations")
    aid = add_account("ERP", emp_username(eid), eid, date(2026, 8, 14))
    grant(aid, "ERP_READ", date(2026, 8, 14))
    emp_accounts[eid]["ERP_EXTRA"] = aid
    dormant_never.append(aid)
planted["dormant_accounts"] = dormant_stale + dormant_never

# 5. Orphaned accounts: user accounts with no matching employee (3)
for sysid, u, emp in [("CRM", "jmorris_old", None), ("ERP", "contractor07", 9999), ("VPN", "vendor_access", None)]:
    aid = add_account(sysid, u, emp, date(2024, random.randint(1, 12), 10))
    grant(aid, {"CRM": "CRM_USER", "ERP": "ERP_READ", "VPN": "VPN_USER"}[sysid], date(2024, 6, 1))
    planted["orphaned_accounts"].append(aid)
    normal_logins(aid, [f"172.16.{random.randint(1, 250)}.{random.randint(2, 250)}"], date(2026, 5, 1), date(2026, 9, 30), recent=False)

# 6. Shared / generic accounts owned by a real person (2)
ops_mgr = by_dept["Operations"][0]
shared = add_account("AD", "shared_ops", ops_mgr, date(2023, 3, 1))
grant(shared, "AD_USER", date(2023, 3, 1))
test_acct = add_account("ERP", "test_user1", it_staff[2], date(2025, 11, 3))
grant(test_acct, "ERP_READ", date(2025, 11, 3))
grant(test_acct, "ERP_INVOICE_ENTER", date(2025, 11, 3))
planted["generic_accounts"] = [shared, test_acct]
normal_logins(shared, [f"10.20.40.{n}" for n in range(101, 110)], PERIOD_START, AUDIT_DATE)
normal_logins(test_acct, ["10.20.10.15", "10.20.10.16"], PERIOD_START, AUDIT_DATE)

# 7. Service accounts (legitimate, no human owner, run at night)
for sysid, u, role in [("AD", "svc_backup", "AD_USER"), ("ERP", "svc_erp_integration", "ERP_READ"), ("PAYROLL", "svc_payroll_export", "PAY_VIEW")]:
    aid = add_account(sysid, u, None, date(2022, 1, 10), acct_type="service")
    grant(aid, role, date(2022, 1, 10))
    day = PERIOD_START
    while day <= AUDIT_DATE:
        login(aid, datetime(day.year, day.month, day.day, 2, random.randint(0, 9), 0), "10.20.99.5")
        day += timedelta(days=1)

# ------------------------------------------------------------------ normal login history
special = set(planted["terminated_enabled_accounts"] + planted["dormant_accounts"] + planted["orphaned_accounts"]
              + planted["generic_accounts"])
for e in employees:
    eid = e["employee_id"]
    d_oct = DEPT_OCTET[e["department"]]
    ips = [f"10.20.{d_oct}.{random.randint(20, 250)}"] + ([f"172.16.{d_oct}.{random.randint(2, 250)}"] if random.random() < 0.5 else [])
    hire = date.fromisoformat(e["hire_date"])
    term = date.fromisoformat(e["termination_date"]) if e["termination_date"] else None
    for key, aid in emp_accounts[eid].items():
        if aid in special and aid not in planted["terminated_enabled_accounts"]:
            if aid in dormant_stale:   # last activity in early summer, nothing since
                normal_logins(aid, ips, max(hire, PERIOD_START), date(2026, random.randint(6, 7), random.randint(1, 25)), recent=False)
            continue   # never-used accounts get no logins
        end = (term - timedelta(days=random.randint(1, 5))) if term else AUDIT_DATE
        normal_logins(aid, ips, hire, end, recent=not term)

# 8. Logins after termination (2 of the missed leavers' accounts)
post = []
for aid in planted["terminated_enabled_accounts"]:
    a = next(x for x in accounts if x["account_id"] == aid)
    if a["system_id"] in ("VPN", "AD") and len(post) < 2 and a["employee_id"] not in [p[1] for p in post]:
        post.append((aid, a["employee_id"]))
for aid, eid in post:
    term = date.fromisoformat(E[eid]["termination_date"])
    for k in range(random.randint(2, 4)):
        dd = weekday_on_or_before(min(AUDIT_DATE, term + timedelta(days=3 + 4 * k)))
        if dd <= term:
            dd = term + timedelta(days=1)
        login(aid, business_time(dd), f"203.0.113.{random.randint(10, 200)}")   # external, documentation range
    planted["post_termination_login_accounts"].append(aid)

# 9. Privileged logins at odd hours (2 admin accounts)
odd = [emp_accounts[sysadmins[0]]["AD"], ops_admin_acct]
for aid in odd:
    for _ in range(random.randint(3, 5)):
        day = rand_date(date(2026, 6, 1), date(2026, 10, 25))
        if random.random() < 0.5:   # weekend
            while day.weekday() < 5:
                day += timedelta(days=1)
            ts = datetime(day.year, day.month, day.day, random.randint(10, 22), random.randint(0, 59))
        else:                       # middle of the night
            ts = datetime(day.year, day.month, day.day, random.randint(0, 4), random.randint(0, 59))
        login(aid, ts, "172.16.10.77")
planted["off_hours_privileged_accounts"] = odd


# ------------------------------------------------------------------ write SQL
def lit(v):
    if v is None:
        return "NULL"
    if isinstance(v, int):
        return str(v)
    return "'" + str(v).replace("'", "''") + "'"


def inserts(table, rows, cols):
    out = []
    for i in range(0, len(rows), 500):
        chunk = rows[i:i + 500]
        out.append(f"INSERT INTO {table} ({', '.join(cols)}) VALUES\n" +
                   ",\n".join("(" + ", ".join(lit(r[c]) for c in cols) + ")" for r in chunk) + ";")
    return "\n".join(out)


logins.sort(key=lambda r: (r["login_time"], r["account_id"]))
for i, r in enumerate(logins, 1):
    r["event_id"] = i

sql = ["-- Generated by scripts/generate_data.py. Fictional data: Ridgeline Logistics.", "BEGIN;",
       inserts("employees", employees, ["employee_id", "first_name", "last_name", "department", "job_title",
                                        "manager_id", "hire_date", "termination_date"]),
       inserts("systems", [dict(system_id=s[0], system_name=s[1], criticality=s[2]) for s in SYSTEMS],
               ["system_id", "system_name", "criticality"]),
       inserts("accounts", accounts, ["account_id", "system_id", "username", "employee_id", "account_type", "status", "created_date"]),
       inserts("roles", [dict(role_id=r[0], system_id=r[1], role_name=r[2], privileged=r[3]) for r in ROLES],
               ["role_id", "system_id", "role_name", "privileged"]),
       inserts("account_roles", account_roles, ["account_id", "role_id", "granted_date"]),
       inserts("sod_rules", [dict(rule_id=r[0], role_a=r[1], role_b=r[2], description=r[3]) for r in SOD_RULES],
               ["rule_id", "role_a", "role_b", "description"]),
       inserts("login_events", logins, ["event_id", "account_id", "login_time", "source_ip", "success"]),
       "COMMIT;"]
(ROOT / "data" / "seed.sql").write_text("\n".join(sql) + "\n")
(ROOT / "data" / "planted_issues.json").write_text(json.dumps(planted, indent=2) + "\n")
print(f"employees={len(employees)} accounts={len(accounts)} role_grants={len(account_roles)} logins={len(logins)}")
