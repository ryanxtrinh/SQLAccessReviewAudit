-- =====================================================================
-- IT Access Review Audit - database schema
-- Fictional company: Ridgeline Logistics (all data is generated)
--
-- Audit as-of date: 2026-10-31 (the end of the review period)
-- =====================================================================

PRAGMA foreign_keys = ON;

DROP TABLE IF EXISTS login_events;
DROP TABLE IF EXISTS account_roles;
DROP TABLE IF EXISTS sod_rules;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS systems;
DROP TABLE IF EXISTS employees;

-- HR system of record. termination_date IS NULL means still employed.
CREATE TABLE employees (
    employee_id      INTEGER PRIMARY KEY,
    first_name       TEXT    NOT NULL,
    last_name        TEXT    NOT NULL,
    department       TEXT    NOT NULL,   -- IT, Finance, HR, Operations, Sales
    job_title        TEXT    NOT NULL,
    manager_id       INTEGER REFERENCES employees(employee_id),
    hire_date        TEXT    NOT NULL,   -- ISO date YYYY-MM-DD
    termination_date TEXT                -- NULL = active employee
);

-- Applications in scope for the review.
CREATE TABLE systems (
    system_id   TEXT PRIMARY KEY,        -- AD, ERP, PAYROLL, CRM, VPN
    system_name TEXT NOT NULL,
    criticality TEXT NOT NULL CHECK (criticality IN ('High','Medium','Low'))
);

-- User accounts in each system. employee_id links an account to a person;
-- service accounts are expected to have no employee.
CREATE TABLE accounts (
    account_id   INTEGER PRIMARY KEY,
    system_id    TEXT    NOT NULL REFERENCES systems(system_id),
    username     TEXT    NOT NULL,
    employee_id  INTEGER,                -- deliberately no FK: orphaned accounts are an audit test
    account_type TEXT    NOT NULL CHECK (account_type IN ('user','service')),
    status       TEXT    NOT NULL CHECK (status IN ('enabled','disabled')),
    created_date TEXT    NOT NULL,
    UNIQUE (system_id, username)
);

-- Permissions that can be granted in each system.
CREATE TABLE roles (
    role_id     TEXT PRIMARY KEY,        -- e.g. ERP_VENDOR_CREATE
    system_id   TEXT NOT NULL REFERENCES systems(system_id),
    role_name   TEXT NOT NULL,
    privileged  INTEGER NOT NULL CHECK (privileged IN (0,1))   -- 1 = admin-level
);

-- Which account holds which role.
CREATE TABLE account_roles (
    account_id   INTEGER NOT NULL REFERENCES accounts(account_id),
    role_id      TEXT    NOT NULL REFERENCES roles(role_id),
    granted_date TEXT    NOT NULL,
    PRIMARY KEY (account_id, role_id)
);

-- Segregation-of-duties policy: no single PERSON may hold both roles.
CREATE TABLE sod_rules (
    rule_id     TEXT PRIMARY KEY,
    role_a      TEXT NOT NULL REFERENCES roles(role_id),
    role_b      TEXT NOT NULL REFERENCES roles(role_id),
    description TEXT NOT NULL
);

-- Authentication log for the review period.
CREATE TABLE login_events (
    event_id   INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(account_id),
    login_time TEXT    NOT NULL,         -- ISO datetime, company local time
    source_ip  TEXT    NOT NULL,
    success    INTEGER NOT NULL CHECK (success IN (0,1))
);

CREATE INDEX idx_login_account ON login_events(account_id, login_time);
CREATE INDEX idx_accounts_emp  ON accounts(employee_id);
