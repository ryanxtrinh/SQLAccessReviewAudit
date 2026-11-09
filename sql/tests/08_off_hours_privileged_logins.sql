-- @id: AR-08
-- @title: Privileged logins outside business hours
-- @severity: Medium
-- @criteria: Administrator activity happens during business hours (Mon-Fri, 06:00-20:00) or under a documented change window.
-- @risk: Attackers using stolen admin credentials often work at night or on weekends, when nobody is watching. Unexplained off-hours admin activity needs follow-up.
-- @recommendation: Ask each admin to match these sessions to approved change tickets. Investigate any session that can't be explained, and alert on off-hours privileged logins.
-- @nist: DE.CM-03
-- @iso: A.8.2 Privileged access rights; A.8.16 Monitoring activities

-- SQLite's strftime('%w') returns 0 = Sunday ... 6 = Saturday.
WITH privileged_accounts AS (
    SELECT DISTINCT ar.account_id
    FROM account_roles ar
    JOIN roles r ON r.role_id = ar.role_id
    WHERE r.privileged = 1
),
off_hours AS (
    SELECT l.*,
           CASE WHEN strftime('%w', l.login_time) IN ('0','6') THEN 'Weekend' ELSE 'Overnight' END AS window
    FROM login_events l
    JOIN privileged_accounts p ON p.account_id = l.account_id
    WHERE l.success = 1
      AND (
            strftime('%w', l.login_time) IN ('0','6')
         OR CAST(strftime('%H', l.login_time) AS INTEGER) < 6
         OR CAST(strftime('%H', l.login_time) AS INTEGER) >= 20
      )
)
SELECT
    a.system_id,
    a.username,
    e.first_name || ' ' || e.last_name     AS employee,
    e.department,
    COUNT(*)                               AS off_hours_logins,
    SUM(o.window = 'Weekend')              AS weekend,
    SUM(o.window = 'Overnight')            AS overnight,
    MIN(o.login_time)                      AS first_seen,
    MAX(o.login_time)                      AS last_seen
FROM off_hours o
JOIN accounts  a ON a.account_id  = o.account_id
JOIN employees e ON e.employee_id = a.employee_id   -- service accounts (no employee) are expected to run at night
WHERE a.account_type = 'user'
GROUP BY a.account_id
ORDER BY off_hours_logins DESC;
