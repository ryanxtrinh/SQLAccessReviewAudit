-- @id: AR-04
-- @title: Dormant accounts
-- @severity: Medium
-- @criteria: Enabled user accounts with no successful login in 90 days (or never used, 30+ days after creation) are disabled.
-- @risk: Unused accounts are ideal targets: nobody notices when an attacker starts using them. They also show access was granted that isn't needed.
-- @recommendation: Confirm with each manager whether the access is still needed; disable the rest. Add automatic disablement after 90 days of inactivity.
-- @nist: PR.AA-01
-- @iso: A.5.18 Access rights

-- Only current employees: terminated employees' accounts are already covered by AR-01.
WITH last_login AS (
    SELECT account_id, MAX(login_time) AS last_success
    FROM login_events
    WHERE success = 1
    GROUP BY account_id
)
SELECT
    e.first_name || ' ' || e.last_name  AS employee,
    e.department,
    a.system_id,
    a.username,
    a.created_date,
    COALESCE(ll.last_success, 'never')  AS last_successful_login,
    CAST(julianday('2026-10-31') - julianday(COALESCE(ll.last_success, a.created_date)) AS INTEGER)
                                        AS days_inactive
FROM accounts  a
JOIN employees e        ON e.employee_id = a.employee_id
LEFT JOIN last_login ll ON ll.account_id = a.account_id
WHERE a.status = 'enabled'
  AND a.account_type = 'user'
  AND e.termination_date IS NULL
  AND (
        ll.last_success < datetime('2026-10-31', '-90 days')
     OR (ll.last_success IS NULL AND a.created_date < date('2026-10-31', '-30 days'))
  )
ORDER BY days_inactive DESC;
