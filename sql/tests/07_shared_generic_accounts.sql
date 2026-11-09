-- @id: AR-07
-- @title: Shared or generic accounts
-- @severity: Medium
-- @criteria: User accounts are assigned to one named individual. Generic names (test, shared, temp, admin, guest) are not used for user accounts.
-- @risk: When several people share one login, actions can't be traced to a person, so audit logs lose their value. Test accounts often keep powerful roles long after testing ends.
-- @recommendation: Replace shared accounts with individual accounts, and remove test accounts from production systems.
-- @nist: PR.AA-01
-- @iso: A.5.16 Identity management; A.5.17 Authentication information

-- Two signals: a generic-looking name, OR a single account used from many
-- different machines (normal users here use one or two).
WITH usage AS (
    SELECT account_id,
           COUNT(DISTINCT source_ip) AS distinct_ips,
           COUNT(*)                  AS logins
    FROM login_events
    WHERE success = 1
    GROUP BY account_id
)
SELECT
    a.system_id,
    a.username,
    e.first_name || ' ' || e.last_name AS recorded_owner,
    COALESCE(u.distinct_ips, 0)        AS distinct_source_ips,
    COALESCE(u.logins, 0)              AS successful_logins,
    CASE
      WHEN a.username LIKE 'shared%' OR a.username LIKE 'test%' OR a.username LIKE 'temp%'
        OR a.username LIKE 'admin%'  OR a.username LIKE 'guest%' OR a.username LIKE 'training%'
      THEN 'Generic name' ELSE '' END ||
    CASE WHEN COALESCE(u.distinct_ips, 0) >= 5 THEN ' + used from many machines' ELSE '' END
                                       AS reason
FROM accounts a
LEFT JOIN employees e ON e.employee_id = a.employee_id
LEFT JOIN usage u     ON u.account_id  = a.account_id
WHERE a.account_type = 'user'
  AND a.status = 'enabled'
  AND (
        a.username LIKE 'shared%' OR a.username LIKE 'test%' OR a.username LIKE 'temp%'
     OR a.username LIKE 'admin%'  OR a.username LIKE 'guest%' OR a.username LIKE 'training%'
     OR COALESCE(u.distinct_ips, 0) >= 5
  )
ORDER BY distinct_source_ips DESC;
