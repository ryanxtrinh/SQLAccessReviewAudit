-- @id: AR-06
-- @title: Orphaned accounts with no owner
-- @severity: Medium
-- @criteria: Every enabled user account maps to a current or former employee in the HR system.
-- @risk: Nobody is accountable for an account without an owner. Leftover contractor and vendor accounts are a common way into a network.
-- @recommendation: Identify an owner for each account or disable it. Require an employee or contractor record before any account can be created.
-- @nist: PR.AA-01
-- @iso: A.5.16 Identity management

-- LEFT JOIN + IS NULL finds rows with no match, which covers both a blank
-- employee_id and an employee_id that doesn't exist in HR.
SELECT
    a.system_id,
    a.username,
    a.employee_id     AS employee_id_on_account,
    a.created_date,
    (SELECT MAX(l.login_time) FROM login_events l
      WHERE l.account_id = a.account_id AND l.success = 1) AS last_successful_login
FROM accounts a
LEFT JOIN employees e ON e.employee_id = a.employee_id
WHERE a.account_type = 'user'   -- service accounts legitimately have no employee
  AND a.status = 'enabled'
  AND e.employee_id IS NULL
ORDER BY a.system_id, a.username;
