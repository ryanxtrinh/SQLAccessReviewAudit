-- @id: AR-05
-- @title: Administrator access held outside IT
-- @severity: High
-- @criteria: Privileged (administrator) roles are held only by IT staff whose job requires them.
-- @risk: Admin rights let a user change security settings, create accounts and bypass controls. Outside IT this is rarely justified and greatly increases the damage a compromised account can do.
-- @recommendation: Remove the admin role, or obtain written justification from the system owner and add the account to quarterly privileged-access reviews.
-- @nist: PR.AA-05
-- @iso: A.8.2 Privileged access rights

SELECT
    e.first_name || ' ' || e.last_name AS employee,
    e.department,
    e.job_title,
    a.system_id,
    a.username,
    r.role_name,
    ar.granted_date
FROM account_roles ar
JOIN roles     r ON r.role_id     = ar.role_id
JOIN accounts  a ON a.account_id  = ar.account_id
JOIN employees e ON e.employee_id = a.employee_id
WHERE r.privileged = 1
  AND a.status = 'enabled'
  AND e.department <> 'IT'
ORDER BY ar.granted_date DESC;

-- Context: share of each department's people holding any admin role
-- (window function; run separately for the summary in the report)
-- SELECT department, admins, headcount,
--        ROUND(100.0 * admins / headcount, 1) AS pct_admin
-- FROM (
--   SELECT e.department,
--          COUNT(DISTINCT CASE WHEN r.privileged = 1 THEN e.employee_id END) AS admins,
--          COUNT(DISTINCT e.employee_id) AS headcount
--   FROM employees e
--   LEFT JOIN accounts a       ON a.employee_id = e.employee_id AND a.status = 'enabled'
--   LEFT JOIN account_roles ar ON ar.account_id = a.account_id
--   LEFT JOIN roles r          ON r.role_id = ar.role_id
--   WHERE e.termination_date IS NULL
--   GROUP BY e.department);
