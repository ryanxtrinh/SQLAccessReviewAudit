-- @id: AR-01
-- @title: Terminated employees still have enabled accounts
-- @severity: High
-- @criteria: All system access is disabled on or before an employee's termination date.
-- @risk: A former employee (or anyone who has their password) can still get into company systems, including from outside the network.
-- @recommendation: Disable the listed accounts now. Automate deprovisioning from the HR termination event and reconcile HR terminations against enabled accounts every week.
-- @nist: PR.AA-01
-- @iso: A.5.18 Access rights; A.6.5 Responsibilities after termination

SELECT
    e.employee_id,
    e.first_name || ' ' || e.last_name               AS employee,
    e.department,
    e.termination_date,
    a.system_id,
    a.username,
    CAST(julianday('2026-10-31') - julianday(e.termination_date) AS INTEGER)
                                                     AS days_since_termination
FROM accounts  a
JOIN employees e ON e.employee_id = a.employee_id
WHERE e.termination_date IS NOT NULL
  AND e.termination_date <= '2026-10-31'
  AND a.status = 'enabled'
ORDER BY days_since_termination DESC, e.employee_id, a.system_id;
