-- @id: AR-02
-- @title: Successful logins after termination
-- @severity: High
-- @criteria: No account is used after its owner's employment ends.
-- @risk: Access that was not removed was actually used. This is a potential security incident (data theft, sabotage) rather than just a control gap.
-- @recommendation: Escalate to the security team to investigate what each session did. Disable the accounts and preserve the logs as evidence.
-- @nist: DE.CM-03
-- @iso: A.6.5 Responsibilities after termination; A.8.16 Monitoring activities

SELECT
    e.first_name || ' ' || e.last_name  AS employee,
    e.termination_date,
    a.system_id,
    a.username,
    COUNT(*)                            AS logins_after_termination,
    MIN(l.login_time)                   AS first_login_after,
    MAX(l.login_time)                   AS last_login_after,
    GROUP_CONCAT(DISTINCT l.source_ip)  AS source_ips
FROM login_events l
JOIN accounts  a ON a.account_id  = l.account_id
JOIN employees e ON e.employee_id = a.employee_id
WHERE e.termination_date IS NOT NULL
  AND l.success = 1
  AND date(l.login_time) > e.termination_date
GROUP BY a.account_id
ORDER BY logins_after_termination DESC;
