-- @id: AR-03
-- @title: Segregation-of-duties conflicts
-- @severity: High
-- @criteria: No single person holds both roles in any segregation-of-duties (SoD) rule.
-- @risk: One person can complete a sensitive process end to end with no one checking, e.g. create a fake vendor and approve payment to it.
-- @recommendation: Remove one of the conflicting roles. If the business truly needs both, document a formal exception with a compensating control (e.g. monthly review of that person's transactions by their manager).
-- @nist: PR.AA-05
-- @iso: A.5.3 Segregation of duties

-- Roles are granted to accounts, but SoD applies to PEOPLE. A person could hold
-- one role in one system and the other in a different system, so we resolve
-- every grant to its employee first.
WITH person_roles AS (
    SELECT DISTINCT a.employee_id, ar.role_id
    FROM account_roles ar
    JOIN accounts a ON a.account_id = ar.account_id
    WHERE a.status = 'enabled'
      AND a.employee_id IS NOT NULL
)
SELECT
    s.rule_id,
    e.first_name || ' ' || e.last_name AS employee,
    e.department,
    e.job_title,
    s.role_a,
    s.role_b,
    s.description
FROM sod_rules s
JOIN person_roles pa ON pa.role_id = s.role_a
JOIN person_roles pb ON pb.role_id = s.role_b
                    AND pb.employee_id = pa.employee_id   -- same person holds both
JOIN employees e     ON e.employee_id  = pa.employee_id
ORDER BY s.rule_id, employee;
