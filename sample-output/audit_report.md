# IT Access Review Audit Report

**Entity:** Ridgeline Logistics *(fictional company, generated data)*  
**Review period:** 2026-05-01 to 2026-10-31  
**Report generated:** 2026-11-09  
**Framework:** NIST CSF 2.0 (Identity Management & Access Control) and ISO/IEC 27001:2022 Annex A

## 1. Scope
- **Systems:** Active Directory, Customer CRM, ERP Financials, Payroll System, Remote Access VPN
- **Population:** 180 employees (14 who left the company in 2026), 479 accounts (446 enabled), 523 role assignments, 17,345 login events
- **Approach:** 100% of the population was tested with SQL queries (no sampling). Each test compares system access data against HR records and the company's access policies.

## 2. Executive Summary

8 access controls were tested. **8 had exceptions**, including **4 high-risk** findings. The most serious issue is that access was not removed when employees left, and in some cases those accounts were used after termination. That should be treated as a possible security incident, not only a control gap.

| ID | Control tested | Risk | Exceptions | Result |
|---|---|---|---|---|
| AR-01 | Terminated employees still have enabled accounts | High | 6 | Exception |
| AR-02 | Successful logins after termination | High | 2 | Exception |
| AR-03 | Segregation-of-duties conflicts | High | 4 | Exception |
| AR-04 | Dormant accounts | Medium | 7 | Exception |
| AR-05 | Administrator access held outside IT | High | 3 | Exception |
| AR-06 | Orphaned accounts with no owner | Medium | 3 | Exception |
| AR-07 | Shared or generic accounts | Medium | 2 | Exception |
| AR-08 | Privileged logins outside business hours | Medium | 2 | Exception |

## 3. Detailed Findings

### AR-01: Terminated employees still have enabled accounts  (High risk)

**Condition:** 6 exception(s) found. The full list is in `output/findings/AR-01.csv`.

| employee_id | employee | department | termination_date | system_id | username | days_since_termination |
|---|---|---|---|---|---|---|
| 64 | Bianca Wood | HR | 2026-05-14 | AD | bwood | 170 |
| 64 | Bianca Wood | HR | 2026-05-14 | VPN | bwood | 170 |
| 8 | Carlos Miller | IT | 2026-05-25 | AD | cmiller | 159 |
| 8 | Carlos Miller | IT | 2026-05-25 | VPN | cmiller | 159 |
| 166 | Michael Ward | Sales | 2026-10-14 | AD | mward | 17 |
| 166 | Michael Ward | Sales | 2026-10-14 | VPN | mward | 17 |

**Criteria:** All system access is disabled on or before an employee's termination date.

**Risk:** A former employee (or anyone who has their password) can still get into company systems, including from outside the network.

**Recommendation:** Disable the listed accounts now. Automate deprovisioning from the HR termination event and reconcile HR terminations against enabled accounts every week.

**Framework:** NIST CSF PR.AA-01 · ISO 27001 A.5.18 Access rights; A.6.5 Responsibilities after termination  
**Test query:** [`sql/tests/01_terminated_users_active.sql`](../sql/tests/01_terminated_users_active.sql)

### AR-02: Successful logins after termination  (High risk)

**Condition:** 2 exception(s) found. The full list is in `output/findings/AR-02.csv`.

| employee | termination_date | system_id | username | logins_after_termination | first_login_after | last_login_after | source_ips |
|---|---|---|---|---|---|---|---|
| Michael Ward | 2026-10-14 | AD | mward | 3 | 2026-10-16 07:26:53 | 2026-10-23 11:32:08 | 203.0.113.83 |
| Carlos Miller | 2026-05-25 | AD | cmiller | 3 | 2026-05-28 13:50:23 | 2026-06-05 07:54:24 | 203.0.113.52 |

**Criteria:** No account is used after its owner's employment ends.

**Risk:** Access that was not removed was actually used. This is a potential security incident (data theft, sabotage) rather than just a control gap.

**Recommendation:** Escalate to the security team to investigate what each session did. Disable the accounts and preserve the logs as evidence.

**Framework:** NIST CSF DE.CM-03 · ISO 27001 A.6.5 Responsibilities after termination; A.8.16 Monitoring activities  
**Test query:** [`sql/tests/02_logins_after_termination.sql`](../sql/tests/02_logins_after_termination.sql)

### AR-03: Segregation-of-duties conflicts  (High risk)

**Condition:** 4 exception(s) found. The full list is in `output/findings/AR-03.csv`.

| rule_id | employee | department | job_title | role_a | role_b | description |
|---|---|---|---|---|---|---|
| SOD-01 | James Wright | Finance | Procurement Specialist | ERP_VENDOR_CREATE | ERP_PAYMENT_APPROVE | Creating vendors and approving payments lets one person pay a fake vendor |
| SOD-02 | Grace Richardson | Finance | Accounts Payable Clerk | ERP_INVOICE_ENTER | ERP_PAYMENT_RELEASE | Entering invoices and releasing payment runs lets one person pay their own invoice |
| SOD-03 | Patrick Carter | HR | Payroll Specialist | PAY_EDIT | PAY_APPROVE | Editing pay rates and approving payroll lets one person raise their own pay |
| SOD-04 | David Richardson | IT | Help Desk Technician | IAM_USER_CREATE | IAM_ACCESS_APPROVE | Creating accounts and approving access lets one person grant themselves any access |

**Criteria:** No single person holds both roles in any segregation-of-duties (SoD) rule.

**Risk:** One person can complete a sensitive process end to end with no one checking, e.g. create a fake vendor and approve payment to it.

**Recommendation:** Remove one of the conflicting roles. If the business truly needs both, document a formal exception with a compensating control (e.g. monthly review of that person's transactions by their manager).

**Framework:** NIST CSF PR.AA-05 · ISO 27001 A.5.3 Segregation of duties  
**Test query:** [`sql/tests/03_sod_conflicts.sql`](../sql/tests/03_sod_conflicts.sql)

### AR-05: Administrator access held outside IT  (High risk)

**Condition:** 3 exception(s) found. The full list is in `output/findings/AR-05.csv`.

| employee | department | job_title | system_id | username | role_name | granted_date |
|---|---|---|---|---|---|---|
| Alicia Cox | Operations | Logistics Coordinator | AD | acox | Domain Administrator | 2026-05-01 |
| Omar Cox | Finance | AP Manager | ERP | ocox | ERP System Administrator | 2026-03-15 |
| Nina Carter | Sales | Customer Success Rep | CRM | ncarter | CRM Administrator | 2026-03-07 |

**Criteria:** Privileged (administrator) roles are held only by IT staff whose job requires them.

**Risk:** Admin rights let a user change security settings, create accounts and bypass controls. Outside IT this is rarely justified and greatly increases the damage a compromised account can do.

**Recommendation:** Remove the admin role, or obtain written justification from the system owner and add the account to quarterly privileged-access reviews.

**Framework:** NIST CSF PR.AA-05 · ISO 27001 A.8.2 Privileged access rights  
**Test query:** [`sql/tests/05_privileged_access_outside_it.sql`](../sql/tests/05_privileged_access_outside_it.sql)

### AR-04: Dormant accounts  (Medium risk)

**Condition:** 7 exception(s) found. The full list is in `output/findings/AR-04.csv`.

| employee | department | system_id | username | created_date | last_successful_login | days_inactive |
|---|---|---|---|---|---|---|
| Jada Morgan | Finance | VPN | jmorgan | 2021-02-13 | 2026-06-02 08:20:09 | 150 |
| Ethan Richardson | Operations | VPN | erichardson | 2025-12-20 | 2026-06-02 13:02:40 | 150 |
| Alicia Baker | Sales | VPN | abaker | 2023-08-29 | 2026-06-12 08:07:31 | 140 |
| Robert Miller | Finance | VPN | rmiller | 2021-01-07 | 2026-06-19 17:38:52 | 133 |
| Olivia Turner | Sales | VPN | oturner | 2017-07-03 | 2026-06-23 09:52:02 | 129 |
| Victor Kelly | Operations | ERP | vkelly | 2026-08-14 | never | 78 |
| James Cook | Operations | ERP | jcook | 2026-08-14 | never | 78 |

**Criteria:** Enabled user accounts with no successful login in 90 days (or never used, 30+ days after creation) are disabled.

**Risk:** Unused accounts are ideal targets: nobody notices when an attacker starts using them. They also show access was granted that isn't needed.

**Recommendation:** Confirm with each manager whether the access is still needed; disable the rest. Add automatic disablement after 90 days of inactivity.

**Framework:** NIST CSF PR.AA-01 · ISO 27001 A.5.18 Access rights  
**Test query:** [`sql/tests/04_dormant_accounts.sql`](../sql/tests/04_dormant_accounts.sql)

### AR-06: Orphaned accounts with no owner  (Medium risk)

**Condition:** 3 exception(s) found. The full list is in `output/findings/AR-06.csv`.

| system_id | username | employee_id_on_account | created_date | last_successful_login |
|---|---|---|---|---|
| CRM | jmorris_old |  | 2024-05-10 | 2026-09-29 17:55:55 |
| ERP | contractor07 | 9999 | 2024-03-10 | 2026-09-25 17:06:30 |
| VPN | vendor_access |  | 2024-10-10 | 2026-09-25 10:54:48 |

**Criteria:** Every enabled user account maps to a current or former employee in the HR system.

**Risk:** Nobody is accountable for an account without an owner. Leftover contractor and vendor accounts are a common way into a network.

**Recommendation:** Identify an owner for each account or disable it. Require an employee or contractor record before any account can be created.

**Framework:** NIST CSF PR.AA-01 · ISO 27001 A.5.16 Identity management  
**Test query:** [`sql/tests/06_orphaned_accounts.sql`](../sql/tests/06_orphaned_accounts.sql)

### AR-07: Shared or generic accounts  (Medium risk)

**Condition:** 2 exception(s) found. The full list is in `output/findings/AR-07.csv`.

| system_id | username | recorded_owner | distinct_source_ips | successful_logins | reason |
|---|---|---|---|---|---|
| AD | shared_ops | Maria Bailey | 8 | 36 | Generic name + used from many machines |
| ERP | test_user1 | Ethan Morgan | 2 | 38 | Generic name |

**Criteria:** User accounts are assigned to one named individual. Generic names (test, shared, temp, admin, guest) are not used for user accounts.

**Risk:** When several people share one login, actions can't be traced to a person, so audit logs lose their value. Test accounts often keep powerful roles long after testing ends.

**Recommendation:** Replace shared accounts with individual accounts, and remove test accounts from production systems.

**Framework:** NIST CSF PR.AA-01 · ISO 27001 A.5.16 Identity management; A.5.17 Authentication information  
**Test query:** [`sql/tests/07_shared_generic_accounts.sql`](../sql/tests/07_shared_generic_accounts.sql)

### AR-08: Privileged logins outside business hours  (Medium risk)

**Condition:** 2 exception(s) found. The full list is in `output/findings/AR-08.csv`.

| system_id | username | employee | department | off_hours_logins | weekend | overnight | first_seen | last_seen |
|---|---|---|---|---|---|---|---|---|
| AD | acox | Alicia Cox | Operations | 4 | 3 | 1 | 2026-06-20 10:30:00 | 2026-10-03 02:36:00 |
| AD | kgray | Kevin Gray | IT | 4 | 0 | 4 | 2026-06-08 00:11:00 | 2026-08-05 04:04:00 |

**Criteria:** Administrator activity happens during business hours (Mon-Fri, 06:00-20:00) or under a documented change window.

**Risk:** Attackers using stolen admin credentials often work at night or on weekends, when nobody is watching. Unexplained off-hours admin activity needs follow-up.

**Recommendation:** Ask each admin to match these sessions to approved change tickets. Investigate any session that can't be explained, and alert on off-hours privileged logins.

**Framework:** NIST CSF DE.CM-03 · ISO 27001 A.8.2 Privileged access rights; A.8.16 Monitoring activities  
**Test query:** [`sql/tests/08_off_hours_privileged_logins.sql`](../sql/tests/08_off_hours_privileged_logins.sql)

## 4. Limitations
- Point-in-time review of exported data; changes made after the export are not reflected.
- Login data covers the review period only, so dormancy is measured within that window.
- Exceptions are leads for follow-up with system owners. Some (e.g. an approved change window for off-hours admin work) may turn out to be justified, and would then be documented as accepted exceptions.
