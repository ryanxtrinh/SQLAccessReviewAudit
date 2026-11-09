# IT Access Review Audit Report

**Entity:** Ridgeline Logistics *(fictional company, generated data)*  
**Review period:** 2026-05-01 to 2026-10-31  
**Report generated:** 2026-11-09  
**Framework:** NIST CSF 2.0 (Identity Management & Access Control) and ISO/IEC 27001:2022 Annex A

## 1. Scope
- **Systems:** Active Directory, Customer CRM, ERP Financials, Payroll System, Remote Access VPN
- **Population:** 180 employees (14 who left the company in 2026), 479 accounts (449 enabled), 515 role assignments, 17,063 login events
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
| 151 | Nina Bell | Sales | 2026-04-07 | AD | nbell | 207 |
| 151 | Nina Bell | Sales | 2026-04-07 | VPN | nbell | 207 |
| 84 | Aisha Adams | Operations | 2026-07-09 | AD | aadams | 114 |
| 84 | Aisha Adams | Operations | 2026-07-09 | VPN | aadams | 114 |
| 44 | Maria Cook | Finance | 2026-08-22 | AD | mcook | 70 |
| 44 | Maria Cook | Finance | 2026-08-22 | VPN | mcook | 70 |

**Criteria:** All system access is disabled on or before an employee's termination date.

**Risk:** A former employee (or anyone who has their password) can still get into company systems, including from outside the network.

**Recommendation:** Disable the listed accounts now. Automate deprovisioning from the HR termination event and reconcile HR terminations against enabled accounts every week.

**Framework:** NIST CSF PR.AA-01 · ISO 27001 A.5.18 Access rights; A.6.5 Responsibilities after termination  
**Test query:** [`sql/tests/01_terminated_users_active.sql`](../sql/tests/01_terminated_users_active.sql)

### AR-02: Successful logins after termination  (High risk)

**Condition:** 2 exception(s) found. The full list is in `output/findings/AR-02.csv`.

| employee | termination_date | system_id | username | logins_after_termination | first_login_after | last_login_after | source_ips |
|---|---|---|---|---|---|---|---|
| Aisha Adams | 2026-07-09 | AD | aadams | 2 | 2026-07-10 15:07:58 | 2026-07-16 17:14:55 | 203.0.113.119,203.0.113.120 |
| Maria Cook | 2026-08-22 | AD | mcook | 2 | 2026-08-25 09:33:19 | 2026-08-28 12:01:02 | 203.0.113.56,203.0.113.41 |

**Criteria:** No account is used after its owner's employment ends.

**Risk:** Access that was not removed was actually used. This is a potential security incident (data theft, sabotage) rather than just a control gap.

**Recommendation:** Escalate to the security team to investigate what each session did. Disable the accounts and preserve the logs as evidence.

**Framework:** NIST CSF DE.CM-03 · ISO 27001 A.6.5 Responsibilities after termination; A.8.16 Monitoring activities  
**Test query:** [`sql/tests/02_logins_after_termination.sql`](../sql/tests/02_logins_after_termination.sql)

### AR-03: Segregation-of-duties conflicts  (High risk)

**Condition:** 4 exception(s) found. The full list is in `output/findings/AR-03.csv`.

| rule_id | employee | department | job_title | role_a | role_b | description |
|---|---|---|---|---|---|---|
| SOD-01 | Olivia Murphy | Finance | Procurement Specialist | ERP_VENDOR_CREATE | ERP_PAYMENT_APPROVE | Creating vendors and approving payments lets one person pay a fake vendor |
| SOD-02 | Olivia Miller | Finance | Accounts Payable Clerk | ERP_INVOICE_ENTER | ERP_PAYMENT_RELEASE | Entering invoices and releasing payment runs lets one person pay their own invoice |
| SOD-03 | Victor Walker | HR | Payroll Specialist | PAY_EDIT | PAY_APPROVE | Editing pay rates and approving payroll lets one person raise their own pay |
| SOD-04 | Gavin Rogers | IT | Systems Administrator | IAM_USER_CREATE | IAM_ACCESS_APPROVE | Creating accounts and approving access lets one person grant themselves any access |

**Criteria:** No single person holds both roles in any segregation-of-duties (SoD) rule.

**Risk:** One person can complete a sensitive process end to end with no one checking, e.g. create a fake vendor and approve payment to it.

**Recommendation:** Remove one of the conflicting roles. If the business truly needs both, document a formal exception with a compensating control (e.g. monthly review of that person's transactions by their manager).

**Framework:** NIST CSF PR.AA-05 · ISO 27001 A.5.3 Segregation of duties  
**Test query:** [`sql/tests/03_sod_conflicts.sql`](../sql/tests/03_sod_conflicts.sql)

### AR-05: Administrator access held outside IT  (High risk)

**Condition:** 3 exception(s) found. The full list is in `output/findings/AR-05.csv`.

| employee | department | job_title | system_id | username | role_name | granted_date |
|---|---|---|---|---|---|---|
| Brian Brooks | Finance | Financial Analyst | ERP | bbrooks | ERP System Administrator | 2026-05-08 |
| Robert Bennett | Sales | Account Executive | CRM | rbennett | CRM Administrator | 2026-05-08 |
| Noah Howard | Operations | Logistics Coordinator | AD | nhoward | Domain Administrator | 2026-04-14 |

**Criteria:** Privileged (administrator) roles are held only by IT staff whose job requires them.

**Risk:** Admin rights let a user change security settings, create accounts and bypass controls. Outside IT this is rarely justified and greatly increases the damage a compromised account can do.

**Recommendation:** Remove the admin role, or obtain written justification from the system owner and add the account to quarterly privileged-access reviews.

**Framework:** NIST CSF PR.AA-05 · ISO 27001 A.8.2 Privileged access rights  
**Test query:** [`sql/tests/05_privileged_access_outside_it.sql`](../sql/tests/05_privileged_access_outside_it.sql)

### AR-04: Dormant accounts  (Medium risk)

**Condition:** 7 exception(s) found. The full list is in `output/findings/AR-04.csv`.

| employee | department | system_id | username | created_date | last_successful_login | days_inactive |
|---|---|---|---|---|---|---|
| Brian Collins | Operations | VPN | bcollins | 2022-10-30 | 2026-06-12 13:43:47 | 140 |
| Patrick Morris | Sales | VPN | pmorris | 2015-04-11 | 2026-06-12 11:23:38 | 140 |
| Yuna Wright | Sales | VPN | ywright | 2024-08-19 | 2026-06-12 08:26:24 | 140 |
| Maria Morris | Sales | VPN | mmorris | 2020-09-14 | 2026-07-10 11:38:34 | 112 |
| Noah King | Finance | VPN | nking | 2017-12-14 | 2026-07-17 17:56:59 | 105 |
| Grace Ward | Operations | ERP | gward2 | 2026-08-14 | never | 78 |
| Victor Phillips | Operations | ERP | vphillips | 2026-08-14 | never | 78 |

**Criteria:** Enabled user accounts with no successful login in 90 days (or never used, 30+ days after creation) are disabled.

**Risk:** Unused accounts are ideal targets: nobody notices when an attacker starts using them. They also show access was granted that isn't needed.

**Recommendation:** Confirm with each manager whether the access is still needed; disable the rest. Add automatic disablement after 90 days of inactivity.

**Framework:** NIST CSF PR.AA-01 · ISO 27001 A.5.18 Access rights  
**Test query:** [`sql/tests/04_dormant_accounts.sql`](../sql/tests/04_dormant_accounts.sql)

### AR-06: Orphaned accounts with no owner  (Medium risk)

**Condition:** 3 exception(s) found. The full list is in `output/findings/AR-06.csv`.

| system_id | username | employee_id_on_account | created_date | last_successful_login |
|---|---|---|---|---|
| CRM | jmorris_old |  | 2024-03-10 | 2026-09-28 13:30:18 |
| ERP | contractor07 | 9999 | 2024-03-10 | 2026-09-25 16:16:20 |
| VPN | vendor_access |  | 2024-10-10 | 2026-09-29 11:51:51 |

**Criteria:** Every enabled user account maps to a current or former employee in the HR system.

**Risk:** Nobody is accountable for an account without an owner. Leftover contractor and vendor accounts are a common way into a network.

**Recommendation:** Identify an owner for each account or disable it. Require an employee or contractor record before any account can be created.

**Framework:** NIST CSF PR.AA-01 · ISO 27001 A.5.16 Identity management  
**Test query:** [`sql/tests/06_orphaned_accounts.sql`](../sql/tests/06_orphaned_accounts.sql)

### AR-07: Shared or generic accounts  (Medium risk)

**Condition:** 2 exception(s) found. The full list is in `output/findings/AR-07.csv`.

| system_id | username | recorded_owner | distinct_source_ips | successful_logins | reason |
|---|---|---|---|---|---|
| AD | shared_ops | Aisha Kelly | 9 | 34 | Generic name + used from many machines |
| ERP | test_user1 | Owen Kelly | 2 | 35 | Generic name |

**Criteria:** User accounts are assigned to one named individual. Generic names (test, shared, temp, admin, guest) are not used for user accounts.

**Risk:** When several people share one login, actions can't be traced to a person, so audit logs lose their value. Test accounts often keep powerful roles long after testing ends.

**Recommendation:** Replace shared accounts with individual accounts, and remove test accounts from production systems.

**Framework:** NIST CSF PR.AA-01 · ISO 27001 A.5.16 Identity management; A.5.17 Authentication information  
**Test query:** [`sql/tests/07_shared_generic_accounts.sql`](../sql/tests/07_shared_generic_accounts.sql)

### AR-08: Privileged logins outside business hours  (Medium risk)

**Condition:** 2 exception(s) found. The full list is in `output/findings/AR-08.csv`.

| system_id | username | employee | department | off_hours_logins | weekend | overnight | first_seen | last_seen |
|---|---|---|---|---|---|---|---|---|
| AD | gward | Gavin Ward | IT | 4 | 3 | 1 | 2026-06-27 17:50:00 | 2026-08-01 10:28:00 |
| AD | nhoward | Noah Howard | Operations | 3 | 1 | 2 | 2026-07-18 11:29:00 | 2026-09-25 01:13:00 |

**Criteria:** Administrator activity happens during business hours (Mon-Fri, 06:00-20:00) or under a documented change window.

**Risk:** Attackers using stolen admin credentials often work at night or on weekends, when nobody is watching. Unexplained off-hours admin activity needs follow-up.

**Recommendation:** Ask each admin to match these sessions to approved change tickets. Investigate any session that can't be explained, and alert on off-hours privileged logins.

**Framework:** NIST CSF DE.CM-03 · ISO 27001 A.8.2 Privileged access rights; A.8.16 Monitoring activities  
**Test query:** [`sql/tests/08_off_hours_privileged_logins.sql`](../sql/tests/08_off_hours_privileged_logins.sql)

## 4. Limitations
- Point-in-time review of exported data; changes made after the export are not reflected.
- Login data covers the review period only, so dormancy is measured within that window.
- Exceptions are leads for follow-up with system owners. Some (e.g. an approved change window for off-hours admin work) may turn out to be justified, and would then be documented as accepted exceptions.
