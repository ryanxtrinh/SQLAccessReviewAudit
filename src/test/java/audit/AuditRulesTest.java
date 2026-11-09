package audit;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Edge cases for each control, on tiny hand-built datasets. The audit as-of date is
 * 2026-10-31. Each test plants one thing that SHOULD be an exception next to
 * look-alikes that should NOT, so both misses and false positives are caught.
 */
class AuditRulesTest {

    @Test
    void ar01TerminatedUsersWithEnabledAccounts() throws Exception {
        try (TestDb db = new TestDb()) {
            db.employee(1, "Gone", "Sales", "2026-09-01").user(10, "AD", "gone", 1)
              .employee(2, "Cleaned", "Sales", "2026-09-01").account(20, "AD", "cleaned", 2, "user", "disabled", "2025-01-06")
              .employee(3, "Leaving", "Sales", "2026-11-15").user(30, "AD", "leaving", 3) // future-dated termination
              .employee(4, "Current", "Sales", null).user(40, "AD", "current", 4);
            assertEquals(Set.of("AD/gone"), db.run("AR-01"));
        }
    }

    @Test
    void ar02OnlySuccessfulLoginsAfterTerminationDayCount() throws Exception {
        try (TestDb db = new TestDb()) {
            db.employee(1, "A", "Sales", "2026-09-01").user(10, "VPN", "a", 1)
              .login(10, "2026-09-01 16:30:00", "10.0.0.1", true)   // last day at work: fine
              .login(10, "2026-09-03 21:00:00", "203.0.113.5", false); // failed attempt: not access
            assertTrue(db.run("AR-02").isEmpty());

            db.login(10, "2026-09-02 09:00:00", "203.0.113.5", true);
            assertEquals(Set.of("VPN/a"), db.run("AR-02"));
        }
    }

    @Test
    void ar03SodConflictAcrossTwoAccountsOfOnePerson() throws Exception {
        try (TestDb db = new TestDb()) {
            db.employee(1, "Pat", "Finance", null)
              .user(10, "ERP", "pat", 1).grant(10, "ERP_VENDOR_CREATE")
              .user(11, "ERP", "pat_adm", 1).grant(11, "ERP_PAYMENT_APPROVE")
              .employee(2, "Sam", "Finance", null)
              .user(20, "ERP", "sam", 2).grant(20, "ERP_VENDOR_CREATE")
              .account(21, "ERP", "sam_old", 2, "user", "disabled", "2024-01-08").grant(21, "ERP_PAYMENT_APPROVE")
              .employee(3, "Lee", "Finance", null)
              .user(30, "ERP", "lee", 3).grant(30, "ERP_PAYMENT_APPROVE");
            assertEquals(Set.of("Pat Test"), db.run("AR-03"));
        }
    }

    @Test
    void ar04DormantAccountsOfCurrentEmployeesOnly() throws Exception {
        try (TestDb db = new TestDb()) {
            db.employee(1, "Idle", "Sales", null).user(10, "AD", "idle", 1)
              .login(10, "2026-07-01 09:00:00", "10.0.0.1", true)          // ~120 days ago
              .employee(2, "Busy", "Sales", null).user(20, "AD", "busy", 2)
              .login(20, "2026-10-20 09:00:00", "10.0.0.2", true)
              .employee(3, "Never", "Sales", null).user(30, "AD", "never", 3)  // created 2025, never used
              .employee(4, "New", "Sales", null).account(40, "AD", "new", 4, "user", "enabled", "2026-10-20")
              .employee(5, "Left", "Sales", "2026-06-01").user(50, "AD", "left", 5) // AR-01's job
              .account(60, "AD", "svc_backup", null, "service", "enabled", "2024-01-08");
            assertEquals(Set.of("AD/idle", "AD/never"), db.run("AR-04"));
        }
    }

    @Test
    void ar05PrivilegedRolesOutsideIt() throws Exception {
        try (TestDb db = new TestDb()) {
            db.employee(1, "Fin", "Finance", null).user(10, "ERP", "fin", 1).grant(10, "ERP_SYSADMIN")
              .employee(2, "Ops", "IT", null).user(20, "AD", "ops", 2).grant(20, "AD_DOMAIN_ADMIN")
              .employee(3, "Hr", "HR", null).user(30, "AD", "hr", 3).grant(30, "AD_USER")
              .employee(4, "Old", "Sales", null)
              .account(40, "AD", "old", 4, "user", "disabled", "2024-01-08").grant(40, "AD_DOMAIN_ADMIN");
            assertEquals(Set.of("ERP/fin"), db.run("AR-05"));
        }
    }

    @Test
    void ar06OrphanedUserAccounts() throws Exception {
        try (TestDb db = new TestDb()) {
            db.employee(1, "Real", "Sales", null).user(10, "AD", "real", 1)
              .user(20, "AD", "ghost", 999)           // points at nobody
              .user(30, "AD", "nobody", null)         // no owner at all
              .account(40, "AD", "svc_sync", null, "service", "enabled", "2024-01-08")
              .account(50, "AD", "ghost_off", 998, "user", "disabled", "2024-01-08");
            assertEquals(Set.of("AD/ghost", "AD/nobody"), db.run("AR-06"));
        }
    }

    @Test
    void ar07GenericNamesOrManyMachines() throws Exception {
        try (TestDb db = new TestDb()) {
            db.employee(1, "Desk", "Operations", null).user(10, "AD", "shared_frontdesk", 1)
              .employee(2, "Roam", "Sales", null).user(20, "AD", "roam", 2)
              .employee(3, "Lap", "Sales", null).user(30, "AD", "lap", 3);
            for (int i = 1; i <= 5; i++) db.login(20, "2026-10-0" + i + " 09:00:00", "10.0.1." + i, true);
            for (int i = 1; i <= 4; i++) db.login(30, "2026-10-0" + i + " 09:00:00", "10.0.2." + i, true);
            assertEquals(Set.of("AD/shared_frontdesk", "AD/roam"), db.run("AR-07"));
        }
    }

    @Test
    void ar08OffHoursPrivilegedLogins() throws Exception {
        try (TestDb db = new TestDb()) {
            db.employee(1, "Wknd", "IT", null).user(10, "AD", "wknd", 1).grant(10, "AD_DOMAIN_ADMIN")
              .login(10, "2026-10-24 11:00:00", "10.0.0.1", true)        // Saturday
              .employee(2, "Night", "IT", null).user(20, "AD", "night", 2).grant(20, "AD_DOMAIN_ADMIN")
              .login(20, "2026-10-27 22:15:00", "10.0.0.2", true)        // Tuesday 22:15
              .employee(3, "Day", "IT", null).user(30, "AD", "day", 3).grant(30, "AD_DOMAIN_ADMIN")
              .login(30, "2026-10-27 10:00:00", "10.0.0.3", true)        // Tuesday 10:00
              .login(30, "2026-10-27 23:00:00", "10.0.0.3", false)       // failed attempt
              .employee(4, "Plain", "Sales", null).user(40, "AD", "plain", 4).grant(40, "AD_USER")
              .login(40, "2026-10-27 23:00:00", "10.0.0.4", true)        // not privileged
              .account(50, "AD", "svc_backup", null, "service", "enabled", "2024-01-08").grant(50, "AD_DOMAIN_ADMIN")
              .login(50, "2026-10-27 02:00:00", "10.0.0.5", true);       // nightly job
            assertEquals(Set.of("AD/wknd", "AD/night"), db.run("AR-08"));
        }
    }
}
