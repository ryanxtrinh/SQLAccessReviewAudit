package audit;

import java.nio.file.*;
import java.time.*;
import java.util.*;

/**
 * Generates the fictional Ridgeline Logistics dataset (data/seed.sql).
 *
 * All people, usernames and IP addresses are invented. A fixed random seed means
 * every run produces the same file and the same findings.
 *
 * A realistic access-review dataset is mostly clean, with a small number of control
 * failures planted on purpose, the kind an IT auditor actually finds:
 *   - terminated employees whose accounts were never disabled
 *   - logins after termination
 *   - segregation-of-duties conflicts
 *   - dormant accounts
 *   - admin rights outside IT
 *   - orphaned accounts with no owner
 *   - shared / generic accounts
 *   - privileged logins at odd hours
 * The answer key is written to data/answer_key.sql so Verify can check the
 * audit queries for misses and false positives.
 *
 * You only need this to rebuild the data:
 *   java -cp build audit.DataGenerator
 */
public class DataGenerator {

    static final Random RND = new Random(2026);
    static final LocalDate AUDIT_DATE = LocalDate.of(2026, 10, 31);
    static final LocalDate PERIOD_START = LocalDate.of(2026, 5, 1);

    static final String[] FIRST = {"James", "Maria", "Robert", "Linda", "Michael", "Priya", "David", "Aisha", "Daniel", "Sofia",
            "Kevin", "Grace", "Brian", "Nina", "Carlos", "Hannah", "Jason", "Olivia", "Marcus", "Chloe",
            "Andre", "Leah", "Victor", "Megan", "Omar", "Rachel", "Luis", "Kayla", "Derek", "Yuna",
            "Patrick", "Imani", "Gavin", "Alicia", "Noah", "Fatima", "Ethan", "Bianca", "Owen", "Jada"};
    static final String[] LAST = {"Miller", "Garcia", "Johnson", "Nguyen", "Brown", "Patel", "Davis", "Wilson", "Lopez", "Clark",
            "Lewis", "Walker", "Hall", "Young", "King", "Wright", "Scott", "Green", "Baker", "Adams",
            "Nelson", "Hill", "Campbell", "Mitchell", "Roberts", "Carter", "Phillips", "Turner", "Parker", "Collins",
            "Morris", "Murphy", "Cook", "Rogers", "Morgan", "Cooper", "Reed", "Bailey", "Bell", "Kelly",
            "Howard", "Ward", "Cox", "Diaz", "Richardson", "Wood", "Watson", "Brooks", "Bennett", "Gray"};

    /** department -> headcount; first title is the department head. */
    static final LinkedHashMap<String, Integer> HEADCOUNT = new LinkedHashMap<>();
    static final Map<String, String[]> TITLES = new HashMap<>();
    static final Map<String, Integer> DEPT_OCTET = Map.of("IT", 10, "Finance", 20, "HR", 30, "Operations", 40, "Sales", 50);
    static {
        HEADCOUNT.put("IT", 20);         TITLES.put("IT", new String[]{"IT Manager", "Systems Administrator", "Help Desk Technician", "Network Engineer", "Security Analyst"});
        HEADCOUNT.put("Finance", 30);    TITLES.put("Finance", new String[]{"Controller", "Accounts Payable Clerk", "AP Manager", "Procurement Specialist", "Financial Analyst"});
        HEADCOUNT.put("HR", 15);         TITLES.put("HR", new String[]{"HR Manager", "HR Specialist", "Payroll Specialist", "Recruiter"});
        HEADCOUNT.put("Operations", 75); TITLES.put("Operations", new String[]{"Operations Manager", "Dispatcher", "Warehouse Supervisor", "Logistics Coordinator", "Driver Lead"});
        HEADCOUNT.put("Sales", 40);      TITLES.put("Sales", new String[]{"Sales Manager", "Account Executive", "Sales Representative", "Customer Success Rep"});
    }

    static final String[][] SYSTEMS = {{"AD", "Active Directory", "High"}, {"ERP", "ERP Financials", "High"},
            {"PAYROLL", "Payroll System", "High"}, {"CRM", "Customer CRM", "Medium"}, {"VPN", "Remote Access VPN", "Medium"}};

    /** role_id, system, name, privileged (1 = admin) */
    static final String[][] ROLES = {
            {"AD_USER", "AD", "Domain User", "0"}, {"AD_DOMAIN_ADMIN", "AD", "Domain Administrator", "1"},
            {"IAM_USER_CREATE", "AD", "Create User Accounts", "0"}, {"IAM_ACCESS_APPROVE", "AD", "Approve Access Requests", "0"},
            {"ERP_READ", "ERP", "ERP Read Only", "0"}, {"ERP_VENDOR_CREATE", "ERP", "Create/Modify Vendors", "0"},
            {"ERP_PAYMENT_APPROVE", "ERP", "Approve Payments", "0"}, {"ERP_INVOICE_ENTER", "ERP", "Enter Invoices", "0"},
            {"ERP_PAYMENT_RELEASE", "ERP", "Release Payment Runs", "0"}, {"ERP_SYSADMIN", "ERP", "ERP System Administrator", "1"},
            {"PAY_VIEW", "PAYROLL", "View Payroll", "0"}, {"PAY_EDIT", "PAYROLL", "Edit Pay Rates", "0"},
            {"PAY_APPROVE", "PAYROLL", "Approve Payroll Run", "0"}, {"PAY_ADMIN", "PAYROLL", "Payroll System Administrator", "1"},
            {"CRM_USER", "CRM", "CRM User", "0"}, {"CRM_ADMIN", "CRM", "CRM Administrator", "1"},
            {"VPN_USER", "VPN", "VPN Access", "0"}};
    static final String[][] SOD_RULES = {
            {"SOD-01", "ERP_VENDOR_CREATE", "ERP_PAYMENT_APPROVE", "Creating vendors and approving payments lets one person pay a fake vendor"},
            {"SOD-02", "ERP_INVOICE_ENTER", "ERP_PAYMENT_RELEASE", "Entering invoices and releasing payment runs lets one person pay their own invoice"},
            {"SOD-03", "PAY_EDIT", "PAY_APPROVE", "Editing pay rates and approving payroll lets one person raise their own pay"},
            {"SOD-04", "IAM_USER_CREATE", "IAM_ACCESS_APPROVE", "Creating accounts and approving access lets one person grant themselves any access"}};
    static final Map<String, String> BASE_ROLE = Map.of("AD", "AD_USER", "VPN", "VPN_USER", "ERP", "ERP_READ",
            "PAYROLL", "PAY_VIEW", "CRM", "CRM_USER");

    // ------------------------------------------------------------------ data model
    static class Employee {
        int id; String first, last, dept, title; Integer managerId; LocalDate hire, term;
    }
    record Account(int id, String system, String username, Integer employeeId, String type, String[] status, LocalDate created) {}
    record Grant(int accountId, String role, LocalDate granted) {}
    record Login(int accountId, LocalDateTime time, String ip, int success) {}

    static final List<Employee> employees = new ArrayList<>();
    static final Map<Integer, Employee> E = new HashMap<>();
    static final List<Account> accounts = new ArrayList<>();
    static final List<Grant> grants = new ArrayList<>();
    static final List<Login> logins = new ArrayList<>();
    static final Map<Integer, Map<String, Integer>> empAccounts = new HashMap<>();   // employee -> system -> account
    static final Set<String> usernames = new HashSet<>();
    static final Map<String, List<Object>> planted = new LinkedHashMap<>();
    static int nextAccount = 1000;

    // ------------------------------------------------------------------ small helpers
    static LocalDate randDate(LocalDate a, LocalDate b) {
        return a.plusDays(RND.nextInt((int) (b.toEpochDay() - a.toEpochDay()) + 1));
    }
    static int between(int lo, int hi) { return lo + RND.nextInt(hi - lo + 1); }
    static <T> T pickOne(List<T> list) { return list.get(RND.nextInt(list.size())); }

    static String uname(String first, String last) {
        String base = (first.charAt(0) + last).toLowerCase();
        String u = base;
        for (int n = 2; usernames.contains(u); n++) u = base + n;
        usernames.add(u);
        return u;
    }

    static int addAccount(String system, String username, Integer empId, LocalDate created, String status, String type) {
        int id = nextAccount++;
        accounts.add(new Account(id, system, username, empId, type, new String[]{status}, created));
        return id;
    }
    static int addAccount(String system, String username, Integer empId, LocalDate created) {
        return addAccount(system, username, empId, created, "enabled", "user");
    }
    static Account account(int id) { return accounts.stream().filter(a -> a.id() == id).findFirst().orElseThrow(); }

    static void grant(int accountId, String role, LocalDate when) { grants.add(new Grant(accountId, role, when)); }
    static String systemOf(String role) { return Arrays.stream(ROLES).filter(r -> r[0].equals(role)).findFirst().orElseThrow()[1]; }

    static void login(int accountId, LocalDateTime t, String ip, int success) { logins.add(new Login(accountId, t, ip, success)); }

    static LocalDateTime businessTime(LocalDate d) {
        return d.atTime(between(7, 17), between(0, 59), between(0, 59));
    }
    static LocalDate weekdayOnOrBefore(LocalDate d) {
        while (d.getDayOfWeek().getValue() >= 6) d = d.minusDays(1);
        return d;
    }

    /** Roughly 1-2 logins a week on weekdays during business hours. */
    static void normalLogins(int accountId, List<String> ips, LocalDate start, LocalDate end, boolean recent) {
        if (start.isBefore(PERIOD_START)) start = PERIOD_START;
        if (start.isAfter(end)) return;
        for (LocalDate day = start; !day.isAfter(end); day = day.plusDays(7)) {
            int n = RND.nextInt(3) == 2 ? 2 : 1;
            for (int i = 0; i < n; i++) {
                LocalDate d = day.plusDays(between(0, 4));
                if (d.isAfter(end)) continue;
                d = weekdayOnOrBefore(d);
                if (d.isBefore(start)) continue;
                if (RND.nextDouble() < 0.04) login(accountId, businessTime(d), pickOne(ips), 0);   // mistyped password
                login(accountId, businessTime(d), pickOne(ips), 1);
            }
        }
        if (recent && end.equals(AUDIT_DATE)) {   // guarantee activity in the last two weeks
            login(accountId, businessTime(weekdayOnOrBefore(AUDIT_DATE.minusDays(between(0, 12)))), ips.get(0), 1);
        }
    }

    static String usernameOf(int empId) { return account(empAccounts.get(empId).get("AD")).username(); }

    static int ensureAccount(int empId, String system) {
        Map<String, Integer> acc = empAccounts.get(empId);
        if (!acc.containsKey(system)) {
            LocalDate hire = E.get(empId).hire;
            int id = addAccount(system, usernameOf(empId), empId, hire);
            grant(id, BASE_ROLE.get(system), hire);
            acc.put(system, id);
        }
        return acc.get(system);
    }

    static final Set<Integer> used = new HashSet<>();
    static List<Employee> active;

    /** Picks a current, non-head employee in a department (preferring a title) who hasn't been used for another planted issue. */
    static int pick(String dept, String title) {
        List<Integer> pool = new ArrayList<>();
        for (Employee e : active)
            if (e.dept.equals(dept) && !used.contains(e.id) && (title == null || e.title.equals(title))) pool.add(e.id);
        if (pool.isEmpty())
            for (Employee e : active) if (e.dept.equals(dept) && !used.contains(e.id)) pool.add(e.id);
        int id = pickOne(pool);
        used.add(id);
        return id;
    }

    // ------------------------------------------------------------------ main
    public static void main(String[] args) throws Exception {
        for (String k : List.of("terminated_enabled_accounts", "post_termination_login_accounts", "sod_conflict_employees",
                "dormant_accounts", "privileged_non_it_accounts", "orphaned_accounts", "generic_accounts",
                "off_hours_privileged_accounts")) planted.put(k, new ArrayList<>());

        // ---- employees
        int nextEmp = 1;
        Map<String, List<Integer>> byDept = new LinkedHashMap<>();
        for (var d : HEADCOUNT.entrySet()) {
            int head = nextEmp;
            String[] titles = TITLES.get(d.getKey());
            for (int i = 0; i < d.getValue(); i++) {
                Employee e = new Employee();
                e.id = nextEmp++;
                e.first = FIRST[RND.nextInt(FIRST.length)];
                e.last = LAST[RND.nextInt(LAST.length)];
                e.dept = d.getKey();
                e.title = i == 0 ? titles[0] : titles[1 + RND.nextInt(titles.length - 1)];
                e.managerId = i == 0 ? null : head;
                e.hire = randDate(LocalDate.of(2015, 1, 5), LocalDate.of(2026, 6, 30));
                employees.add(e);
                E.put(e.id, e);
                byDept.computeIfAbsent(e.dept, k -> new ArrayList<>()).add(e.id);
            }
        }

        // 14 people left during 2026 (never a department head)
        List<Employee> leaverPool = new ArrayList<>();
        for (Employee e : employees) if (e.managerId != null && e.hire.isBefore(LocalDate.of(2026, 1, 1))) leaverPool.add(e);
        Collections.shuffle(leaverPool, RND);
        List<Employee> leavers = leaverPool.subList(0, 14);
        for (Employee e : leavers) e.term = randDate(LocalDate.of(2026, 3, 1), LocalDate.of(2026, 10, 15));

        // ---- accounts and job roles (each person holds at most one side of any SoD pair)
        Map<String, String> jobRole = Map.of("Procurement Specialist", "ERP_VENDOR_CREATE", "Controller", "ERP_PAYMENT_APPROVE",
                "Accounts Payable Clerk", "ERP_INVOICE_ENTER", "AP Manager", "ERP_PAYMENT_RELEASE",
                "Payroll Specialist", "PAY_EDIT", "HR Manager", "PAY_APPROVE",
                "Help Desk Technician", "IAM_USER_CREATE", "IT Manager", "IAM_ACCESS_APPROVE");
        for (Employee e : employees) {
            String status = e.term != null ? "disabled" : "enabled";
            String u = uname(e.first, e.last);
            List<String> systems = new ArrayList<>(List.of("AD", "VPN"));
            if (e.dept.equals("Finance") || (e.dept.equals("Operations") && RND.nextDouble() < 0.3)) systems.add("ERP");
            if (e.dept.equals("HR")) systems.add("PAYROLL");
            if (e.dept.equals("Sales")) systems.add("CRM");
            Map<String, Integer> acc = new LinkedHashMap<>();
            empAccounts.put(e.id, acc);
            for (String s : systems) {
                int id = addAccount(s, u, e.id, e.hire, status, "user");
                acc.put(s, id);
                grant(id, BASE_ROLE.get(s), e.hire);
            }
            String role = jobRole.get(e.title);
            if (role != null) {
                String sys = systemOf(role);
                if (!acc.containsKey(sys)) {
                    acc.put(sys, addAccount(sys, u, e.id, e.hire, status, "user"));
                    grant(acc.get(sys), BASE_ROLE.get(sys), e.hire);
                }
                grant(acc.get(sys), role, e.hire.plusDays(between(0, 30)));
            }
        }

        // ---- legitimate admins: all in IT
        List<Integer> itStaff = new ArrayList<>();
        for (int id : byDept.get("IT")) if (E.get(id).term == null) itStaff.add(id);
        List<Integer> sysadmins = new ArrayList<>();
        for (int id : itStaff) if (E.get(id).title.equals("Systems Administrator") && sysadmins.size() < 2) sysadmins.add(id);
        if (sysadmins.isEmpty()) sysadmins = itStaff.subList(1, 3);
        Object[][] adminAssignments = {{sysadmins.get(0), "AD", "AD_DOMAIN_ADMIN"}, {sysadmins.get(sysadmins.size() - 1), "AD", "AD_DOMAIN_ADMIN"},
                {itStaff.get(3), "ERP", "ERP_SYSADMIN"}, {itStaff.get(4), "PAYROLL", "PAY_ADMIN"}, {itStaff.get(5), "CRM", "CRM_ADMIN"}};
        for (Object[] a : adminAssignments) {
            int id = ensureAccount((Integer) a[0], (String) a[1]);
            grant(id, (String) a[2], LocalDate.of(2025, 1, 15));
        }

        active = new ArrayList<>();
        for (Employee e : employees) if (e.term == null && e.managerId != null) active.add(e);
        used.addAll(sysadmins);
        used.addAll(itStaff.subList(0, 6));

        // ================================================================ PLANTED ISSUES
        // 1. SoD conflicts (4 people)
        Map<String, String[]> sodTarget = Map.of("SOD-01", new String[]{"Finance", "Procurement Specialist"},
                "SOD-02", new String[]{"Finance", "Accounts Payable Clerk"}, "SOD-03", new String[]{"HR", "Payroll Specialist"},
                "SOD-04", new String[]{"IT", "Help Desk Technician"});
        for (String[] rule : SOD_RULES) {
            String[] t = sodTarget.get(rule[0]);
            int emp = pick(t[0], t[1]);
            int id = ensureAccount(emp, systemOf(rule[1]));
            Set<String> have = new HashSet<>();
            for (Grant g : grants) if (g.accountId() == id) have.add(g.role());
            for (String role : new String[]{rule[1], rule[2]})
                if (!have.contains(role)) grant(id, role, LocalDate.of(2026, between(1, 8), between(1, 28)));
            planted.get("sod_conflict_employees").add(emp);
        }

        // 2. Admin rights outside IT (3 accounts)
        String[][] nonItAdmins = {{"Finance", "ERP", "ERP_SYSADMIN"}, {"Operations", "AD", "AD_DOMAIN_ADMIN"}, {"Sales", "CRM", "CRM_ADMIN"}};
        List<Integer> nonItAdminAccounts = new ArrayList<>();
        for (String[] a : nonItAdmins) {
            int id = ensureAccount(pick(a[0], null), a[1]);
            grant(id, a[2], LocalDate.of(2026, between(2, 7), between(1, 28)));
            nonItAdminAccounts.add(id);
        }
        planted.get("privileged_non_it_accounts").addAll(nonItAdminAccounts);
        int opsAdminAccount = nonItAdminAccounts.get(1);

        // 3. Leavers whose access was never removed: 3 people, AD + VPN left enabled (6 accounts)
        List<Employee> missed = new ArrayList<>(leavers);
        Collections.shuffle(missed, RND);
        missed = missed.subList(0, 3);
        List<Integer> terminatedEnabled = new ArrayList<>();
        for (Employee e : missed)
            for (String s : List.of("AD", "VPN")) {
                int id = empAccounts.get(e.id).get(s);
                account(id).status()[0] = "enabled";
                terminatedEnabled.add(id);
            }
        planted.get("terminated_enabled_accounts").addAll(terminatedEnabled);

        // 4. Dormant accounts for current employees: 5 stale + 2 never used
        List<Integer> dormantStale = new ArrayList<>();
        for (int i = 0; i < 5; i++)
            dormantStale.add(ensureAccount(pick(List.of("Operations", "Sales", "Finance").get(RND.nextInt(3)), null), "VPN"));
        List<Integer> dormantNever = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            int emp = pick("Operations", null);
            while (empAccounts.get(emp).containsKey("ERP")) emp = pick("Operations", null);
            int id = addAccount("ERP", usernameOf(emp), emp, LocalDate.of(2026, 8, 14));
            grant(id, "ERP_READ", LocalDate.of(2026, 8, 14));
            empAccounts.get(emp).put("ERP", id);
            dormantNever.add(id);
        }
        planted.get("dormant_accounts").addAll(dormantStale);
        planted.get("dormant_accounts").addAll(dormantNever);

        // 5. Orphaned accounts: user accounts with no matching employee (3)
        Object[][] orphans = {{"CRM", "jmorris_old", null}, {"ERP", "contractor07", 9999}, {"VPN", "vendor_access", null}};
        for (Object[] o : orphans) {
            int id = addAccount((String) o[0], (String) o[1], (Integer) o[2], LocalDate.of(2024, between(1, 12), 10));
            grant(id, BASE_ROLE.get((String) o[0]), LocalDate.of(2024, 6, 1));
            planted.get("orphaned_accounts").add(id);
            normalLogins(id, List.of("172.16." + between(1, 250) + "." + between(2, 250)), PERIOD_START, LocalDate.of(2026, 9, 30), false);
        }

        // 6. Shared / generic accounts owned by a real person (2)
        int shared = addAccount("AD", "shared_ops", byDept.get("Operations").get(0), LocalDate.of(2023, 3, 1));
        grant(shared, "AD_USER", LocalDate.of(2023, 3, 1));
        int testAcct = addAccount("ERP", "test_user1", itStaff.get(2), LocalDate.of(2025, 11, 3));
        grant(testAcct, "ERP_READ", LocalDate.of(2025, 11, 3));
        grant(testAcct, "ERP_INVOICE_ENTER", LocalDate.of(2025, 11, 3));
        planted.get("generic_accounts").addAll(List.of(shared, testAcct));
        List<String> manyIps = new ArrayList<>();
        for (int n = 101; n < 110; n++) manyIps.add("10.20.40." + n);
        normalLogins(shared, manyIps, PERIOD_START, AUDIT_DATE, true);
        normalLogins(testAcct, List.of("10.20.10.15", "10.20.10.16"), PERIOD_START, AUDIT_DATE, true);

        // 7. Service accounts: legitimate, no human owner, run nightly
        String[][] services = {{"AD", "svc_backup"}, {"ERP", "svc_erp_integration"}, {"PAYROLL", "svc_payroll_export"}};
        for (String[] s : services) {
            int id = addAccount(s[0], s[1], null, LocalDate.of(2022, 1, 10), "enabled", "service");
            grant(id, BASE_ROLE.get(s[0]), LocalDate.of(2022, 1, 10));
            for (LocalDate d = PERIOD_START; !d.isAfter(AUDIT_DATE); d = d.plusDays(1))
                login(id, d.atTime(2, between(0, 9)), "10.20.99.5", 1);
        }

        // ---- normal login history for everyone else
        Set<Integer> special = new HashSet<>();
        for (List<Object> l : List.of(planted.get("dormant_accounts"), planted.get("orphaned_accounts"), planted.get("generic_accounts")))
            for (Object o : l) special.add((Integer) o);
        for (Employee e : employees) {
            int oct = DEPT_OCTET.get(e.dept);
            List<String> ips = new ArrayList<>(List.of("10.20." + oct + "." + between(20, 250)));
            if (RND.nextDouble() < 0.5) ips.add("172.16." + oct + "." + between(2, 250));
            for (int id : empAccounts.get(e.id).values()) {
                if (special.contains(id)) {
                    if (dormantStale.contains(id))   // last activity in early summer, nothing since
                        normalLogins(id, ips, e.hire, LocalDate.of(2026, between(6, 7), between(1, 25)), false);
                    continue;                        // never-used accounts get no logins
                }
                LocalDate end = e.term != null ? e.term.minusDays(between(1, 5)) : AUDIT_DATE;
                normalLogins(id, ips, e.hire, end, e.term == null);
            }
        }

        // 8. Logins after termination: the AD account of 2 of those leavers
        for (int i = 0; i < 2; i++) {
            Employee e = missed.get(i);
            int id = empAccounts.get(e.id).get("AD");
            int count = between(2, 4);
            String outsideIp = "203.0.113." + between(10, 200);   // one external address (documentation range)
            for (int k = 0; k < count; k++) {
                LocalDate d = weekdayOnOrBefore(min(AUDIT_DATE, e.term.plusDays(3 + 4L * k)));
                if (!d.isAfter(e.term)) d = e.term.plusDays(1);
                login(id, businessTime(d), outsideIp, 1);
            }
            planted.get("post_termination_login_accounts").add(id);
        }

        // 9. Privileged logins at odd hours (2 admin accounts)
        List<Integer> odd = List.of(empAccounts.get(sysadmins.get(0)).get("AD"), opsAdminAccount);
        for (int id : odd) {
            int n = between(3, 5);
            for (int k = 0; k < n; k++) {
                LocalDate d = randDate(LocalDate.of(2026, 6, 1), LocalDate.of(2026, 10, 25));
                LocalDateTime t;
                if (RND.nextDouble() < 0.5) {   // weekend
                    while (d.getDayOfWeek().getValue() < 6) d = d.plusDays(1);
                    t = d.atTime(between(10, 22), between(0, 59));
                } else {                        // middle of the night
                    t = d.atTime(between(0, 4), between(0, 59));
                }
                login(id, t, "172.16.10.77", 1);
            }
        }
        planted.get("off_hours_privileged_accounts").addAll(odd);

        write();
        System.out.printf("employees=%d accounts=%d role_grants=%d logins=%d%n",
                employees.size(), accounts.size(), grants.size(), logins.size());
    }

    static LocalDate min(LocalDate a, LocalDate b) { return a.isBefore(b) ? a : b; }

    // ------------------------------------------------------------------ write SQL + answer key
    static String lit(Object v) {
        if (v == null) return "NULL";
        if (v instanceof Integer) return v.toString();
        return "'" + v.toString().replace("'", "''") + "'";
    }

    static void inserts(StringBuilder sb, String table, String cols, List<Object[]> rows) {
        for (int i = 0; i < rows.size(); i += 500) {
            sb.append("INSERT INTO ").append(table).append(" (").append(cols).append(") VALUES\n");
            List<Object[]> chunk = rows.subList(i, Math.min(rows.size(), i + 500));
            for (int j = 0; j < chunk.size(); j++) {
                StringJoiner sj = new StringJoiner(", ", "(", ")");
                for (Object v : chunk.get(j)) sj.add(lit(v));
                sb.append(sj).append(j < chunk.size() - 1 ? ",\n" : ";\n");
            }
        }
    }

    static void write() throws Exception {
        logins.sort(Comparator.comparing(Login::time).thenComparingInt(Login::accountId));
        java.time.format.DateTimeFormatter ts = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

        StringBuilder sb = new StringBuilder("-- Generated by DataGenerator.java. Fictional data: Ridgeline Logistics.\nBEGIN;\n");
        List<Object[]> rows = new ArrayList<>();
        for (Employee e : employees)
            rows.add(new Object[]{e.id, e.first, e.last, e.dept, e.title, e.managerId, e.hire.toString(), e.term == null ? null : e.term.toString()});
        inserts(sb, "employees", "employee_id, first_name, last_name, department, job_title, manager_id, hire_date, termination_date", rows);

        rows = new ArrayList<>();
        for (String[] s : SYSTEMS) rows.add(new Object[]{s[0], s[1], s[2]});
        inserts(sb, "systems", "system_id, system_name, criticality", rows);

        rows = new ArrayList<>();
        for (Account a : accounts)
            rows.add(new Object[]{a.id(), a.system(), a.username(), a.employeeId(), a.type(), a.status()[0], a.created().toString()});
        inserts(sb, "accounts", "account_id, system_id, username, employee_id, account_type, status, created_date", rows);

        rows = new ArrayList<>();
        for (String[] r : ROLES) rows.add(new Object[]{r[0], r[1], r[2], Integer.parseInt(r[3])});
        inserts(sb, "roles", "role_id, system_id, role_name, privileged", rows);

        rows = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (Grant g : grants)
            if (seen.add(g.accountId() + "|" + g.role())) rows.add(new Object[]{g.accountId(), g.role(), g.granted().toString()});
        inserts(sb, "account_roles", "account_id, role_id, granted_date", rows);

        rows = new ArrayList<>();
        for (String[] r : SOD_RULES) rows.add(new Object[]{r[0], r[1], r[2], r[3]});
        inserts(sb, "sod_rules", "rule_id, role_a, role_b, description", rows);

        rows = new ArrayList<>();
        int eventId = 1;
        for (Login l : logins) rows.add(new Object[]{eventId++, l.accountId(), l.time().format(ts), l.ip(), l.success()});
        inserts(sb, "login_events", "event_id, account_id, login_time, source_ip, success", rows);
        sb.append("COMMIT;\n");
        Files.writeString(Path.of("data/seed.sql"), sb.toString());

        // answer key: one row per planted issue, as SQL so Verify can load it straight into the database
        Map<String, String> checkIds = Map.of("terminated_enabled_accounts", "AR-01", "post_termination_login_accounts", "AR-02",
                "sod_conflict_employees", "AR-03", "dormant_accounts", "AR-04", "privileged_non_it_accounts", "AR-05",
                "orphaned_accounts", "AR-06", "generic_accounts", "AR-07", "off_hours_privileged_accounts", "AR-08");
        StringBuilder key = new StringBuilder("""
                -- Answer key: every control failure planted by DataGenerator.java.
                -- Verify.java loads this and compares it with what each audit query finds.
                DROP TABLE IF EXISTS planted_issues;
                CREATE TABLE planted_issues (
                    check_id    TEXT    NOT NULL,   -- which audit test should find it
                    account_id  INTEGER,            -- for account-level tests
                    employee_id INTEGER             -- for person-level tests (SoD)
                );
                """);
        for (var entry : planted.entrySet()) {
            String id = checkIds.get(entry.getKey());
            boolean person = entry.getKey().equals("sod_conflict_employees");
            for (Object o : entry.getValue())
                key.append(person
                        ? "INSERT INTO planted_issues (check_id, employee_id) VALUES ('" + id + "', " + o + ");\n"
                        : "INSERT INTO planted_issues (check_id, account_id) VALUES ('" + id + "', " + o + ");\n");
        }
        Files.writeString(Path.of("data/answer_key.sql"), key.toString());
    }
}
