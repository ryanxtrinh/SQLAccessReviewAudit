package audit;

import java.nio.file.*;
import java.sql.*;
import java.util.*;

/**
 * Checks that every audit query finds exactly the issues planted in the data:
 * no missed issues and no false positives.
 *
 * The answer key (data/answer_key.sql) lists every planted issue. Verify loads it
 * into the audit database, runs each test query, and compares the two lists.
 *
 * Run AuditRunner first (it builds output/audit.db), then:
 *   java -cp "build:lib/*" audit.Verify
 */
public class Verify {

    /** test id, query file, and whether the test reports accounts or people */
    static final String[][] CHECKS = {
        {"AR-01", "01_terminated_users_active.sql",      "accounts"},
        {"AR-02", "02_logins_after_termination.sql",     "accounts"},
        {"AR-03", "03_sod_conflicts.sql",                "people"},
        {"AR-04", "04_dormant_accounts.sql",             "accounts"},
        {"AR-05", "05_privileged_access_outside_it.sql", "accounts"},
        {"AR-06", "06_orphaned_accounts.sql",            "accounts"},
        {"AR-07", "07_shared_generic_accounts.sql",      "accounts"},
        {"AR-08", "08_off_hours_privileged_logins.sql",  "accounts"},
    };

    public static void main(String[] args) throws Exception {
        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:output/audit.db")) {
            try (Statement st = conn.createStatement()) {
                st.executeUpdate(Files.readString(Path.of("data/answer_key.sql")));
            }

            boolean allOk = true;
            for (String[] c : CHECKS) {
                Set<String> expected = expected(conn, c[0], c[2]);
                Set<String> found = found(conn, Path.of("sql/tests", c[1]), c[2]);

                Set<String> missed = new TreeSet<>(expected); missed.removeAll(found);
                Set<String> extra  = new TreeSet<>(found);    extra.removeAll(expected);
                boolean ok = missed.isEmpty() && extra.isEmpty();
                allOk &= ok;
                System.out.printf("%s: %-8s expected %d, found %d%s%s%n", c[0], ok ? "OK" : "MISMATCH",
                        expected.size(), found.size(),
                        missed.isEmpty() ? "" : "  missed=" + missed,
                        extra.isEmpty() ? "" : "  extra=" + extra);
            }
            System.out.println(allOk ? "\nAll tests match the planted issues." : "\nSome tests do not match.");
            System.exit(allOk ? 0 : 1);
        }
    }

    /** What the answer key says this test should find, as "SYSTEM/username" or the employee's name. */
    static Set<String> expected(Connection conn, String checkId, String kind) throws SQLException {
        String sql = kind.equals("people")
                ? "SELECT e.first_name || ' ' || e.last_name FROM planted_issues p "
                  + "JOIN employees e ON e.employee_id = p.employee_id WHERE p.check_id = ?"
                : "SELECT a.system_id || '/' || a.username FROM planted_issues p "
                  + "JOIN accounts a ON a.account_id = p.account_id WHERE p.check_id = ?";
        Set<String> out = new TreeSet<>();
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, checkId);
            try (ResultSet rs = ps.executeQuery()) { while (rs.next()) out.add(rs.getString(1)); }
        }
        return out;
    }

    /** What the audit query actually returns, in the same format. */
    static Set<String> found(Connection conn, Path file, String kind) throws Exception {
        Set<String> out = new TreeSet<>();
        try (Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(Files.readString(file))) {
            while (rs.next()) {
                out.add(kind.equals("people") ? rs.getString("employee")
                                              : rs.getString("system_id") + "/" + rs.getString("username"));
            }
        }
        return out;
    }
}
