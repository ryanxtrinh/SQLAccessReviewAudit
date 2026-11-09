package audit;

import java.nio.file.*;
import java.sql.*;
import java.util.*;
import java.util.regex.*;

/**
 * Checks that every audit query finds exactly the issues planted in the data
 * (data/planted_issues.json): no missed issues and no false positives.
 *
 * Run AuditRunner first (it builds output/audit.db), then:  ./run.sh verify
 */
public class Verify {

    public static void main(String[] args) throws Exception {
        String json = Files.readString(Path.of("data/planted_issues.json"));
        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:output/audit.db")) {

            // test id, query file, planted list in the JSON, and whether the test lists accounts or people
            String[][] checks = {
                {"AR-01", "01_terminated_users_active.sql",       "terminated_enabled_accounts",     "accounts"},
                {"AR-02", "02_logins_after_termination.sql",      "post_termination_login_accounts", "accounts"},
                {"AR-03", "03_sod_conflicts.sql",                 "sod_conflict_employees",          "people"},
                {"AR-04", "04_dormant_accounts.sql",              "dormant_accounts",                "accounts"},
                {"AR-05", "05_privileged_access_outside_it.sql",  "privileged_non_it_accounts",      "accounts"},
                {"AR-06", "06_orphaned_accounts.sql",             "orphaned_accounts",               "accounts"},
                {"AR-07", "07_shared_generic_accounts.sql",       "generic_accounts",                "accounts"},
                {"AR-08", "08_off_hours_privileged_logins.sql",   "off_hours_privileged_accounts",   "accounts"},
            };

            boolean allOk = true;
            for (String[] c : checks) {
                List<Integer> ids = idsFromJson(json, c[2]);
                Set<String> expected = c[3].equals("people") ? employeeNames(conn, ids) : accountKeys(conn, ids);
                Set<String> found = runAndCollect(conn, Path.of("sql/tests", c[1]), c[3]);

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

    /**
     * Pulls the numbers for one key out of planted_issues.json. A tiny regex parser,
     * so the project needs no JSON library. For the SoD list it takes the employee_id values.
     */
    static List<Integer> idsFromJson(String json, String key) {
        Matcher block = Pattern.compile("\"" + key + "\"\\s*:\\s*\\[(.*?)\\]", Pattern.DOTALL).matcher(json);
        if (!block.find()) throw new IllegalArgumentException("Key not found: " + key);
        String body = block.group(1);
        Pattern num = body.contains("employee_id")
                ? Pattern.compile("\"employee_id\"\\s*:\\s*(\\d+)")
                : Pattern.compile("(\\d+)");
        List<Integer> ids = new ArrayList<>();
        Matcher m = num.matcher(body);
        while (m.find()) ids.add(Integer.parseInt(m.group(1)));
        return ids;
    }

    static Set<String> accountKeys(Connection conn, List<Integer> ids) throws SQLException {
        return lookup(conn, "SELECT system_id || '/' || username FROM accounts WHERE account_id = ?", ids);
    }

    static Set<String> employeeNames(Connection conn, List<Integer> ids) throws SQLException {
        return lookup(conn, "SELECT first_name || ' ' || last_name FROM employees WHERE employee_id = ?", ids);
    }

    static Set<String> lookup(Connection conn, String sql, List<Integer> ids) throws SQLException {
        Set<String> out = new TreeSet<>();
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            for (int id : ids) {
                ps.setInt(1, id);
                try (ResultSet rs = ps.executeQuery()) { if (rs.next()) out.add(rs.getString(1)); }
            }
        }
        return out;
    }

    /** Runs a test query and returns "SYSTEM/username" per row, or the employee name for people-based tests. */
    static Set<String> runAndCollect(Connection conn, Path file, String kind) throws Exception {
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
