package audit;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.*;
import java.sql.*;
import java.time.LocalDate;
import java.util.*;
import java.util.regex.*;

/**
 * Runs the access review.
 *
 *  1. Builds a fresh SQLite database (output/audit.db) from sql/schema.sql and data/seed.sql
 *  2. Runs every audit test in sql/tests/ (one SELECT per file)
 *  3. Writes each test's exceptions to output/findings/AR-0X.csv
 *  4. Writes the audit report to output/audit_report.md
 *
 * Each test file starts with comment lines like "-- @severity: High" that hold the
 * control's details (criteria, risk, recommendation, framework mapping). This class
 * reads those comments and uses them to write the report, so the SQL file is the
 * single place where a control is defined.
 *
 * Run (from the project folder):
 *   javac -d build src/main/java/audit/*.java
 *   java -cp "build:lib/*" audit.AuditRunner
 */
public class AuditRunner {

    static final Path ROOT = Path.of(".");
    static final Path OUT = ROOT.resolve("output");
    static final int MAX_ROWS_IN_REPORT = 10;

    /** One audit test: its metadata from the comments, plus the SQL itself. */
    record AuditTest(String fileName, Map<String, String> meta, String sql) {
        String id()       { return meta.get("id"); }
        String title()    { return meta.get("title"); }
        String severity() { return meta.get("severity"); }
    }

    /** The result of running one test: column names plus every row returned. */
    record TestResult(AuditTest test, List<String> columns, List<List<String>> rows) {}

    public static void main(String[] args) throws Exception {
        Files.createDirectories(OUT.resolve("findings"));
        Files.deleteIfExists(OUT.resolve("audit.db"));

        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + OUT.resolve("audit.db"))) {
            System.out.println("Building database...");
            runScript(conn, ROOT.resolve("sql/schema.sql"));
            runScript(conn, ROOT.resolve("data/seed.sql"));

            System.out.println("Running audit tests:\n");
            List<TestResult> results = new ArrayList<>();
            for (AuditTest t : loadTests()) {
                TestResult r = runTest(conn, t);
                results.add(r);
                writeCsv(r);
                System.out.printf("  %s  %-6s  %-10s  %3d  %s%n", t.id(), t.severity(),
                        r.rows().isEmpty() ? "PASS" : "EXCEPTIONS", r.rows().size(), t.title());
            }

            writeReport(conn, results);

            long withExceptions = results.stream().filter(r -> !r.rows().isEmpty()).count();
            long high = results.stream().filter(r -> !r.rows().isEmpty() && r.test().severity().equals("High")).count();
            System.out.printf("%n%d of %d tests had exceptions (%d high-risk).%n", withExceptions, results.size(), high);
            System.out.println("Report:   output/audit_report.md");
            System.out.println("Findings: output/findings/");
            System.out.println("Database: output/audit.db");
        }
    }

    // ------------------------------------------------------------------ database setup

    /** Runs a .sql file that contains many statements (e.g. CREATE TABLE..., INSERT...). */
    static void runScript(Connection conn, Path file) throws IOException, SQLException {
        try (Statement st = conn.createStatement()) {
            st.executeUpdate(Files.readString(file));
        }
    }

    // ------------------------------------------------------------------ tests

    static List<AuditTest> loadTests() throws IOException {
        Pattern metaLine = Pattern.compile("^--\\s*@(\\w+):\\s*(.+)$", Pattern.MULTILINE);
        List<AuditTest> tests = new ArrayList<>();
        try (DirectoryStream<Path> files = Files.newDirectoryStream(ROOT.resolve("sql/tests"), "*.sql")) {
            for (Path f : files) {
                String sql = Files.readString(f);
                Map<String, String> meta = new HashMap<>();
                Matcher m = metaLine.matcher(sql);
                while (m.find()) meta.put(m.group(1), m.group(2).trim());
                tests.add(new AuditTest(f.getFileName().toString(), meta, sql));
            }
        }
        tests.sort(Comparator.comparing(AuditTest::fileName));
        return tests;
    }

    static TestResult runTest(Connection conn, AuditTest t) throws SQLException {
        try (Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(t.sql())) {
            ResultSetMetaData md = rs.getMetaData();
            List<String> cols = new ArrayList<>();
            for (int i = 1; i <= md.getColumnCount(); i++) cols.add(md.getColumnLabel(i));

            List<List<String>> rows = new ArrayList<>();
            while (rs.next()) {
                List<String> row = new ArrayList<>();
                for (int i = 1; i <= cols.size(); i++) row.add(rs.getString(i));
                rows.add(row);
            }
            return new TestResult(t, cols, rows);
        }
    }

    // ------------------------------------------------------------------ output

    static void writeCsv(TestResult r) throws IOException {
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(OUT.resolve("findings/" + r.test().id() + ".csv")))) {
            w.println(String.join(",", r.columns().stream().map(AuditRunner::csv).toList()));
            for (List<String> row : r.rows()) w.println(String.join(",", row.stream().map(AuditRunner::csv).toList()));
        }
    }

    static String csv(String v) {
        if (v == null) return "";
        return (v.contains(",") || v.contains("\"")) ? "\"" + v.replace("\"", "\"\"") + "\"" : v;
    }

    static int count(Connection conn, String sql) throws SQLException {
        try (Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            rs.next();
            return rs.getInt(1);
        }
    }

    static void writeReport(Connection conn, List<TestResult> results) throws Exception {
        int employees = count(conn, "SELECT COUNT(*) FROM employees");
        int leavers = count(conn, "SELECT COUNT(*) FROM employees WHERE termination_date IS NOT NULL");
        int accounts = count(conn, "SELECT COUNT(*) FROM accounts");
        int enabled = count(conn, "SELECT COUNT(*) FROM accounts WHERE status = 'enabled'");
        int grants = count(conn, "SELECT COUNT(*) FROM account_roles");
        int logins = count(conn, "SELECT COUNT(*) FROM login_events");
        List<String> systems = new ArrayList<>();
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("SELECT system_name FROM systems ORDER BY system_id")) {
            while (rs.next()) systems.add(rs.getString(1));
        }

        List<TestResult> exceptions = results.stream().filter(r -> !r.rows().isEmpty()).toList();
        long high = exceptions.stream().filter(r -> r.test().severity().equals("High")).count();

        StringBuilder md = new StringBuilder();
        md.append("# IT Access Review Audit Report\n\n")
          .append("**Entity:** Ridgeline Logistics *(fictional company, generated data)*  \n")
          .append("**Review period:** 2026-05-01 to 2026-10-31  \n")
          .append("**Report generated:** ").append(LocalDate.now()).append("  \n")
          .append("**Framework:** NIST CSF 2.0 (Identity Management & Access Control) and ISO/IEC 27001:2022 Annex A\n\n")

          .append("## 1. Scope\n")
          .append("- **Systems:** ").append(String.join(", ", systems)).append("\n")
          .append(String.format("- **Population:** %d employees (%d who left the company in 2026), %d accounts (%d enabled), "
                  + "%d role assignments, %,d login events%n", employees, leavers, accounts, enabled, grants, logins))
          .append("- **Approach:** 100% of the population was tested with SQL queries (no sampling). Each test compares "
                  + "system access data against HR records and the company's access policies.\n\n")

          .append("## 2. Executive Summary\n\n")
          .append(String.format("%d access controls were tested. **%d had exceptions**, including **%d high-risk** findings. ",
                  results.size(), exceptions.size(), high))
          .append("The most serious issue is that access was not removed when employees left, and in some cases those "
                  + "accounts were used after termination. That should be treated as a possible security incident, "
                  + "not only a control gap.\n\n");

        List<List<String>> summary = new ArrayList<>();
        for (TestResult r : results) {
            summary.add(List.of(r.test().id(), r.test().title(), r.test().severity(),
                    String.valueOf(r.rows().size()), r.rows().isEmpty() ? "Pass" : "Exception"));
        }
        md.append(table(List.of("ID", "Control tested", "Risk", "Exceptions", "Result"), summary)).append("\n\n");

        md.append("## 3. Detailed Findings\n\n");
        List<TestResult> ordered = new ArrayList<>(exceptions);
        ordered.sort(Comparator.comparing((TestResult r) -> r.test().severity().equals("High") ? 0 : 1)
                .thenComparing(r -> r.test().id()));
        for (TestResult r : ordered) {
            AuditTest t = r.test();
            String csvPath = "`output/findings/" + t.id() + ".csv`";
            md.append("### ").append(t.id()).append(": ").append(t.title())
              .append("  (").append(t.severity()).append(" risk)\n\n")
              .append("**Condition:** ").append(r.rows().size()).append(" exception(s) found. ")
              .append(r.rows().size() <= MAX_ROWS_IN_REPORT
                      ? "The full list is in " + csvPath + "."
                      : "The first " + MAX_ROWS_IN_REPORT + " are shown below; the full list is in " + csvPath + ".")
              .append("\n\n")
              .append(table(r.columns(), r.rows().subList(0, Math.min(MAX_ROWS_IN_REPORT, r.rows().size())))).append("\n\n")
              .append("**Criteria:** ").append(t.meta().get("criteria")).append("\n\n")
              .append("**Risk:** ").append(t.meta().get("risk")).append("\n\n")
              .append("**Recommendation:** ").append(t.meta().get("recommendation")).append("\n\n")
              .append("**Framework:** NIST CSF ").append(t.meta().get("nist"))
              .append(" · ISO 27001 ").append(t.meta().get("iso")).append("  \n")
              .append("**Test query:** [`sql/tests/").append(t.fileName()).append("`](../sql/tests/")
              .append(t.fileName()).append(")\n\n");
        }

        md.append("## 4. Limitations\n")
          .append("- Point-in-time review of exported data; changes made after the export are not reflected.\n")
          .append("- Login data covers the review period only, so dormancy is measured within that window.\n")
          .append("- Exceptions are leads for follow-up with system owners. Some (e.g. an approved change window for "
                  + "off-hours admin work) may turn out to be justified, and would then be documented as accepted exceptions.\n");

        Files.writeString(OUT.resolve("audit_report.md"), md.toString());
    }

    /** Builds a Markdown table (renders as a real table on GitHub). */
    static String table(List<String> cols, List<List<String>> rows) {
        StringBuilder sb = new StringBuilder("| " + String.join(" | ", cols) + " |\n|");
        sb.append("---|".repeat(cols.size()));
        for (List<String> row : rows) {
            sb.append("\n| ");
            sb.append(String.join(" | ", row.stream().map(v -> v == null ? "" : v.replace("|", "/")).toList()));
            sb.append(" |");
        }
        return sb.toString();
    }
}
