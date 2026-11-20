package audit;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Set;

/**
 * A fresh in-memory SQLite database with the real schema, for building tiny,
 * hand-written scenarios that each audit query must classify correctly.
 */
final class TestDb implements AutoCloseable {

    final Connection conn;

    TestDb() throws SQLException {
        conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        exec(read("sql/schema.sql"));
        exec("""
            INSERT INTO systems VALUES ('AD','Active Directory','High'), ('ERP','ERP Financials','High'),
                                       ('VPN','VPN','High');
            INSERT INTO roles VALUES ('AD_USER','AD','Domain User',0), ('AD_DOMAIN_ADMIN','AD','Domain Admin',1),
                                     ('ERP_VENDOR_CREATE','ERP','Create Vendor',0),
                                     ('ERP_PAYMENT_APPROVE','ERP','Approve Payment',0),
                                     ('ERP_SYSADMIN','ERP','ERP Administrator',1);
            INSERT INTO sod_rules VALUES ('SOD-01','ERP_VENDOR_CREATE','ERP_PAYMENT_APPROVE',
                                          'Create vendor and approve payment');
            """);
    }

    static String read(String file) {
        try { return Files.readString(Path.of(file)); }
        catch (IOException e) { throw new UncheckedIOException(e); }
    }

    TestDb exec(String sql) throws SQLException {
        try (Statement st = conn.createStatement()) { st.executeUpdate(sql); }
        return this;
    }

    TestDb employee(int id, String first, String dept, String terminated) throws SQLException {
        return exec(String.format("INSERT INTO employees VALUES (%d,'%s','Test','%s','Analyst',NULL,'2020-01-06',%s)",
                id, first, dept, terminated == null ? "NULL" : "'" + terminated + "'"));
    }

    TestDb account(int id, String system, String user, Integer emp, String type, String status, String created)
            throws SQLException {
        return exec(String.format("INSERT INTO accounts VALUES (%d,'%s','%s',%s,'%s','%s','%s')",
                id, system, user, emp == null ? "NULL" : emp.toString(), type, status, created));
    }

    TestDb user(int id, String system, String user, Integer emp) throws SQLException {
        return account(id, system, user, emp, "user", "enabled", "2025-01-06");
    }

    TestDb grant(int account, String role) throws SQLException {
        return exec(String.format("INSERT INTO account_roles VALUES (%d,'%s','2025-01-06')", account, role));
    }

    TestDb login(int account, String time, String ip, boolean success) throws SQLException {
        return exec(String.format("INSERT INTO login_events (account_id, login_time, source_ip, success) VALUES (%d,'%s','%s',%d)",
                account, time, ip, success ? 1 : 0));
    }

    /** Runs one audit query; results as "SYSTEM/username" (or employee name for person-level tests). */
    Set<String> run(String id) throws Exception {
        for (String[] c : Verify.CHECKS) {
            if (c[0].equals(id)) return Verify.found(conn, Path.of("sql/tests", c[1]), c[2]);
        }
        throw new IllegalArgumentException(id);
    }

    @Override public void close() throws SQLException { conn.close(); }
}
