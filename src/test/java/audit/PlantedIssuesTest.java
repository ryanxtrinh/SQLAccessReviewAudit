package audit;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The JUnit version of Verify: every audit query must return exactly the issues
 * planted by DataGenerator in the full 180-employee dataset. No misses, no false positives.
 */
class PlantedIssuesTest {

    private static Connection loadFullDataset() throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        try (Statement st = conn.createStatement()) {
            st.executeUpdate(TestDb.read("sql/schema.sql"));
            st.executeUpdate(TestDb.read("data/seed.sql"));
            st.executeUpdate(TestDb.read("data/answer_key.sql"));
        }
        return conn;
    }

    @Test
    void everyQueryFindsExactlyThePlantedIssues() throws Exception {
        try (Connection conn = loadFullDataset()) {
            StringBuilder problems = new StringBuilder();
            for (String[] c : Verify.CHECKS) {
                Set<String> expected = Verify.expected(conn, c[0], c[2]);
                Set<String> found = Verify.found(conn, Path.of("sql/tests", c[1]), c[2]);
                assertFalse(expected.isEmpty(), c[0] + " has nothing planted");
                if (!expected.equals(found)) {
                    problems.append(c[0]).append(": expected ").append(expected)
                            .append(" but found ").append(found).append('\n');
                }
            }
            assertTrue(problems.length() == 0, problems.toString());
        }
    }

    @Test
    void datasetMatchesTheSizeStatedInTheReadme() throws Exception {
        try (Connection conn = loadFullDataset(); Statement st = conn.createStatement()) {
            assertEquals(180, count(st, "SELECT COUNT(*) FROM employees"));
            assertEquals(479, count(st, "SELECT COUNT(*) FROM accounts"));
            assertEquals(17345, count(st, "SELECT COUNT(*) FROM login_events"));
            assertEquals(5, count(st, "SELECT COUNT(*) FROM systems"));
        }
    }

    @Test
    void verifyCoversEveryTestFile() throws Exception {
        long files;
        try (var s = java.nio.file.Files.list(Path.of("sql/tests"))) {
            files = s.filter(p -> p.toString().endsWith(".sql")).count();
        }
        assertEquals(files, Verify.CHECKS.length, "add new tests to Verify.CHECKS");
    }

    private static int count(Statement st, String sql) throws Exception {
        try (ResultSet rs = st.executeQuery(sql)) { rs.next(); return rs.getInt(1); }
    }
}
