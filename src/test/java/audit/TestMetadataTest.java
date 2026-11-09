package audit;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** Every SQL test must carry the metadata AuditRunner needs to write a complete finding. */
class TestMetadataTest {

    private static final List<String> REQUIRED =
            List.of("id", "title", "severity", "criteria", "risk", "recommendation", "nist", "iso");

    @Test
    void everyTestFileHasCompleteMetadata() throws Exception {
        List<AuditRunner.AuditTest> tests = AuditRunner.loadTests();
        assertEquals(8, tests.size());
        Set<String> ids = new HashSet<>();
        for (AuditRunner.AuditTest t : tests) {
            for (String key : REQUIRED) {
                String v = t.meta().get(key);
                assertTrue(v != null && !v.isBlank(), t.fileName() + " is missing @" + key);
            }
            assertTrue(Set.of("High", "Medium", "Low").contains(t.severity()), t.fileName() + " severity " + t.severity());
            assertTrue(t.meta().get("nist").matches("(GV|ID|PR|DE|RS|RC)\\.[A-Z]{2}-\\d{2}"), t.fileName());
            assertTrue(t.meta().get("iso").startsWith("A."), t.fileName());
            assertTrue(ids.add(t.id()), "duplicate id " + t.id());
            assertEquals(t.fileName().substring(0, 2), t.id().substring(3), t.fileName() + " number should match its id");
        }
    }

    @Test
    void csvEscaping() {
        assertEquals("", AuditRunner.csv(null));
        assertEquals("plain", AuditRunner.csv("plain"));
        assertEquals("\"a,b\"", AuditRunner.csv("a,b"));
        assertEquals("\"say \"\"hi\"\"\"", AuditRunner.csv("say \"hi\""));
    }

    @Test
    void markdownTableEscapesPipes() {
        String t = AuditRunner.table(List.of("a", "b"), List.of(java.util.Arrays.asList("x|y", null)));
        assertEquals("| a | b |\n|---|---|\n| x/y |  |", t);
    }
}
