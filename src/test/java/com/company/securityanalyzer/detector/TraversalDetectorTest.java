package com.company.securityanalyzer.detector;

import com.company.securityanalyzer.TestConfiguration;
import com.company.securityanalyzer.TestUtils;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TraversalDetectorTest {

    @Test
    void shouldDetectEtcPasswdTraversal() {

        var config =
                TestConfiguration.config();

        var event =
                TestUtils.webEvent(
                        "203.0.113.5",
                        "/admin/../../../etc/passwd",
                        "400"
                );

        var incidents =
                new TraversalDetector(config)
                        .detect(List.of(event));

        assertEquals(
                1,
                incidents.size()
        );
    }

    @Test
    void shouldDetectParentDirectoryTraversal() {

        var config =
                TestConfiguration.config();

        var event =
                TestUtils.webEvent(
                        "203.0.113.5",
                        "/../../secret.txt",
                        "400"
                );

        var incidents =
                new TraversalDetector(config)
                        .detect(List.of(event));

        assertEquals(
                1,
                incidents.size()
        );
    }

    @Test
    void shouldIgnoreNormalPath() {

        var config =
                TestConfiguration.config();

        var event =
                TestUtils.webEvent(
                        "203.0.113.5",
                        "/products",
                        "200"
                );

        var incidents =
                new TraversalDetector(config)
                        .detect(List.of(event));

        assertTrue(
                incidents.isEmpty()
        );
    }

    @Test
    void shouldCreateIncidentForEachMatch() {

        var config =
                TestConfiguration.config();

        var incidents =
                new TraversalDetector(config)
                        .detect(
                                List.of(
                                        TestUtils.webEvent(
                                                "203.0.113.5",
                                                "/../../a",
                                                "400"
                                        ),
                                        TestUtils.webEvent(
                                                "203.0.113.5",
                                                "/../../b",
                                                "400"
                                        )
                                )
                        );

        assertEquals(
                2,
                incidents.size()
        );
    }
}