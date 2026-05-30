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
}