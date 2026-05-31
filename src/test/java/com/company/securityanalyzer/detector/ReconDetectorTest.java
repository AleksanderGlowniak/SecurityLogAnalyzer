package com.company.securityanalyzer.detector;

import com.company.securityanalyzer.TestConfiguration;
import com.company.securityanalyzer.TestUtils;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ReconDetectorTest {

    @Test
    void shouldDetectEnumeration() {

        var config =
                TestConfiguration.config();

        var incidents =
                new ReconDetector(config)
                        .detect(
                                List.of(
                                        TestUtils.webEvent(
                                                "1.1.1.1",
                                                "/admin",
                                                "403"
                                        ),
                                        TestUtils.webEvent(
                                                "1.1.1.1",
                                                "/phpmyadmin",
                                                "404"
                                        ),
                                        TestUtils.webEvent(
                                                "1.1.1.1",
                                                "/wp-admin",
                                                "404"
                                        )
                                )
                        );

        assertEquals(
                1,
                incidents.size()
        );
    }

    @Test
    void shouldIgnoreDuplicatePaths() {

        var config =
                TestConfiguration.config();

        var incidents =
                new ReconDetector(config)
                        .detect(
                                List.of(
                                        TestUtils.webEvent(
                                                "1.1.1.1",
                                                "/admin",
                                                "403"
                                        ),
                                        TestUtils.webEvent(
                                                "1.1.1.1",
                                                "/admin",
                                                "403"
                                        ),
                                        TestUtils.webEvent(
                                                "1.1.1.1",
                                                "/admin",
                                                "403"
                                        )
                                )
                        );

        assertTrue(
                incidents.isEmpty()
        );
    }

    @Test
    void shouldIgnoreNonSensitivePaths() {

        var config =
                TestConfiguration.config();

        var incidents =
                new ReconDetector(config)
                        .detect(
                                List.of(
                                        TestUtils.webEvent(
                                                "1.1.1.1",
                                                "/home",
                                                "200"
                                        ),
                                        TestUtils.webEvent(
                                                "1.1.1.1",
                                                "/products",
                                                "200"
                                        ),
                                        TestUtils.webEvent(
                                                "1.1.1.1",
                                                "/contact",
                                                "200"
                                        )
                                )
                        );

        assertTrue(
                incidents.isEmpty()
        );
    }

    @Test
    void shouldNotDetectBelowThreshold() {

        var config =
                TestConfiguration.config();

        var incidents =
                new ReconDetector(config)
                        .detect(
                                List.of(
                                        TestUtils.webEvent(
                                                "1.1.1.1",
                                                "/admin",
                                                "403"
                                        ),
                                        TestUtils.webEvent(
                                                "1.1.1.1",
                                                "/phpmyadmin",
                                                "404"
                                        )
                                )
                        );

        assertTrue(
                incidents.isEmpty()
        );
    }
}