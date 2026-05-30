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
}