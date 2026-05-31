package com.company.securityanalyzer.detector;

import com.company.securityanalyzer.TestConfiguration;
import com.company.securityanalyzer.TestUtils;
import com.company.securityanalyzer.config.RuleConfig;
import com.company.securityanalyzer.model.Incident;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SQLInjectionDetectorTest {

    @Test
    void shouldDetectUnionSelect() {

        RuleConfig config =
                TestConfiguration.config();

        var event =
                TestUtils.webEvent(
                        "10.0.0.88",
                        "/search?q=' UNION SELECT * FROM users--",
                        "200"
                );

        var incidents =
                new SQLInjectionDetector(config)
                        .detect(List.of(event));

        assertEquals(
                1,
                incidents.size()
        );
    }

    @Test
    void shouldDetectCaseInsensitivePayload() {

        RuleConfig config =
                TestConfiguration.config();

        var event =
                TestUtils.webEvent(
                        "10.0.0.88",
                        "/search?q=union select password",
                        "200"
                );

        var incidents =
                new SQLInjectionDetector(config)
                        .detect(List.of(event));

        assertEquals(
                1,
                incidents.size()
        );
    }

    @Test
    void shouldIgnoreNormalRequests() {

        RuleConfig config =
                TestConfiguration.config();

        var event =
                TestUtils.webEvent(
                        "10.0.0.88",
                        "/products?id=1",
                        "200"
                );

        var incidents =
                new SQLInjectionDetector(config)
                        .detect(List.of(event));

        assertTrue(
                incidents.isEmpty()
        );
    }

    @Test
    void shouldAggregateEvidencePerIp() {

        RuleConfig config =
                TestConfiguration.config();

        var incidents =
                new SQLInjectionDetector(config)
                        .detect(
                                List.of(
                                        TestUtils.webEvent(
                                                "10.0.0.88",
                                                "/a?q=UNION SELECT",
                                                "200"
                                        ),
                                        TestUtils.webEvent(
                                                "10.0.0.88",
                                                "/b?q=DROP TABLE users",
                                                "200"
                                        )
                                )
                        );

        assertEquals(
                1,
                incidents.size()
        );

        assertEquals(
                2,
                incidents.get(0)
                        .evidence()
                        .size()
        );
    }
}