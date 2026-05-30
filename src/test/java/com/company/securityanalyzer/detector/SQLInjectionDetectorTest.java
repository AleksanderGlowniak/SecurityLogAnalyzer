package com.company.securityanalyzer.detector;

import com.company.securityanalyzer.TestConfiguration;
import com.company.securityanalyzer.TestUtils;
import com.company.securityanalyzer.config.RuleConfig;
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
}