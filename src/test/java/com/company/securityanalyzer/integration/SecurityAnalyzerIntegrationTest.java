package com.company.securityanalyzer.integration;

import com.company.securityanalyzer.config.*;
import com.company.securityanalyzer.parser.AuthLogParser;
import com.company.securityanalyzer.parser.WebServerLogParser;
import com.company.securityanalyzer.service.*;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SecurityAnalyzerIntegrationTest {

    @Test
    void shouldDetectRealSecurityIncidents() {

        RuleConfig config =
                ConfigLoader.load(
                        Path.of(
                                "src/main/resources/rules.yaml"
                        )
                );

        var parser =
                new AutoDetectParsingService(
                        List.of(
                                new WebServerLogParser(),
                                new AuthLogParser()
                        )
                );

        var parsed =
                parser.parse(
                        List.of(
                                Path.of(
                                        "src/test/resources/webserver.log"
                                ),
                                Path.of(
                                        "src/test/resources/auth.log"
                                )
                        )
                );

        var detection =
                new DetectionService(
                        config
                );

        var incidents =
                detection.detect(
                        parsed.events()
                );

        assertFalse(
                incidents.isEmpty()
        );

        assertTrue(
                incidents.size() >= 4
        );
    }
}