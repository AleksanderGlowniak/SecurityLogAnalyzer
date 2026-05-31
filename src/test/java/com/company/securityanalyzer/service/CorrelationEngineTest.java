package com.company.securityanalyzer.service;

import com.company.securityanalyzer.config.RuleConfig;
import com.company.securityanalyzer.model.Incident;
import com.company.securityanalyzer.model.Severity;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CorrelationEngineTest {

    @Test
    void shouldCorrelateReconAndTraversal() {

        LocalDateTime ts =
                LocalDateTime.of(
                        2025,
                        1,
                        1,
                        12,
                        0
                );

        Incident recon =
                new Incident(
                        Severity.HIGH,
                        "Reconnaissance Activity",
                        "",
                        "203.0.113.5",
                        ts,
                        List.of()
                );

        Incident traversal =
                new Incident(
                        Severity.HIGH,
                        "Directory Traversal",
                        "",
                        "203.0.113.5",
                        ts.plusMinutes(3),
                        List.of()
                );

        RuleConfig config =
                new RuleConfig();

        config.setReconTraversalWindowMinutes(
                5
        );

        CorrelationEngine engine =
                new CorrelationEngine(
                        config
                );

        List<Incident> result =
                engine.correlate(
                        List.of(
                                recon,
                                traversal
                        )
                );

        assertTrue(
                result.stream()
                        .anyMatch(
                                i ->
                                        i.title()
                                                .contains(
                                                        "Active Exploitation"
                                                )
                        )
        );
    }

    @Test
    void shouldNotCorrelateWhenOutsideWindow() {

        LocalDateTime ts =
                LocalDateTime.of(
                        2025,
                        1,
                        1,
                        12,
                        0
                );

        Incident recon =
                new Incident(
                        Severity.HIGH,
                        "Reconnaissance Activity",
                        "",
                        "203.0.113.5",
                        ts,
                        List.of()
                );

        Incident traversal =
                new Incident(
                        Severity.HIGH,
                        "Directory Traversal",
                        "",
                        "203.0.113.5",
                        ts.plusMinutes(10),
                        List.of()
                );

        RuleConfig config =
                new RuleConfig();

        config.setReconTraversalWindowMinutes(
                5
        );

        CorrelationEngine engine =
                new CorrelationEngine(
                        config
                );

        List<Incident> result =
                engine.correlate(
                        List.of(
                                recon,
                                traversal
                        )
                );

        assertFalse(
                result.stream()
                        .anyMatch(
                                i ->
                                        i.title()
                                                .contains(
                                                        "Active Exploitation"
                                                )
                        )
        );
    }
}
