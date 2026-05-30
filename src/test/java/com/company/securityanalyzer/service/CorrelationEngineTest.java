package com.company.securityanalyzer.service;

import com.company.securityanalyzer.model.Incident;
import com.company.securityanalyzer.model.Severity;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class CorrelationEngineTest {

    @Test
    void shouldCorrelateReconAndTraversal() {

        Incident recon =
                new Incident(
                        Severity.HIGH,
                        "Reconnaissance Activity",
                        "",
                        "203.0.113.5",
                        List.of()
                );

        Incident traversal =
                new Incident(
                        Severity.HIGH,
                        "Directory Traversal",
                        "",
                        "203.0.113.5",
                        List.of()
                );

        CorrelationEngine engine =
                new CorrelationEngine();

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
}
