package com.company.securityanalyzer.service;

import com.company.securityanalyzer.config.RuleConfig;
import com.company.securityanalyzer.model.*;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

public class ReconEscalationCorrelationRule
        implements CorrelationRule {

    private final RuleConfig config;

    public ReconEscalationCorrelationRule(
            RuleConfig config
    ) {
        this.config = config;
    }

    @Override
    public List<Incident> correlate(
            List<Incident> incidents
    ) {

        Map<String, List<Incident>> byIp =
                incidents.stream()
                        .collect(
                                Collectors.groupingBy(
                                        Incident::sourceIp
                                )
                        );

        List<Incident> results =
                new ArrayList<>();

        Set<Incident> consumed =
                new HashSet<>();

        for (var entry : byIp.entrySet()) {

            String ip =
                    entry.getKey();

            List<Incident> ipIncidents =
                    entry.getValue();

            List<Incident> reconIncidents =
                    ipIncidents.stream()
                            .filter(
                                    i ->
                                            i.title()
                                                    .contains(
                                                            "Recon"
                                                    )
                            )
                            .toList();

            List<Incident> traversalIncidents =
                    ipIncidents.stream()
                            .filter(
                                    i ->
                                            i.title()
                                                    .contains(
                                                            "Directory Traversal"
                                                    )
                            )
                            .toList();

            boolean correlated =
                    reconIncidents.stream()
                            .anyMatch(
                                    reconIncident ->
                                            traversalIncidents.stream()
                                                    .anyMatch(
                                                            traversalIncident ->
                                                                    Math.abs(
                                                                            Duration.between(
                                                                                    reconIncident.firstSeen(),
                                                                                    traversalIncident.firstSeen()
                                                                            ).toMinutes()
                                                                    )
                                                                            <= config.getReconTraversalWindowMinutes()
                                                    )
                            );

            if (!correlated) {
                continue;
            }

            LocalDateTime firstSeen =
                    ipIncidents.stream()
                            .map(
                                    Incident::firstSeen
                            )
                            .filter(
                                    Objects::nonNull
                            )
                            .min(
                                    LocalDateTime::compareTo
                            )
                            .orElse(null);

            Incident correlatedIncident =
                    new Incident(
                            Severity.CRITICAL,
                            "Active Exploitation Attempt",
                            "Reconnaissance followed by attack activity",
                            ip,
                            firstSeen,
                            ipIncidents.stream()
                                    .flatMap(
                                            i ->
                                                    i.evidence()
                                                            .stream()
                                    )
                                    .toList()
                    );

            results.add(
                    correlatedIncident
            );

            consumed.addAll(
                    reconIncidents
            );

            consumed.addAll(
                    traversalIncidents
            );
        }

        incidents.stream()
                .filter(
                        i ->
                                !consumed.contains(i)
                )
                .forEach(
                        results::add
                );

        return results;
    }
}