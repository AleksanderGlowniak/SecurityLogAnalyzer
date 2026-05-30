package com.company.securityanalyzer.service;

import com.company.securityanalyzer.model.*;

import java.util.*;
import java.util.stream.Collectors;

public class ReconEscalationCorrelationRule
        implements CorrelationRule {

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

            boolean recon =
                    ipIncidents.stream()
                            .anyMatch(
                                    i ->
                                            i.title()
                                                    .contains(
                                                            "Recon"
                                                    )
                            );

            boolean traversal =
                    ipIncidents.stream()
                            .anyMatch(
                                    i ->
                                            i.title()
                                                    .contains(
                                                            "Directory Traversal"
                                                    )
                            );

            if (!(recon && traversal)) {
                continue;
            }

            Incident correlated =
                    new Incident(
                            Severity.CRITICAL,
                            "Active Exploitation Attempt",
                            "Reconnaissance followed by attack activity",
                            ip,
                            ipIncidents.stream()
                                    .flatMap(
                                            i ->
                                                    i.evidence()
                                                            .stream()
                                    )
                                    .toList()
                    );

            results.add(correlated);

            consumed.addAll(ipIncidents);
        }

        incidents.stream()
                .filter(
                        i ->
                                !consumed.contains(i)
                )
                .forEach(results::add);

        return results;
    }
}