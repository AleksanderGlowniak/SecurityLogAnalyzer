package com.company.securityanalyzer.service;

import com.company.securityanalyzer.model.*;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

public class CredentialAttackCorrelationRule
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

            boolean credentialAttack =
                    ipIncidents.stream()
                            .anyMatch(
                                    i ->
                                            i.title()
                                                    .contains(
                                                            "Credential Attack"
                                                    )
                            );

            if (!credentialAttack) {
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

            Incident merged =
                    new Incident(
                            Severity.CRITICAL,
                            "Multi-Vector Credential Attack",
                            "Correlated login abuse across services",
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

            results.add(merged);

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