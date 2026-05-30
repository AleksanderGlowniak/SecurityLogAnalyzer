package com.company.securityanalyzer.detector;

import com.company.securityanalyzer.config.RuleConfig;
import com.company.securityanalyzer.model.*;

import java.util.*;
import java.util.stream.Collectors;

public class BruteForceDetector
        extends AbstractDetector {

    public BruteForceDetector(
            RuleConfig config
    ) {
        super(config);
    }

    @Override
    public List<Incident> detect(
            List<Event> events
    ) {

        List<Incident> incidents =
                new ArrayList<>();

        Map<String, List<Event>> byIp =
                events.stream()
                        .collect(
                                Collectors.groupingBy(
                                        Event::sourceIp
                                )
                        );

        for (var entry : byIp.entrySet()) {

            String ip = entry.getKey();

            List<Event> ipEvents =
                    entry.getValue();

            long failures =
                    ipEvents.stream()
                            .filter(
                                    e ->
                                            e.eventType() ==
                                                    EventType.SSH_FAILED_LOGIN
                                                    ||
                                                    e.eventType() ==
                                                            EventType.WEB_LOGIN_FAILURE
                            )
                            .count();

            boolean success =
                    ipEvents.stream()
                            .anyMatch(
                                    e ->
                                            e.eventType() ==
                                                    EventType.SSH_SUCCESS_LOGIN
                                                    ||
                                                    e.eventType() ==
                                                            EventType.WEB_LOGIN_SUCCESS
                            );

            if (failures >=
                    config.getFailedLoginThreshold()
                    && success) {

                incidents.add(
                        new Incident(
                                Severity.CRITICAL,
                                "Credential Attack",
                                "Repeated failures followed by success",
                                ip,
                                List.of(
                                        failures
                                                + " failures",
                                        "Successful login observed"
                                )
                        )
                );
            }
        }

        return incidents;
    }
}