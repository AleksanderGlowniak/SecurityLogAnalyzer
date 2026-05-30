package com.company.securityanalyzer.detector;

import com.company.securityanalyzer.config.RuleConfig;
import com.company.securityanalyzer.model.*;

import java.util.*;
import java.util.stream.Collectors;

public class ApiAbuseDetector
        extends AbstractDetector {

    public ApiAbuseDetector(
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
                        .filter(
                                e ->
                                        "/api/users".equals(
                                                e.attributes()
                                                        .get("path")
                                        )
                        )
                        .collect(
                                Collectors.groupingBy(
                                        Event::sourceIp
                                )
                        );

        for (var entry : byIp.entrySet()) {

            String ip =
                    entry.getKey();

            List<Event> requests =
                    entry.getValue();

            boolean rateLimited =
                    requests.stream()
                            .anyMatch(
                                    e ->
                                            "429".equals(
                                                    e.attributes()
                                                            .get(
                                                                    "status"
                                                            )
                                            )
                            );

            if (requests.size()
                    >= config.getRequestBurstThreshold()
                    && rateLimited) {

                incidents.add(
                        new Incident(
                                Severity.MEDIUM,
                                "API Abuse",
                                "Burst activity followed by rate limiting",
                                ip,
                                List.of(
                                        requests.size()
                                                + " requests"
                                )
                        )
                );
            }
        }

        return incidents;
    }
}