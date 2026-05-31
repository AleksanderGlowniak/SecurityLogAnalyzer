package com.company.securityanalyzer.detector;

import com.company.securityanalyzer.config.RuleConfig;
import com.company.securityanalyzer.model.*;

import java.time.LocalDateTime;
import java.util.*;

public class SQLInjectionDetector
        extends AbstractDetector {

    public SQLInjectionDetector(
            RuleConfig config
    ) {
        super(config);
    }

    @Override
    public List<Incident> detect(
            List<Event> events
    ) {

        Map<String, List<String>> evidenceByIp =
                new HashMap<>();

        Map<String, LocalDateTime> firstSeenByIp =
                new HashMap<>();

        for (Event event : events) {

            String path =
                    event.attributes()
                            .getOrDefault(
                                    "path",
                                    ""
                            );

            String upper =
                    path.toUpperCase();

            boolean matched = false;

            for (String pattern :
                    config.getSqlInjectionPatterns()) {

                if (upper.contains(
                        pattern.toUpperCase()
                )) {

                    matched = true;
                    break;
                }
            }

            if (matched) {

                evidenceByIp
                        .computeIfAbsent(
                                event.sourceIp(),
                                ip -> new ArrayList<>()
                        )
                        .add(path);

                firstSeenByIp.merge(
                        event.sourceIp(),
                        event.timestamp(),
                        (a, b) ->
                                a.isBefore(b)
                                        ? a
                                        : b
                );
            }
        }

        List<Incident> incidents =
                new ArrayList<>();

        for (var entry : evidenceByIp.entrySet()) {

            incidents.add(
                    new Incident(
                            Severity.HIGH,
                            "SQL Injection",
                            "SQL injection payloads detected",
                            entry.getKey(),
                            firstSeenByIp.get(
                                    entry.getKey()
                            ),
                            entry.getValue()
                    )
            );
        }

        return incidents;
    }
}