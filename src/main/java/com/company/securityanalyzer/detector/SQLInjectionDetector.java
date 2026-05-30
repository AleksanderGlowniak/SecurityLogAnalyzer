package com.company.securityanalyzer.detector;

import com.company.securityanalyzer.config.RuleConfig;
import com.company.securityanalyzer.model.*;

import java.util.ArrayList;
import java.util.List;

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

        List<Incident> incidents =
                new ArrayList<>();

        for (Event event : events) {

            String path =
                    event.attributes()
                            .getOrDefault(
                                    "path",
                                    ""
                            );

            String upper =
                    path.toUpperCase();

            for (String pattern :
                    config.getSqlInjectionPatterns()) {

                if (upper.contains(
                        pattern.toUpperCase()
                )) {

                    incidents.add(
                            new Incident(
                                    Severity.HIGH,
                                    "SQL Injection Attempt",
                                    "Detected SQLi payload",
                                    event.sourceIp(),
                                    List.of(path)
                            )
                    );

                    break;
                }
            }
        }

        return incidents;
    }
}