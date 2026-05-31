package com.company.securityanalyzer.detector;

import com.company.securityanalyzer.config.RuleConfig;
import com.company.securityanalyzer.model.*;

import java.util.ArrayList;
import java.util.List;

public class TraversalDetector
        extends AbstractDetector {

    public TraversalDetector(
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

        for (Event e : events) {

            String path =
                    e.attributes()
                            .getOrDefault(
                                    "path",
                                    ""
                            );

            for (String pattern :
                    config.getTraversalPatterns()) {

                if (path.contains(pattern)) {

                    incidents.add(
                            new Incident(
                                    Severity.HIGH,
                                    "Directory Traversal",
                                    "Traversal pattern detected",
                                    e.sourceIp(),
                                    e.timestamp(),
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