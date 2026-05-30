package com.company.securityanalyzer.detector;

import com.company.securityanalyzer.config.RuleConfig;
import com.company.securityanalyzer.model.*;

import java.util.*;
import java.util.stream.Collectors;

public class ReconDetector
        extends AbstractDetector {

    public ReconDetector(
            RuleConfig config
    ) {
        super(config);
    }

    @Override
    public List<Incident> detect(
            List<Event> events
    ) {

        Map<String, Set<String>> pathsByIp =
                new HashMap<>();

        for (Event e : events) {

            String path =
                    e.attributes()
                            .getOrDefault(
                                    "path",
                                    ""
                            );

            if (config.getSensitivePaths()
                    .contains(path)) {

                pathsByIp
                        .computeIfAbsent(
                                e.sourceIp(),
                                k -> new HashSet<>()
                        )
                        .add(path);
            }
        }

        return pathsByIp.entrySet()
                .stream()
                .filter(
                        e ->
                                e.getValue().size()
                                        >= config.getAdminProbeThreshold()
                )
                .map(
                        e ->
                                new Incident(
                                        Severity.HIGH,
                                        "Reconnaissance Activity",
                                        "Sensitive endpoint enumeration",
                                        e.getKey(),
                                        e.getValue()
                                                .stream()
                                                .toList()
                                )
                )
                .collect(
                        Collectors.toList()
                );
    }
}