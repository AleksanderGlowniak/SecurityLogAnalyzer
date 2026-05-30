package com.company.securityanalyzer.service;

import com.company.securityanalyzer.config.RuleConfig;
import com.company.securityanalyzer.detector.*;
import com.company.securityanalyzer.model.Event;
import com.company.securityanalyzer.model.Incident;

import java.util.ArrayList;
import java.util.List;

public class DetectionService {

    private final List<Detector> detectors;

    public DetectionService(
            RuleConfig config
    ) {

        detectors = List.of(
                new BruteForceDetector(config),
                new SQLInjectionDetector(config),
                new ReconDetector(config),
                new TraversalDetector(config),
                new ApiAbuseDetector(config),
                new PrivilegeEscalationDetector(config)
        );
    }

    public List<Incident> detect(
            List<Event> events
    ) {

        List<Incident> incidents =
                new ArrayList<>();

        for (Detector detector : detectors) {

            incidents.addAll(
                    detector.detect(events)
            );
        }

        CorrelationEngine correlation =
                new CorrelationEngine();

        incidents =
                correlation.correlate(
                        incidents
                );

        incidents.sort(
                (a, b) ->
                        Integer.compare(
                                b.severity().priority(),
                                a.severity().priority()
                        )
        );

        return incidents;
    }
}