package com.company.securityanalyzer.service;

import com.company.securityanalyzer.config.RuleConfig;
import com.company.securityanalyzer.model.Incident;

import java.util.ArrayList;
import java.util.List;

public class CorrelationEngine {

    private final List<CorrelationRule> rules;

    public CorrelationEngine(
            RuleConfig config
    ) {

        this.rules = List.of(
                new CredentialAttackCorrelationRule(),
                new ReconEscalationCorrelationRule(
                        config
                )
        );
    }

    public List<Incident> correlate(
            List<Incident> incidents
    ) {

        List<Incident> current =
                new ArrayList<>(incidents);

        for (CorrelationRule rule : rules) {

            current =
                    rule.correlate(current);
        }

        return current;
    }
}