package com.company.securityanalyzer.service;

import com.company.securityanalyzer.model.Incident;

import java.util.List;

public interface CorrelationRule {

    List<Incident> correlate(
            List<Incident> incidents
    );
}
