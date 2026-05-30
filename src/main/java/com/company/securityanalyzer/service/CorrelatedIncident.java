package com.company.securityanalyzer.service;

import com.company.securityanalyzer.model.Incident;

import java.util.List;

public record CorrelatedIncident(
        Incident primaryIncident,
        List<Incident> relatedIncidents

) {
}
