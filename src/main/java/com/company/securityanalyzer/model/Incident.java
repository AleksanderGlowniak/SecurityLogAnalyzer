package com.company.securityanalyzer.model;

import java.util.List;

public record Incident(
        Severity severity,
        String title,
        String description,
        String sourceIp,
        List<String> evidence
) {
}