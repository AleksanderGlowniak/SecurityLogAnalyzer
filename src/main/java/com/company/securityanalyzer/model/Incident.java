package com.company.securityanalyzer.model;

import java.time.LocalDateTime;
import java.util.List;

public record Incident(
        Severity severity,
        String title,
        String description,
        String sourceIp,
        LocalDateTime firstSeen,
        List<String> evidence
) {
}