package com.company.securityanalyzer.model;

import java.time.LocalDateTime;
import java.util.Map;

public record Event(
        LocalDateTime timestamp,
        String sourceIp,
        EventType eventType,
        Map<String, String> attributes,
        String rawLine
) {

}