package com.company.securityanalyzer.model;

public record ParseError(
        String source,
        long lineNumber,
        String rawLine,
        String reason
) {
}