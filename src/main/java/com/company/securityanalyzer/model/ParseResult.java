package com.company.securityanalyzer.model;

import java.util.List;

public record ParseResult(
        List<Event> events,
        List<ParseError> errors
) {
}
