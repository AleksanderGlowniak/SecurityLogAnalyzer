package com.company.securityanalyzer.report;

import com.company.securityanalyzer.model.Incident;
import com.company.securityanalyzer.model.ParseError;

import java.util.List;

public record ReportSummary(
        int totalEvents,
        int totalIncidents,
        int totalParseErrors,
        List<Incident> incidents,
        List<ParseError> parseErrors
) {
}