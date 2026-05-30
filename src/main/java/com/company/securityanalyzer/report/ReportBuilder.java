package com.company.securityanalyzer.report;

import com.company.securityanalyzer.model.Incident;
import com.company.securityanalyzer.model.ParseError;

import java.util.List;

public class ReportBuilder {

    public ReportSummary build(
            int totalEvents,
            List<Incident> incidents,
            List<ParseError> errors
    ) {

        return new ReportSummary(
                totalEvents,
                incidents.size(),
                errors.size(),
                incidents,
                errors
        );
    }
}