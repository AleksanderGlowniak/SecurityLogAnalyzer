package com.company.securityanalyzer.report;

import com.company.securityanalyzer.model.Incident;
import com.company.securityanalyzer.model.ParseError;
import com.company.securityanalyzer.model.Severity;

import java.util.Map;
import java.util.stream.Collectors;

public class StandardConsoleReporter
        implements ConsoleReporter {

    private static final String SEPARATOR =
            "=".repeat(60);

    private static final String SUB_SEPARATOR =
            "-".repeat(60);

    @Override
    public void print(
            ReportSummary report
    ) {

        printHeader();

        printSummary(report);

        printSeverityBreakdown(report);

        printIncidents(report);

        printParseErrors(report);
    }

    private void printHeader() {

        System.out.println(SEPARATOR);
        System.out.println("SECURITY INCIDENT REPORT");
        System.out.println(SEPARATOR);
        System.out.println();
    }

    private void printSummary(
            ReportSummary report
    ) {

        System.out.println("Summary");
        System.out.println(SUB_SEPARATOR);

        System.out.printf(
                "Events Processed : %d%n",
                report.totalEvents()
        );

        System.out.printf(
                "Parse Errors     : %d%n",
                report.totalParseErrors()
        );

        System.out.printf(
                "Incidents Found  : %d%n",
                report.totalIncidents()
        );

        System.out.println();
    }

    private void printSeverityBreakdown(
            ReportSummary report
    ) {

        Map<Severity, Long> counts =
                report.incidents()
                        .stream()
                        .collect(
                                Collectors.groupingBy(
                                        Incident::severity,
                                        Collectors.counting()
                                )
                        );

        System.out.println(
                "Severity Breakdown"
        );

        System.out.println(
                SUB_SEPARATOR
        );

        for (Severity severity :
                Severity.values()) {

            long count =
                    counts.getOrDefault(
                            severity,
                            0L
                    );

            System.out.printf(
                    "%-8s : %d%n",
                    severity,
                    count
            );
        }

        System.out.println();
    }

    private void printIncidents(
            ReportSummary report
    ) {

        for (Incident incident :
                report.incidents()) {

            System.out.println(SEPARATOR);

            System.out.printf(
                    "[%s] %s%n",
                    incident.severity(),
                    incident.title()
            );

            System.out.println(
                    SEPARATOR
            );

            System.out.println();

            System.out.println(
                    "Source IP:"
            );

            System.out.println(
                    incident.sourceIp()
            );

            System.out.println();

            System.out.println(
                    "Description:"
            );

            System.out.println(
                    incident.description()
            );

            System.out.println();

            System.out.println(
                    "Evidence:"
            );

            incident.evidence()
                    .forEach(
                            e ->
                                    System.out.println(
                                            " - " + e
                                    )
                    );

            System.out.println();
        }
    }

    private void printParseErrors(
            ReportSummary report
    ) {

        if (report.parseErrors()
                .isEmpty()) {
            return;
        }

        System.out.println(SEPARATOR);

        System.out.println(
                "PARSE ERRORS"
        );

        System.out.println(SEPARATOR);

        for (ParseError error :
                report.parseErrors()) {

            System.out.printf(
                    "Line %d : %s%n",
                    error.lineNumber(),
                    error.reason()
            );
        }
    }
}