package com.company.securityanalyzer.service;

import com.company.securityanalyzer.model.Event;
import com.company.securityanalyzer.model.ParseError;
import com.company.securityanalyzer.model.ParseResult;
import com.company.securityanalyzer.parser.AuthLogParser;
import com.company.securityanalyzer.parser.LogParser;
import com.company.securityanalyzer.parser.ParserDetectionException;
import com.company.securityanalyzer.parser.WebServerLogParser;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class AutoDetectParsingService {

    private final List<LogParser> parsers;

    public AutoDetectParsingService(
            List<LogParser> parsers
    ) {
        this.parsers = parsers;
    }

    public ParseResult parse(List<Path> files) {

        List<Event> allEvents = new ArrayList<>();
        List<ParseError> allErrors = new ArrayList<>();

        for (Path file : files) {

            LogParser parser =
                    detectParser(file);

            ParseResult result =
                    parser.parse(file);

            allEvents.addAll(result.events());
            allErrors.addAll(result.errors());
        }

        return new ParseResult(
                allEvents,
                allErrors
        );
    }

    private LogParser detectParser(Path file) {

        String fileName =
                file.getFileName()
                        .toString()
                        .toLowerCase();

        if (fileName.contains("web")) {
            return parsers.stream()
                    .filter(WebServerLogParser.class::isInstance)
                    .findFirst()
                    .orElseThrow();
        }

        if (fileName.contains("auth")) {
            return parsers.stream()
                    .filter(AuthLogParser.class::isInstance)
                    .findFirst()
                    .orElseThrow();
        }

        return parsers.stream()
                .filter(p -> p.supports(file))
                .findFirst()
                .orElseThrow(
                        () -> new ParserDetectionException(
                                "No parser found for " + file
                        )
                );
    }
}