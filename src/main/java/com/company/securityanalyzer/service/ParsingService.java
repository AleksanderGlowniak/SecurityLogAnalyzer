package com.company.securityanalyzer.service;

import com.company.securityanalyzer.model.Event;
import com.company.securityanalyzer.model.ParseError;
import com.company.securityanalyzer.model.ParseResult;
import com.company.securityanalyzer.parser.AuthLogParser;
import com.company.securityanalyzer.parser.WebServerLogParser;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class ParsingService {

    public ParseResult parse(
            Path webLog,
            Path authLog
    ) {

        ParseResult web =
                new WebServerLogParser()
                        .parse(webLog);

        ParseResult auth =
                new AuthLogParser()
                        .parse(authLog);

        List<Event> events =
                new ArrayList<>();

        events.addAll(web.events());
        events.addAll(auth.events());

        List<ParseError> errors =
                new ArrayList<>();

        errors.addAll(web.errors());
        errors.addAll(auth.errors());

        return new ParseResult(
                events,
                errors
        );
    }
}