package com.company.securityanalyzer;

import com.company.securityanalyzer.model.ParseResult;
import com.company.securityanalyzer.parser.AuthLogParser;
import com.company.securityanalyzer.parser.WebServerLogParser;
import com.company.securityanalyzer.service.AutoDetectParsingService;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

public class Main {

    public static void main(String[] args) {

        if (args.length == 0) {

            System.err.println(
                    "Usage: analyzer <log files>"
            );

            System.exit(1);
        }

        List<Path> files =
                Arrays.stream(args)
                        .map(Path::of)
                        .toList();

        AutoDetectParsingService parser =
                new AutoDetectParsingService(
                        List.of(
                                new WebServerLogParser(),
                                new AuthLogParser()
                        )
                );

        ParseResult result =
                parser.parse(files);

        System.out.printf(
                "Parsed %d events%n",
                result.events().size()
        );

        System.out.printf(
                "Found %d parse errors%n",
                result.errors().size()
        );
    }
}