package com.company.securityanalyzer;

import com.company.securityanalyzer.config.ConfigLoader;
import com.company.securityanalyzer.config.RuleConfig;
import com.company.securityanalyzer.model.ParseResult;
import com.company.securityanalyzer.parser.AuthLogParser;
import com.company.securityanalyzer.parser.WebServerLogParser;
import com.company.securityanalyzer.report.*;
import com.company.securityanalyzer.service.AutoDetectParsingService;
import com.company.securityanalyzer.service.DetectionService;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

public class Main {

    public static void main(
            String[] args
    ) {

        RuleConfig config =
                ConfigLoader.load(
                        Path.of(
                                "src/main/resources/rules.yaml"
                        )
                );

        AutoDetectParsingService parser =
                new AutoDetectParsingService(
                        List.of(
                                new WebServerLogParser(),
                                new AuthLogParser()
                        )
                );

        ParseResult result =
                parser.parse(
                        Arrays.stream(args)
                                .map(Path::of)
                                .toList()
                );

        DetectionService detectionService =
                new DetectionService(config);

        var incidents =
                detectionService.detect(
                        result.events()
                );

        ReportSummary report =
                new ReportBuilder()
                        .build(
                                result.events().size(),
                                incidents,
                                result.errors()
                        );

        new StandardConsoleReporter()
                .print(report);
    }
}


