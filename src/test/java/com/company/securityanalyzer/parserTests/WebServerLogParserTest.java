package com.company.securityanalyzer.parserTests;

import com.company.securityanalyzer.model.ParseResult;
import com.company.securityanalyzer.parser.WebServerLogParser;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;

public class WebServerLogParserTest {
    @Test
    void shouldParseValidWebLog() {

        ParseResult result =
                new WebServerLogParser()
                        .parse(
                                Path.of(
                                        "src/test/resources/web.log"
                                )
                        );

        assertFalse(
                result.events().isEmpty()
        );
    }
}
