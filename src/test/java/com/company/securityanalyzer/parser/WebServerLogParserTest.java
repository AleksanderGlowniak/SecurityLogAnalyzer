package com.company.securityanalyzer.parser;

import com.company.securityanalyzer.model.ParseResult;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

    @Test
    void shouldCaptureMalformedEntry() {

        ParseResult result =
                new WebServerLogParser()
                        .parse(
                                Path.of(
                                        "src/test/resources/malformed.log"
                                )
                        );

        assertEquals(
                1,
                result.errors().size()
        );
    }

    @Test
    void shouldParseWebLogEntry() {

        var result =
                new WebServerLogParser()
                        .parse(
                                Path.of(
                                        "src/test/resources/webserver.log"
                                )
                        );

        assertEquals(
                1,
                result.events().size()
        );
    }
}
