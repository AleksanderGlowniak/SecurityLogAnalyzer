package com.company.securityanalyzer.parser;

import com.company.securityanalyzer.model.ParseResult;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.regex.Matcher;

import static org.junit.jupiter.api.Assertions.*;

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

        System.out.println(
                "events=" + result.events().size()
        );

        System.out.println(
                "errors=" + result.errors().size()
        );

        assertEquals(
                32,
                result.events().size()
        );
    }

    @Test
    void regexShouldMatch() {

        String line =
                "192.168.1.10 - - [03/Jul/2025:10:00:01 +0000] \"GET /index.html HTTP/1.1\" 200 1234";

        Matcher m =
                WebServerLogParser.WEB_LOG_PATTERN.matcher(line);

        assertTrue(m.matches());
    }
}
