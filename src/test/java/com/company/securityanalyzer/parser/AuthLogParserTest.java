package com.company.securityanalyzer.parser;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuthLogParserTest {

    @Test
    void shouldParseFailedLogin() {

        var result =
                new AuthLogParser()
                        .parse(
                                Path.of(
                                        "src/test/resources/auth.log"
                                )
                        );

        assertEquals(
                1,
                result.events().size()
        );
    }
}