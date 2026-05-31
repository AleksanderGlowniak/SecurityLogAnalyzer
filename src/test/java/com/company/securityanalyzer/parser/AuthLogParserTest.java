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
        System.out.println(
                "events=" + result.events().size()
        );

        System.out.println(
                "errors=" + result.errors().size()
        );

        assertEquals(
                11,
                result.events().size()
        );
    }
}