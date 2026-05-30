package com.company.securityanalyzer.parser;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

public final class ParserUtils {

    private ParserUtils() {
    }

    public static LocalDateTime defaultTimestamp() {
        return LocalDateTime.now(ZoneOffset.UTC);
    }
}