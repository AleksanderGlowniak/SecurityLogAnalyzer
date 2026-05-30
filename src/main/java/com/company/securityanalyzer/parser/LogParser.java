package com.company.securityanalyzer.parser;

import com.company.securityanalyzer.model.ParseResult;

import java.nio.file.Path;

public interface LogParser {

    /**
     * Determines whether this parser can handle
     * the supplied file.
     */
    boolean supports(Path file);

    /**
     * Parse the file.
     */
    ParseResult parse(Path file);
}