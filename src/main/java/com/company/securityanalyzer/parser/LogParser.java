package com.company.securityanalyzer.parser;

import com.company.securityanalyzer.model.ParseResult;

import java.nio.file.Path;

public interface LogParser {

    ParseResult parse(Path logFile);

}