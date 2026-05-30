package com.company.securityanalyzer.config;

public class RuleConfigurationException extends RuntimeException {

    public RuleConfigurationException(String message) {
        super(message);
    }

    public RuleConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}