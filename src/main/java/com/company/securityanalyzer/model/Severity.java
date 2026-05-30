package com.company.securityanalyzer.model;

public enum Severity {

    CRITICAL(5),
    HIGH(4),
    MEDIUM(3),
    LOW(2),
    INFO(1);

    private final int priority;

    Severity(int priority) {
        this.priority = priority;
    }

    public int priority() {
        return priority;
    }
}