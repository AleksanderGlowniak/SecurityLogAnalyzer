package com.company.securityanalyzer.config;

import java.util.List;

public class RuleConfig {

    private int failedLoginThreshold;
    private int adminProbeThreshold;
    private int requestBurstThreshold;

    private List<String> sqlInjectionPatterns;
    private List<String> traversalPatterns;
    private List<String> sensitivePaths;
    private List<String> sensitiveCommands;

    public int getFailedLoginThreshold() {
        return failedLoginThreshold;
    }

    public void setFailedLoginThreshold(int failedLoginThreshold) {
        this.failedLoginThreshold = failedLoginThreshold;
    }

    public int getAdminProbeThreshold() {
        return adminProbeThreshold;
    }

    public void setAdminProbeThreshold(int adminProbeThreshold) {
        this.adminProbeThreshold = adminProbeThreshold;
    }

    public int getRequestBurstThreshold() {
        return requestBurstThreshold;
    }

    public void setRequestBurstThreshold(int requestBurstThreshold) {
        this.requestBurstThreshold = requestBurstThreshold;
    }

    public List<String> getSqlInjectionPatterns() {
        return sqlInjectionPatterns;
    }

    public void setSqlInjectionPatterns(List<String> sqlInjectionPatterns) {
        this.sqlInjectionPatterns = sqlInjectionPatterns;
    }

    public List<String> getTraversalPatterns() {
        return traversalPatterns;
    }

    public void setTraversalPatterns(List<String> traversalPatterns) {
        this.traversalPatterns = traversalPatterns;
    }

    public List<String> getSensitivePaths() {
        return sensitivePaths;
    }

    public void setSensitivePaths(List<String> sensitivePaths) {
        this.sensitivePaths = sensitivePaths;
    }

    public List<String> getSensitiveCommands() {
        return sensitiveCommands;
    }

    public void setSensitiveCommands(List<String> sensitiveCommands) {
        this.sensitiveCommands = sensitiveCommands;
    }
}