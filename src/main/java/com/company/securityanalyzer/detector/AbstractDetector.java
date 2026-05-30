package com.company.securityanalyzer.detector;

import com.company.securityanalyzer.config.RuleConfig;

public abstract class AbstractDetector
        implements Detector {

    protected final RuleConfig config;

    protected AbstractDetector(
            RuleConfig config
    ) {
        this.config = config;
    }
}
