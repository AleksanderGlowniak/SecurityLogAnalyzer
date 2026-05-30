package com.company.securityanalyzer;

import com.company.securityanalyzer.config.RuleConfig;

import java.util.List;

public final class TestConfiguration {

    private TestConfiguration() {}

    public static RuleConfig config() {

        RuleConfig c =
                new RuleConfig();

        c.setFailedLoginThreshold(3);
        c.setAdminProbeThreshold(3);
        c.setRequestBurstThreshold(5);

        c.setSqlInjectionPatterns(
                List.of(
                        "UNION SELECT",
                        "DROP TABLE"
                )
        );

        c.setTraversalPatterns(
                List.of(
                        "../",
                        "/etc/passwd"
                )
        );

        c.setSensitivePaths(
                List.of(
                        "/admin",
                        "/phpmyadmin",
                        "/wp-admin"
                )
        );

        c.setSensitiveCommands(
                List.of(
                        "/etc/shadow"
                )
        );

        return c;
    }
}