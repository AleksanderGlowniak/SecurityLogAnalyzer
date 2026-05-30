package com.company.securityanalyzer.config;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ConfigLoaderTest {

    @Test
    void shouldLoadYamlConfiguration() {

        RuleConfig config =
                ConfigLoader.load(
                        Path.of("src/main/resources/rules.yaml")
                );

        assertEquals(
                3,
                config.getFailedLoginThreshold()
        );

        assertTrue(
                config.getSqlInjectionPatterns()
                        .contains("UNION SELECT")
        );
    }
}
