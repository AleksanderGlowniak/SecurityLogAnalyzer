package com.company.securityanalyzer.config;

import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public final class ConfigLoader {

    private ConfigLoader() {
    }

    public static RuleConfig load(Path configFile) {

        try (InputStream inputStream = Files.newInputStream(configFile)) {

            Yaml yaml = new Yaml();

            RuleConfig config =
                    yaml.loadAs(inputStream, RuleConfig.class);

            validate(config);

            return config;

        } catch (Exception ex) {

            throw new RuleConfigurationException(
                    "Unable to load configuration: "
                            + configFile,
                    ex
            );
        }
    }

    private static void validate(RuleConfig config) {

        if (config == null) {
            throw new RuleConfigurationException(
                    "Configuration file is empty"
            );
        }

        if (config.getFailedLoginThreshold() <= 0) {
            throw new RuleConfigurationException(
                    "failedLoginThreshold must be > 0"
            );
        }

        if (config.getAdminProbeThreshold() <= 0) {
            throw new RuleConfigurationException(
                    "adminProbeThreshold must be > 0"
            );
        }

        if (config.getRequestBurstThreshold() <= 0) {
            throw new RuleConfigurationException(
                    "requestBurstThreshold must be > 0"
            );
        }
    }
}