package com.company.securityanalyzer.detector;

import com.company.securityanalyzer.config.RuleConfig;
import com.company.securityanalyzer.model.*;

import java.util.ArrayList;
import java.util.List;

public class PrivilegeEscalationDetector
        extends AbstractDetector {

    public PrivilegeEscalationDetector(
            RuleConfig config
    ) {
        super(config);
    }

    @Override
    public List<Incident> detect(
            List<Event> events
    ) {

        List<Incident> incidents =
                new ArrayList<>();

        for (Event event : events) {

            if (event.eventType()
                    != EventType.SUDO_COMMAND) {
                continue;
            }

            String command =
                    event.attributes()
                            .getOrDefault(
                                    "command",
                                    ""
                            );

            for (String sensitive :
                    config.getSensitiveCommands()) {

                if (command.contains(
                        sensitive
                )) {

                    incidents.add(
                            new Incident(
                                    Severity.MEDIUM,
                                    "Privilege Escalation",
                                    "Sensitive command executed",
                                    event.sourceIp(),
                                    event.timestamp(),
                                    List.of(command)
                            )
                    );

                    break;
                }
            }
        }

        return incidents;
    }
}