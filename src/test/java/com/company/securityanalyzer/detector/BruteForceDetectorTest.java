package com.company.securityanalyzer.detector;

import com.company.securityanalyzer.TestConfiguration;
import com.company.securityanalyzer.TestUtils;
import com.company.securityanalyzer.config.RuleConfig;
import com.company.securityanalyzer.model.Event;
import com.company.securityanalyzer.model.EventType;
import com.company.securityanalyzer.model.Incident;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BruteForceDetectorTest {

    @Test
    void shouldDetectCredentialAttack() {

        RuleConfig config =
                TestConfiguration.config();

        List<Event> events =
                List.of(
                        TestUtils.event(
                                "10.0.0.50",
                                EventType.SSH_FAILED_LOGIN
                        ),
                        TestUtils.event(
                                "10.0.0.50",
                                EventType.SSH_FAILED_LOGIN
                        ),
                        TestUtils.event(
                                "10.0.0.50",
                                EventType.SSH_FAILED_LOGIN
                        ),
                        TestUtils.event(
                                "10.0.0.50",
                                EventType.SSH_SUCCESS_LOGIN
                        )
                );

        List<Incident> incidents =
                new BruteForceDetector(config)
                        .detect(events);

        assertEquals(
                1,
                incidents.size()
        );

        assertEquals(
                "Credential Attack",
                incidents.get(0).title()
        );
    }

    @Test
    void shouldIgnoreNormalLogin() {

        RuleConfig config =
                TestConfiguration.config();

        List<Event> events =
                List.of(
                        TestUtils.event(
                                "10.0.0.50",
                                EventType.SSH_SUCCESS_LOGIN
                        )
                );

        List<Incident> incidents =
                new BruteForceDetector(config)
                        .detect(events);

        assertTrue(
                incidents.isEmpty()
        );
    }

    @Test
    void shouldDetectWhenFailuresEqualThreshold() {
        RuleConfig config = TestConfiguration.config();

        List<Event> events = List.of(
                TestUtils.event("1.1.1.1", EventType.SSH_FAILED_LOGIN),
                TestUtils.event("1.1.1.1", EventType.SSH_FAILED_LOGIN),
                TestUtils.event("1.1.1.1", EventType.SSH_FAILED_LOGIN),
                TestUtils.event("1.1.1.1", EventType.SSH_SUCCESS_LOGIN)
        );

        var incidents = new BruteForceDetector(config).detect(events);

        assertEquals(1, incidents.size());
    }

    @Test
    void shouldNotDetectBelowThreshold() {
        RuleConfig config = TestConfiguration.config();

        List<Event> events = List.of(
                TestUtils.event("1.1.1.1", EventType.SSH_FAILED_LOGIN),
                TestUtils.event("1.1.1.1", EventType.SSH_FAILED_LOGIN),
                TestUtils.event("1.1.1.1", EventType.SSH_SUCCESS_LOGIN)
        );

        assertTrue(
                new BruteForceDetector(config)
                        .detect(events)
                        .isEmpty()
        );
    }

    @Test
    void shouldNotDetectWithoutSuccessfulLogin() {
        RuleConfig config = TestConfiguration.config();

        List<Event> events = List.of(
                TestUtils.event("1.1.1.1", EventType.SSH_FAILED_LOGIN),
                TestUtils.event("1.1.1.1", EventType.SSH_FAILED_LOGIN),
                TestUtils.event("1.1.1.1", EventType.SSH_FAILED_LOGIN)
        );

        assertTrue(
                new BruteForceDetector(config)
                        .detect(events)
                        .isEmpty()
        );
    }
}