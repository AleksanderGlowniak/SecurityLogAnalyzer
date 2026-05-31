package com.company.securityanalyzer.detector;

import com.company.securityanalyzer.TestConfiguration;
import com.company.securityanalyzer.model.Event;
import com.company.securityanalyzer.model.EventType;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ApiAbuseDetectorTest {

    @Test
    void shouldDetectApiAbuse() {

        var config =
                TestConfiguration.config();

        List<Event> events =
                List.of(
                        request("1.1.1.1", "200"),
                        request("1.1.1.1", "200"),
                        request("1.1.1.1", "200"),
                        request("1.1.1.1", "200"),
                        request("1.1.1.1", "429")
                );

        var incidents =
                new ApiAbuseDetector(config)
                        .detect(events);

        assertEquals(
                1,
                incidents.size()
        );
    }

    @Test
    void shouldIgnoreBurstWithoutRateLimit() {

        var config =
                TestConfiguration.config();

        List<Event> events =
                List.of(
                        request("1.1.1.1", "200"),
                        request("1.1.1.1", "200"),
                        request("1.1.1.1", "200"),
                        request("1.1.1.1", "200"),
                        request("1.1.1.1", "200")
                );

        var incidents =
                new ApiAbuseDetector(config)
                        .detect(events);

        assertTrue(
                incidents.isEmpty()
        );
    }

    @Test
    void shouldIgnoreRequestsBelowThreshold() {

        var config =
                TestConfiguration.config();

        List<Event> events =
                List.of(
                        request("1.1.1.1", "200"),
                        request("1.1.1.1", "200"),
                        request("1.1.1.1", "429")
                );

        var incidents =
                new ApiAbuseDetector(config)
                        .detect(events);

        assertTrue(
                incidents.isEmpty()
        );
    }

    private Event request(
            String ip,
            String status
    ) {

        return new Event(
                LocalDateTime.now(),
                ip,
                EventType.HTTP_REQUEST,
                Map.of(
                        "path",
                        "/api/users",
                        "status",
                        status
                ),
                ""
        );
    }
}
