package com.company.securityanalyzer;

import com.company.securityanalyzer.model.Event;
import com.company.securityanalyzer.model.EventType;

import java.time.LocalDateTime;
import java.util.Map;

public final class TestUtils {

    private TestUtils() {}

    public static Event event(
            String ip,
            EventType type
    ) {

        return new Event(
                LocalDateTime.now(),
                ip,
                type,
                Map.of(),
                ""
        );
    }

    public static Event webEvent(
            String ip,
            String path,
            String status
    ) {

        return new Event(
                LocalDateTime.now(),
                ip,
                EventType.HTTP_REQUEST,
                Map.of(
                        "path", path,
                        "status", status
                ),
                ""
        );
    }
}