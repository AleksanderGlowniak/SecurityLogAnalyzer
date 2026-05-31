package com.company.securityanalyzer.parser;

import com.company.securityanalyzer.model.Event;
import com.company.securityanalyzer.model.EventType;
import com.company.securityanalyzer.model.ParseError;
import com.company.securityanalyzer.model.ParseResult;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WebServerLogParser implements LogParser {

    static final Pattern WEB_LOG_PATTERN =
            Pattern.compile(
                    "(\\S+)\\s+-\\s+-\\s+" +
                            "\\[(.*?)\\]\\s+" +
                            "\"(\\S+)\\s+(.*?)\\s+(.*?)\"\\s+" +
                            "(\\d+)\\s+(\\d+)"
            );

    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern(
                    "dd/MMM/yyyy:HH:mm:ss Z",
                    java.util.Locale.ENGLISH
            );

    @Override
    public boolean supports(Path file) {

        try (var lines = Files.lines(file)) {

            return lines
                    .map(String::trim)
                    .filter(line -> !line.isEmpty())
                    .filter(line -> !line.equals("```"))
                    .limit(20)
                    .anyMatch(this::looksLikeWebLog);

        } catch (IOException ex) {

            return false;
        }
    }

    private boolean looksLikeWebLog(String line) {

        return WEB_LOG_PATTERN.matcher(line)
                .matches();
    }

    @Override
    public ParseResult parse(Path logFile) {

        List<Event> events = new ArrayList<>();
        List<ParseError> errors = new ArrayList<>();

        AtomicLong lineCounter = new AtomicLong();

        try (var lines = Files.lines(logFile)) {

            lines.forEach(line -> {

                long lineNumber =
                        lineCounter.incrementAndGet();

                String trimmed = line.trim();

                if (trimmed.isEmpty() || trimmed.equals("```")) {
                    return;
                }

                Matcher matcher =
                        WEB_LOG_PATTERN.matcher(trimmed);

                if (!matcher.matches()) {

                    errors.add(
                            new ParseError(
                                    logFile.toString(),
                                    lineNumber,
                                    line,
                                    "Malformed web log entry"
                            )
                    );

                    return;
                }

                try {

                    String ip = matcher.group(1);

                    LocalDateTime timestamp =
                            OffsetDateTime.parse(
                                            matcher.group(2),
                                            TIMESTAMP_FORMAT
                                    )
                                    .toLocalDateTime();

                    String method = matcher.group(3);
                    String path = matcher.group(4);
                    String protocol = matcher.group(5);
                    String status = matcher.group(6);
                    String bytes = matcher.group(7);

                    Map<String, String> attributes =
                            new HashMap<>();

                    attributes.put("method", method);
                    attributes.put("path", path);
                    attributes.put("protocol", protocol);
                    attributes.put("status", status);
                    attributes.put("bytes", bytes);

                    EventType type =
                            classify(path, status);

                    events.add(
                            new Event(
                                    timestamp,
                                    ip,
                                    type,
                                    attributes,
                                    line
                            )
                    );

                } catch (Exception ex) {

                    errors.add(
                            new ParseError(
                                    logFile.toString(),
                                    lineNumber,
                                    line,
                                    ex.getMessage()
                            )
                    );
                }
            });

        } catch (IOException ex) {

            throw new RuntimeException(
                    "Unable to read file "
                            + logFile,
                    ex
            );
        }

        return new ParseResult(events, errors);
    }

    private EventType classify(
            String path,
            String status
    ) {

        if ("/login".equals(path)) {

            if ("200".equals(status)) {
                return EventType.WEB_LOGIN_SUCCESS;
            }

            if ("401".equals(status)) {
                return EventType.WEB_LOGIN_FAILURE;
            }
        }

        return EventType.HTTP_REQUEST;
    }
}