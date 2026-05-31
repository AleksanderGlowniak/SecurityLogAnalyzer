package com.company.securityanalyzer.parser;

import com.company.securityanalyzer.model.Event;
import com.company.securityanalyzer.model.EventType;
import com.company.securityanalyzer.model.ParseError;
import com.company.securityanalyzer.model.ParseResult;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Locale;

public class AuthLogParser implements LogParser {

    private static final Pattern FAILED_LOGIN =
            Pattern.compile(
                    ".*Failed password.*from\\s+(\\S+).*"
            );

    private static final Pattern SUCCESS_LOGIN =
            Pattern.compile(
                    ".*Accepted.*from\\s+(\\S+).*"
            );

    private static final Pattern SUDO_COMMAND =
            Pattern.compile(
                    ".*sudo:.*COMMAND=(.*)"
            );

    private static final Pattern TIMESTAMP =
            Pattern.compile(
                    "^(\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+)"
            );

    private static final DateTimeFormatter FORMAT =
            DateTimeFormatter.ofPattern(
                    "MMM d HH:mm:ss"
            );

    @Override
    public boolean supports(Path file) {

        try (var lines = Files.lines(file)) {

            return lines
                    .map(String::trim)
                    .filter(line -> !line.isEmpty())
                    .filter(line -> !line.equals("```"))
                    .limit(20)
                    .anyMatch(this::looksLikeAuthLog);

        } catch (IOException ex) {

            return false;
        }
    }

    private boolean looksLikeAuthLog(String line) {

        return line.contains("sshd[")
                || line.contains("sudo:");
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

                try {

                    Event event =
                            parseLine(trimmed);

                    if (event != null) {
                        events.add(event);
                    }

                } catch (Exception ex) {

                    ex.printStackTrace();

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

            throw new RuntimeException(ex);
        }

        return new ParseResult(events, errors);
    }

    private Event parseLine(String line) {

        LocalDateTime timestamp =
                parseTimestamp(line);

        Matcher failed =
                FAILED_LOGIN.matcher(line);

        if (failed.matches()) {

            return new Event(
                    timestamp,
                    failed.group(1),
                    EventType.SSH_FAILED_LOGIN,
                    Map.of(),
                    line
            );
        }

        Matcher success =
                SUCCESS_LOGIN.matcher(line);

        if (success.matches()) {

            return new Event(
                    timestamp,
                    success.group(1),
                    EventType.SSH_SUCCESS_LOGIN,
                    Map.of(),
                    line
            );
        }

        Matcher sudo =
                SUDO_COMMAND.matcher(line);

        if (sudo.matches()) {

            Map<String, String> attrs =
                    new HashMap<>();

            attrs.put(
                    "command",
                    sudo.group(1).trim()
            );

            return new Event(
                    timestamp,
                    "localhost",
                    EventType.SUDO_COMMAND,
                    attrs,
                    line
            );
        }

        return null;
    }

    private LocalDateTime parseTimestamp(String line) {

        Matcher matcher = TIMESTAMP.matcher(line);

        if (!matcher.find()) {
            return ParserUtils.defaultTimestamp();
        }

        String rawTimestamp =
                matcher.group(1)
                        .replaceAll("\\s+", " ")
                        .trim();

        return LocalDateTime.parse(
                LocalDate.now().getYear()
                        + " "
                        + rawTimestamp,
                DateTimeFormatter.ofPattern(
                        "yyyy MMM d HH:mm:ss",
                        Locale.ENGLISH
                )
        );
    }
}