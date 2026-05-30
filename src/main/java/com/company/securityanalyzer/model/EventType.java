package com.company.securityanalyzer.model;

public enum EventType {

    HTTP_REQUEST,

    SSH_FAILED_LOGIN,
    SSH_SUCCESS_LOGIN,

    WEB_LOGIN_FAILURE,
    WEB_LOGIN_SUCCESS,

    SUDO_COMMAND,

    MALFORMED_LOG_ENTRY

}