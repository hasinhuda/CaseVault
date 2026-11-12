package com.casevault.ratelimit;

/** The named limiters. The name is also the only identifier written to the log when a limit is hit. */
public enum LimiterName {
    LOGIN,
    API_BASIC,
    SEARCH,
    UPLOAD,
    REPORT_WRITE
}
