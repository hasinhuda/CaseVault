package com.casevault.ratelimit;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/** Writes the HTTP 429 page. */
public interface BlockedPageRenderer {

    void render(HttpServletRequest request, HttpServletResponse response, String correlationId,
                long retryAfterSeconds) throws IOException;
}
