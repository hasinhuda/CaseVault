package com.casevault.web;

import com.casevault.common.CorrelationIds;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * One correlation id per request (SR-15). The id comes from the client header {@value #HEADER} only when it is a
 * strictly formed UUID; anything else (CR/LF, long junk, script text) is ignored and a new UUID is generated, so a
 * client cannot forge or inject log text. The id is stored in the request, in the logging MDC (key
 * {@value #MDC_KEY}) and in the response header before anything else runs, so every response (success, redirect,
 * error, 429) carries it. Runs before the security filter chain.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorrelationIdFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-Correlation-ID";
    public static final String MDC_KEY = CorrelationIds.MDC_KEY;
    public static final String REQUEST_ATTRIBUTE = CorrelationIdFilter.class.getName() + ".ID";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String id = chooseId(new ServletWebRequest(request).getHeader(HEADER));
        request.setAttribute(REQUEST_ATTRIBUTE, id);
        response.setHeader(HEADER, id);
        MDC.put(MDC_KEY, id);
        try {
            chain.doFilter(request, response);
        } finally {
            MDC.remove(MDC_KEY);
        }
    }

    /** A valid UUID from the client is echoed in canonical lower case; everything else is replaced. */
    static String chooseId(String clientValue) {
        return CorrelationIds.sanitiseOrNew(clientValue);
    }

    /** The id of the current request, or a new UUID when called outside a request that went through this filter. */
    public static String currentId(Object requestAttributeValue) {
        return CorrelationIds.sanitiseOrNew(requestAttributeValue);
    }
}
