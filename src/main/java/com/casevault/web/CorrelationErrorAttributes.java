package com.casevault.web;

import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;

import java.util.Map;

/**
 * Attributes of the Boot /error page: adds the request's correlation id, replaces the (empty) message by a fixed
 * friendly text per status, and drops the request path so nothing the client sent is echoed.
 */
@Component
public class CorrelationErrorAttributes extends DefaultErrorAttributes {

    @Override
    public Map<String, Object> getErrorAttributes(WebRequest webRequest,
                                                  org.springframework.boot.web.error.ErrorAttributeOptions options) {
        Map<String, Object> attributes = super.getErrorAttributes(webRequest, options);
        Object requestId = webRequest.getAttribute(CorrelationIdFilter.REQUEST_ATTRIBUTE, WebRequest.SCOPE_REQUEST);
        attributes.put("correlationId", CorrelationIdFilter.currentId(requestId));
        attributes.put("signedIn", SignedInState.isSignedIn());
        Object status = attributes.get("status");
        attributes.put("message", safeMessage(status instanceof Integer code ? code : 500));
        attributes.remove("path");
        attributes.remove("trace");
        attributes.remove("exception");
        attributes.remove("errors");
        return attributes;
    }

    /** Fixed texts only; never an exception message. */
    public static String safeMessage(int status) {
        HttpStatus resolved = HttpStatus.resolve(status);
        if (resolved == null) {
            return "The request could not be completed.";
        }
        return switch (resolved) {
            case BAD_REQUEST -> "The request was not valid.";
            case UNAUTHORIZED -> "Please sign in to continue.";
            case FORBIDDEN -> "This request was refused.";
            case NOT_FOUND -> "The requested page or item was not found.";
            case METHOD_NOT_ALLOWED -> "This action is not available with that request method.";
            case CONFLICT -> "The item was changed by someone else. Reload and try again.";
            case PAYLOAD_TOO_LARGE -> "The request was too large.";
            case UNSUPPORTED_MEDIA_TYPE -> "That content type is not supported.";
            case TOO_MANY_REQUESTS -> "Too many requests. Please try again later.";
            case INTERNAL_SERVER_ERROR -> "An unexpected error occurred.";
            default -> "The request could not be completed.";
        };
    }
}
