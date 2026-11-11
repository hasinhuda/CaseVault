package com.casevault.evidence;

import com.casevault.controller.GlobalExceptionHandler;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.ModelAndView;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GlobalExceptionHandlerUploadTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    @DisplayName("SEC-EV-ERR-001: MaxUploadSizeExceededException returns safe 400 JSON response for API requests")
    void testMaxUploadSizeExceededJson() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/cases/1/evidence");
        request.addHeader("Accept", "application/json");
        ServletWebRequest webRequest = new ServletWebRequest(request);

        MaxUploadSizeExceededException ex = new MaxUploadSizeExceededException(10 * 1024 * 1024);
        Object response = handler.handleMaxUploadSizeExceeded(ex, webRequest);

        assertTrue(response instanceof ResponseEntity<?>);
        @SuppressWarnings("unchecked")
        ResponseEntity<Map<String, Object>> entity = (ResponseEntity<Map<String, Object>>) response;

        assertEquals(HttpStatus.BAD_REQUEST, entity.getStatusCode());
        assertNotNull(entity.getBody());
        assertEquals("Bad Request", entity.getBody().get("error"));
        assertTrue(entity.getBody().get("message").toString().contains("10MB"));
        assertNotNull(entity.getBody().get("correlationId"));
        // Never exposes stack trace or internal exception details
        assertFalse(entity.getBody().toString().contains("MaxUploadSizeExceededException"));
    }

    @Test
    @DisplayName("SEC-EV-ERR-002: MaxUploadSizeExceededException returns safe 400 HTML view for browser requests")
    void testMaxUploadSizeExceededHtml() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/cases/1/evidence/upload");
        request.addHeader("Accept", "text/html");
        ServletWebRequest webRequest = new ServletWebRequest(request);

        MaxUploadSizeExceededException ex = new MaxUploadSizeExceededException(10 * 1024 * 1024);
        Object response = handler.handleMaxUploadSizeExceeded(ex, webRequest);

        assertTrue(response instanceof ModelAndView);
        ModelAndView mav = (ModelAndView) response;

        assertEquals("error", mav.getViewName());
        assertEquals(HttpStatus.BAD_REQUEST, mav.getStatus());
        assertEquals(400, mav.getModel().get("status"));
        assertEquals("Payload Too Large", mav.getModel().get("error"));
        assertTrue(mav.getModel().get("message").toString().contains("10MB"));
        assertNotNull(mav.getModel().get("correlationId"));
    }
}

