package com.casevault.controller;

import com.casevault.exception.BadRequestException;
import com.casevault.exception.InvalidStatusTransitionException;
import com.casevault.exception.ResourceNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.BindException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.ModelAndView;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Centralized exception handler implementing safe error handling (SR-15).
 * Never exposes stack traces, class names, or SQL statements.
 * Emits a random UUID correlation ID for auditing and client correlation.
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ResourceNotFoundException.class)
    public Object handleResourceNotFound(ResourceNotFoundException ex, WebRequest request) {
        String correlationId = UUID.randomUUID().toString();
        logger.warn("ResourceNotFoundException handled for correlationId={}", correlationId);

        if (isJsonRequest(request)) {
            Map<String, Object> body = new HashMap<>();
            body.put("error", "Not Found");
            body.put("message", ex.getMessage());
            body.put("correlationId", correlationId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).contentType(MediaType.APPLICATION_JSON).body(body);
        }

        ModelAndView mav = new ModelAndView("error");
        mav.setStatus(HttpStatus.NOT_FOUND);
        mav.addObject("status", 404);
        mav.addObject("error", "Not Found");
        mav.addObject("message", ex.getMessage());
        mav.addObject("correlationId", correlationId);
        return mav;
    }

    @ExceptionHandler({InvalidStatusTransitionException.class, BadRequestException.class})
    public Object handleBadRequest(RuntimeException ex, WebRequest request) {
        String correlationId = UUID.randomUUID().toString();
        logger.warn("BadRequest handled for correlationId={}", correlationId);

        if (isJsonRequest(request)) {
            Map<String, Object> body = new HashMap<>();
            body.put("error", "Bad Request");
            body.put("message", ex.getMessage());
            body.put("correlationId", correlationId);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).contentType(MediaType.APPLICATION_JSON).body(body);
        }

        ModelAndView mav = new ModelAndView("error");
        mav.setStatus(HttpStatus.BAD_REQUEST);
        mav.addObject("status", 400);
        mav.addObject("error", "Bad Request");
        mav.addObject("message", ex.getMessage());
        mav.addObject("correlationId", correlationId);
        return mav;
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, BindException.class})
    public Object handleValidationExceptions(Exception ex, WebRequest request) {
        String correlationId = UUID.randomUUID().toString();
        StringBuilder message = new StringBuilder("Validation failure: ");

        if (ex instanceof MethodArgumentNotValidException manve) {
            for (FieldError fieldError : manve.getBindingResult().getFieldErrors()) {
                message.append(fieldError.getField()).append(" ").append(fieldError.getDefaultMessage()).append("; ");
            }
        } else if (ex instanceof BindException be) {
            for (FieldError fieldError : be.getBindingResult().getFieldErrors()) {
                message.append(fieldError.getField()).append(" ").append(fieldError.getDefaultMessage()).append("; ");
            }
        }

        logger.warn("Validation error handled for correlationId={}", correlationId);

        if (isJsonRequest(request)) {
            Map<String, Object> body = new HashMap<>();
            body.put("error", "Bad Request");
            body.put("message", message.toString().trim());
            body.put("correlationId", correlationId);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).contentType(MediaType.APPLICATION_JSON).body(body);
        }

        ModelAndView mav = new ModelAndView("error");
        mav.setStatus(HttpStatus.BAD_REQUEST);
        mav.addObject("status", 400);
        mav.addObject("error", "Validation Failure");
        mav.addObject("message", message.toString().trim());
        mav.addObject("correlationId", correlationId);
        return mav;
    }

    @ExceptionHandler(AccessDeniedException.class)
    public Object handleAccessDenied(AccessDeniedException ex, WebRequest request) {
        String correlationId = UUID.randomUUID().toString();
        logger.warn("AccessDenied handled for correlationId={}", correlationId);

        if (isJsonRequest(request)) {
            Map<String, Object> body = new HashMap<>();
            body.put("error", "Forbidden");
            body.put("message", ex.getMessage());
            body.put("correlationId", correlationId);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).contentType(MediaType.APPLICATION_JSON).body(body);
        }

        ModelAndView mav = new ModelAndView("error");
        mav.setStatus(HttpStatus.FORBIDDEN);
        mav.addObject("status", 403);
        mav.addObject("error", "Forbidden");
        mav.addObject("message", ex.getMessage());
        mav.addObject("correlationId", correlationId);
        return mav;
    }

    @ExceptionHandler(Exception.class)
    public Object handleUncaughtException(Exception ex, WebRequest request) {
        String correlationId = UUID.randomUUID().toString();
        logger.error("Internal Server Error occurred", ex);

        if (isJsonRequest(request)) {
            Map<String, Object> body = new HashMap<>();
            body.put("error", "Internal Server Error");
            body.put("message", "An unexpected error occurred. Reference correlation ID: " + correlationId);
            body.put("correlationId", correlationId);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).contentType(MediaType.APPLICATION_JSON).body(body);
        }

        ModelAndView mav = new ModelAndView("error");
        mav.setStatus(HttpStatus.INTERNAL_SERVER_ERROR);
        mav.addObject("status", 500);
        mav.addObject("error", "Internal Server Error");
        mav.addObject("message", "An unexpected error occurred. Reference correlation ID: " + correlationId);
        mav.addObject("correlationId", correlationId);
        return mav;
    }

    private boolean isJsonRequest(WebRequest request) {
        String acceptHeader = request.getHeader("Accept");
        String uri = request.getDescription(false);
        return (acceptHeader != null && acceptHeader.contains("application/json")) || uri.contains("/api/");
    }
}

