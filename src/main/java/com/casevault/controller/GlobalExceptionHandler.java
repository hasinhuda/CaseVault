package com.casevault.controller;

import com.casevault.exception.AuditAppendFailedException;
import com.casevault.exception.BadRequestException;
import com.casevault.security.CaseVaultUserPrincipal;
import com.casevault.service.AuditEventRecorder;
import com.casevault.service.AuditEventType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.MultipartException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;

import com.casevault.web.CorrelationErrorAttributes;
import com.casevault.web.CorrelationIdFilter;
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

    private AuditEventRecorder auditEventRecorder;

    /** Optional so the handler can still be constructed without a Spring context. */
    @Autowired(required = false)
    public void setAuditEventRecorder(AuditEventRecorder auditEventRecorder) {
        this.auditEventRecorder = auditEventRecorder;
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public Object handleResourceNotFound(ResourceNotFoundException ex, WebRequest request) {
        String correlationId = correlationId(request);
        logger.warn("ResourceNotFoundException handled");

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
        String correlationId = correlationId(request);
        logger.warn("BadRequest handled");

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

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public Object handleMaxUploadSizeExceeded(MaxUploadSizeExceededException ex, WebRequest request) {
        String correlationId = correlationId(request);
        logger.warn("MaxUploadSizeExceededException handled");

        String safeMessage = "File upload exceeds the maximum allowed size of 10MB.";

        if (isJsonRequest(request)) {
            Map<String, Object> body = new HashMap<>();
            body.put("error", "Bad Request");
            body.put("message", safeMessage);
            body.put("correlationId", correlationId);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).contentType(MediaType.APPLICATION_JSON).body(body);
        }

        ModelAndView mav = new ModelAndView("error");
        mav.setStatus(HttpStatus.BAD_REQUEST);
        mav.addObject("status", 400);
        mav.addObject("error", "Payload Too Large");
        mav.addObject("message", safeMessage);
        mav.addObject("correlationId", correlationId);
        return mav;
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, BindException.class})
    public Object handleValidationExceptions(Exception ex, WebRequest request) {
        String correlationId = correlationId(request);
        StringBuilder message = new StringBuilder("Validation failure: ");

        if (ex instanceof MethodArgumentNotValidException manve) {
            for (FieldError fieldError : manve.getBindingResult().getFieldErrors()) {
                message.append(fieldError.getField()).append(" ").append(safeFieldMessage(fieldError)).append("; ");
            }
        } else if (ex instanceof BindException be) {
            for (FieldError fieldError : be.getBindingResult().getFieldErrors()) {
                message.append(fieldError.getField()).append(" ").append(safeFieldMessage(fieldError)).append("; ");
            }
        }

        logger.warn("Validation error handled");

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

    /**
     * The business action already committed but its audit event could not be appended (fail-closed toward the
     * user). Shows the safe error page with the correlation id that was logged with the ERROR line.
     */
    @ExceptionHandler(AuditAppendFailedException.class)
    public Object handleAuditAppendFailed(AuditAppendFailedException ex, WebRequest request) {
        // The ERROR log line of the failed append carries this id; make the response header match the page.
        if (request instanceof org.springframework.web.context.request.ServletWebRequest servletRequest) {
            jakarta.servlet.http.HttpServletResponse response = servletRequest.getResponse();
            if (response != null) {
                response.setHeader(CorrelationIdFilter.HEADER, ex.getCorrelationId());
            }
        }
        return internalServerError(ex.getCorrelationId(), request);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public Object handleAccessDenied(AccessDeniedException ex, WebRequest request) {
        String correlationId = correlationId(request);
        logger.warn("AccessDenied handled");
        recordAccessDenied();

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

    /** Unknown URL or resource: 404 (before this handler existed the catch-all below answered 500). */
    @ExceptionHandler({NoResourceFoundException.class, NoHandlerFoundException.class})
    public Object handleNoHandler(Exception ex, WebRequest request) {
        return fixedStatus(HttpStatus.NOT_FOUND, request);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public Object handleMethodNotAllowed(HttpRequestMethodNotSupportedException ex, WebRequest request) {
        return fixedStatus(HttpStatus.METHOD_NOT_ALLOWED, request);
    }

    /** Type mismatch (page=abc), missing parameter or part, unreadable body, broken multipart: 400. */
    @ExceptionHandler({MethodArgumentTypeMismatchException.class, MissingServletRequestParameterException.class,
            ServletRequestBindingException.class, HttpMessageNotReadableException.class,
            MissingServletRequestPartException.class, MultipartException.class})
    public Object handleMalformedRequest(Exception ex, WebRequest request) {
        return fixedStatus(HttpStatus.BAD_REQUEST, request);
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public Object handleUnsupportedMediaType(HttpMediaTypeNotSupportedException ex, WebRequest request) {
        return fixedStatus(HttpStatus.UNSUPPORTED_MEDIA_TYPE, request);
    }

    @ExceptionHandler(HttpMediaTypeNotAcceptableException.class)
    public Object handleNotAcceptable(HttpMediaTypeNotAcceptableException ex, WebRequest request) {
        return fixedStatus(HttpStatus.NOT_ACCEPTABLE, request);
    }

    /** Concurrent change of a versioned row that no controller handled itself: 409. */
    @ExceptionHandler(ObjectOptimisticLockingFailureException.class)
    public Object handleConflict(ObjectOptimisticLockingFailureException ex, WebRequest request) {
        return fixedStatus(HttpStatus.CONFLICT, request);
    }

    /** Page or JSON with a fixed text for the status: no exception message, class name or request data. */
    private Object fixedStatus(HttpStatus status, WebRequest request) {
        String correlationId = correlationId(request);
        logger.warn("HTTP {} handled", status.value());
        String message = CorrelationErrorAttributes.safeMessage(status.value());
        if (isJsonRequest(request)) {
            Map<String, Object> body = new HashMap<>();
            body.put("error", status.getReasonPhrase());
            body.put("message", message);
            body.put("correlationId", correlationId);
            return ResponseEntity.status(status).contentType(MediaType.APPLICATION_JSON).body(body);
        }
        ModelAndView mav = new ModelAndView("error");
        mav.setStatus(status);
        mav.addObject("status", status.value());
        mav.addObject("error", status.getReasonPhrase());
        mav.addObject("message", message);
        mav.addObject("correlationId", correlationId);
        return mav;
    }

    /**
     * Messages of our own validation annotations are shown; a type-conversion failure (page=abc) is replaced by a
     * fixed text because the framework message names Java classes and echoes the rejected value.
     */
    private static String safeFieldMessage(FieldError fieldError) {
        return fieldError.isBindingFailure() ? "has an invalid value" : fieldError.getDefaultMessage();
    }

    /** The id assigned by {@link CorrelationIdFilter} (page, header and log line share it). */
    private static String correlationId(WebRequest request) {
        return CorrelationIdFilter.currentId(
                request.getAttribute(CorrelationIdFilter.REQUEST_ATTRIBUTE, WebRequest.SCOPE_REQUEST));
    }

    @ExceptionHandler(Exception.class)
    public Object handleUncaughtException(Exception ex, WebRequest request) {
        String correlationId = correlationId(request);
        logger.error("Internal Server Error occurred", ex);
        return internalServerError(correlationId, request);
    }

    private Object internalServerError(String correlationId, WebRequest request) {
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

    private void recordAccessDenied() {
        if (auditEventRecorder == null) {
            return;
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userId = (authentication != null && authentication.getPrincipal() instanceof CaseVaultUserPrincipal principal)
                ? principal.getUserId() : null;
        auditEventRecorder.record(AuditEventType.ACCESS_DENIED, userId, null, "NOT_PERMITTED");
    }

    private boolean isJsonRequest(WebRequest request) {
        String acceptHeader = request.getHeader("Accept");
        String uri = request.getDescription(false);
        return (acceptHeader != null && acceptHeader.contains("application/json")) || uri.contains("/api/");
    }
}

