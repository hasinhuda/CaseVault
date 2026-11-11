package com.casevault.exception;

/**
 * Raised when an audit event could not be appended after the business action committed. Carries only a correlation
 * id: the message, cause and stack trace of the underlying failure are deliberately not kept.
 */
public class AuditAppendFailedException extends IllegalStateException {

    private static final long serialVersionUID = 1L;

    private final String correlationId;

    public AuditAppendFailedException(String correlationId) {
        super("Audit event could not be recorded");
        this.correlationId = correlationId;
    }

    public String getCorrelationId() {
        return correlationId;
    }
}
