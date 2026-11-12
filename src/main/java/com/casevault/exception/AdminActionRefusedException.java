package com.casevault.exception;

/** An admin action was refused by a safety rule (self-action, last active admin). The message is user safe. */
public class AdminActionRefusedException extends RuntimeException {

    public AdminActionRefusedException(String message) {
        super(message);
    }
}
