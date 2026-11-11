package com.casevault.service;

import com.casevault.exception.ResourceNotFoundException;

class EvidenceIntegrityException extends ResourceNotFoundException {
    EvidenceIntegrityException(String message) {
        super(message);
    }
}

