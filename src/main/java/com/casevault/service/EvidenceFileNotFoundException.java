package com.casevault.service;

import com.casevault.exception.ResourceNotFoundException;

class EvidenceFileNotFoundException extends ResourceNotFoundException {
    EvidenceFileNotFoundException(String message) {
        super(message);
    }
}

