package com.casevault.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Entity
@Table(name = "organisations")
public class Organisation {

    @Id
    @Column(name = "id", length = 36, nullable = false, updatable = false)
    private String id;

    @Column(name = "name", length = 100, nullable = false, unique = true)
    private String name;

    @Column(name = "code", length = 50, nullable = false, unique = true)
    private String code;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public Organisation() {
    }

    public Organisation(String id, String name, String code, Instant createdAt) {
        this.id = id != null ? id : UUID.randomUUID().toString();
        this.name = name;
        this.code = code;
        this.createdAt = createdAt != null ? createdAt : Instant.now();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Organisation that = (Organisation) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}

