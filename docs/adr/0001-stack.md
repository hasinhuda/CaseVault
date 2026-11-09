# ADR 0001: Technology Stack Selection

## Status
Accepted

## Context
CaseVault is a secure incident response case management platform requiring enterprise reliability, high-assurance security controls, multi-tenancy, and strict reproducibility. The technology foundation must support rigorous quality gates, static analysis, supply-chain SBOM generation, containerization, and production-identical test environments.

## Decision
We select the following fixed technology stack:
- **Language**: Java 21 LTS (OpenJDK Temurin) for long-term vendor support, virtual threads, and modern language features.
- **Framework**: Spring Boot 3.5.16 (verified latest 3.5.x patch on Maven Central). Explicitly reject Spring Boot 4.x to maintain proven security module compatibility.
- **Web Tier**: Spring MVC + Thymeleaf server-rendered templates. Thymeleaf enforces strict context-aware HTML escaping (`th:text`) by default.
- **Security**: Spring Security 6.x providing servlet filter chains, CSRF protection, and method-level access control.
- **Persistence**: Spring Data JPA + Hibernate ORM on PostgreSQL with HikariCP connection pooling.
- **Database Migrations**: Flyway Core & Flyway Database PostgreSQL for deterministic schema evolution.
- **Test Infrastructure**:
  - H2 in-memory database for rapid unit and local development tests.
  - Testcontainers with official PostgreSQL 16 image for production-equivalent database integration tests.
- **Build & Quality Gates**:
  - Apache Maven 3.9.9 via Maven Wrapper (`mvnw`).
  - Maven Enforcer Plugin (`requireJavaVersion`, `requireMavenVersion`, `banDuplicatePomDependencyVersions`, `dependencyConvergence`).
  - JaCoCo code coverage plugin (bundle coverage `>= 0.70`).
  - SpotBugs + FindSecBugs 1.14.0 for static AST security auditing.
  - CycloneDX Maven Plugin for automated Software Bill of Materials (SBOM) generation.
  - ArchUnit for automated architectural rule verification.

## Consequences
- **Positive**:
  - Full defense-in-depth across the entire stack.
  - Zero custom crypto or ad-hoc frameworks.
  - Automated dependency convergence eliminates classpath collisions.
  - Multi-stage container build produces minimal attack surface with non-root runtime.
- **Negative / Trade-offs**:
  - Testcontainers tests require a local Docker daemon (addressed via fallback profiles).
  - Strict Enforcer rules require explicit dependency convergence management.

## Compliance & Standards Mapping
- **OWASP Top 10**:
  - OWASP Top 10:2025 [VERIFY MANUALLY]: A05 (Security Misconfiguration), A06 (Vulnerable and Outdated Components)
  - OWASP Top 10:2021: A05:2021 (Security Misconfiguration), A06:2021 (Vulnerable and Outdated Components)
- **CWE**: CWE-1104 (Use of Unmaintained Third-Party Components), CWE-1395 (Dependency Convergence / Insecure Dependency Management)
- **ASVS 5.0**: V1 Architecture, V14 Configuration (V14.2.1, V14.3.1 [VERIFY MANUALLY])

