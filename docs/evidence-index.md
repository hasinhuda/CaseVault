# Evidence Index

This index maps architectural, security, and functional requirements to verified artifacts, tests, and CI jobs within the repository.

## Verification Matrix

| Requirement ID | Description | Source / Config | Automated Test / Gate | CI Verification | Status |
| -------------- | ----------- | --------------- | --------------------- | --------------- | ------ |
| SEC-001 | Java 21 LTS baseline & Enforcer | [pom.xml](../pom.xml) | Maven Enforcer plugin | CI `build-and-test` | Verified |
| SEC-002 | Dependency convergence & duplication ban | [pom.xml](../pom.xml) | Maven Enforcer plugin | CI `build-and-test` | Verified |
| SEC-003 | Code coverage quality gate (bundle >= 70%) | [pom.xml](../pom.xml) | JaCoCo check rule | CI `build-and-test` | Verified |
| SEC-004 | Static analysis / AST security scanning | [pom.xml](../pom.xml) | SpotBugs + FindSecBugs | CI `build-and-test` | Verified |
| SEC-005 | Software Bill of Materials (SBOM) generation | [pom.xml](../pom.xml) | CycloneDX plugin | CI `sbom` | Verified |
| SEC-006 | Secret detection in Git history | [.github/workflows/ci.yml](../.github/workflows/ci.yml) | Gitleaks action | CI `gitleaks` | Verified |
| SEC-007 | Container image vulnerability & Dockerfile lint | [Dockerfile](../Dockerfile) | Hadolint & Trivy | CI `container-scan` | Verified |
| SEC-008 | Baseline application health & context loading | [CaseVaultApplicationTests.java](../src/test/java/com/casevault/CaseVaultApplicationTests.java) | JUnit 5 / SpringBootTest | CI `build-and-test` | Verified |
| SEC-009 | Session cookie security & strict headers | [SecurityConfig.java](../src/main/java/com/casevault/config/SecurityConfig.java), [HealthEndpointTest.java](../src/test/java/com/casevault/HealthEndpointTest.java) | `TEST-BASE-002`, `TEST-BASE-005` | CI `build-and-test` | Verified |

## Test Execution Summary

- Local Build Command: `.\mvnw.cmd -B verify`
- Target Environment: Java 21, PostgreSQL 16+ / Testcontainers, H2 (test profile)
