# Build stage
FROM eclipse-temurin:22-jdk-jammy@sha256:d8e6ba486df17bf758888d2b1b608133d1eedca8daf69d3fc6bf78d8be81e07e AS builder
WORKDIR /workspace

# Copy build descriptor and wrapper
COPY pom.xml mvnw ./
COPY .mvn .mvn

# A Windows checkout may have CRLF line endings in mvnw (shell error 127); make the script runnable either way
RUN sed -i 's/\r$//' mvnw && chmod +x mvnw

# Download dependencies offline
RUN ./mvnw dependency:go-offline -B

# Copy source and build package
COPY src src
RUN ./mvnw clean package -DskipTests -B

# Runtime stage
FROM eclipse-temurin:22-jre-jammy@sha256:dbcae8b5dd4d63f81739a538ec2c09797735f04a21d814f9071b62f018326043 AS runner
WORKDIR /app

# Upgrade base packages to address Trivy CVEs
# hadolint ignore=DL3008,DL3009
# Reason: Base package upgrades are required to mitigate security vulnerabilities identified by Trivy; apt lists are cleaned up.
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# Run as non-privileged non-root user
RUN groupadd -g 10001 casevault && \
    useradd -u 10001 -g casevault -s /bin/false -M -d /app casevault && \
    chown -R casevault:casevault /app

# Writable data directories for a read-only root filesystem (Phase 12B): evidence, keys, one-time credentials.
# A named volume mounted over an empty directory inherits its ownership, so the non-root user can write there.
RUN mkdir -p /data/evidence /data/keys /data/firstrun && \
    chown -R casevault:casevault /data && \
    chmod 700 /data/evidence /data/keys /data/firstrun

COPY --from=builder --chown=casevault:casevault /workspace/target/casevault-0.0.1-SNAPSHOT.jar /app/app.jar

USER 10001:10001

EXPOSE 8080

# Unauthenticated liveness URL (docs/adr/0009-deployment-configuration.md): 200 {"status":"UP"}, no details.
# curl is already part of the runtime image; no package is added for this.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/actuator/health || exit 1

ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "/app/app.jar"]
