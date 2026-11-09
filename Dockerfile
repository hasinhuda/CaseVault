# Build stage
FROM eclipse-temurin:21-jdk-jammy@sha256:4b1a74fbffbe6b4e7b6f0171a472478282fb463790a51edf10e465d578f22b69 AS builder
WORKDIR /workspace

# Copy build descriptor and wrapper
COPY pom.xml mvnw ./
COPY .mvn .mvn

# Download dependencies offline
RUN ./mvnw dependency:go-offline -B

# Copy source and build package
COPY src src
RUN ./mvnw clean package -DskipTests -B

# Runtime stage
FROM eclipse-temurin:21-jre-jammy@sha256:1eac8b8fee11ca7d6725a48bc5d41992ed1561504ebae25490d2d062847e8269 AS runner
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

COPY --from=builder --chown=casevault:casevault /workspace/target/casevault-0.0.1-SNAPSHOT.jar /app/app.jar

USER 10001:10001

EXPOSE 8080

ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "/app/app.jar"]
