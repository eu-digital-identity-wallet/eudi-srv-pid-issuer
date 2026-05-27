FROM maven:3.9-eclipse-temurin-17-alpine AS downloader
ARG VERSION
RUN if [[ "${VERSION}" == *"-SNAPSHOT" ]]; then \
      REPOSITORY="https://central.sonatype.com/repository/maven-snapshots/"; \
    else \
      REPOSITORY="https://repo.maven.apache.org/maven2/"; \
    fi && \
    mvn dependency:get \
      -DremoteRepositories=${REPOSITORY} \
      -Dartifact="eu.europa.ec.eudi:abca-keycloak-ext:${VERSION}" \
      -Dtransitive=false
RUN mvn dependency:copy \
      -Dartifact="eu.europa.ec.eudi:abca-keycloak-ext:${VERSION}" \
      -DoutputDirectory=/tmp

FROM quay.io/keycloak/keycloak:26.3.2-0
COPY --from=downloader /tmp/abca-keycloak-ext-*.jar /opt/keycloak/providers/abca-keycloak-ext.jar
USER root
RUN chmod 644 /opt/keycloak/providers/abca-keycloak-ext.jar
USER keycloak
