FROM quay.io/keycloak/keycloak:26.3.2-0

ADD https://repo1.maven.org/maven2/eu/europa/ec/eudi/abca-keycloak-ext/0.1.0/abca-keycloak-ext-0.1.0.jar /opt/keycloak/providers/abca-keycloak-ext.jar

USER root
RUN chmod 644 /opt/keycloak/providers/abca-keycloak-ext.jar

USER keycloak