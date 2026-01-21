FROM eclipse-temurin:21-jre

COPY --chown=nobody target/quarkus-app/lib/ /deployments/lib/
COPY --chown=nobody target/quarkus-app/*.jar /deployments/
COPY --chown=nobody target/quarkus-app/app/ /deployments/app/
COPY --chown=nobody target/quarkus-app/quarkus/ /deployments/quarkus/

EXPOSE 8080
USER nobody

ENTRYPOINT ["java", "-Dquarkus.http.host=0.0.0.0", "-Djava.util.logging.manager=org.jboss.logmanager.LogManager", "-Djdk.tls.rejectClientInitiatedRenegotiation=true", "-jar", "/deployments/quarkus-run.jar"]
