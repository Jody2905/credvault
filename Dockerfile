# ---- Stage 1: build the application ----
FROM eclipse-temurin:17-jdk AS build
WORKDIR /src
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
COPY src/ src/
RUN chmod +x mvnw && ./mvnw -B -DskipTests package

# ---- Stage 2: run it ----
# The final image has only a Java runtime and the app: no compiler, no
# Maven, no source code. Less software means less to attack.
FROM eclipse-temurin:17-jre
RUN useradd --system --create-home vault
WORKDIR /app
COPY --from=build /src/target/*.jar app.jar

# Run as an ordinary user, not root
USER vault
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
