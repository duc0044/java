# Build stage with dependency caching
FROM maven:3.9.6-eclipse-temurin-17-alpine AS build
WORKDIR /app

# Copy only pom.xml first to cache dependencies
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source and build
COPY src ./src
RUN mvn clean package -DskipTests -B && \
    mkdir -p target/dependency && \
    cd target/dependency && \
    jar -xf ../*.jar

# Runtime stage with JRE only
FROM eclipse-temurin:17-jre-alpine

# Add non-root user for security
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

WORKDIR /app

# Copy Spring Boot layers for better caching
COPY --from=build /app/target/dependency/BOOT-INF/lib /app/lib
COPY --from=build /app/target/dependency/META-INF /app/META-INF
COPY --from=build /app/target/dependency/BOOT-INF/classes /app

EXPOSE 8083

# Use exec form and optimized JVM flags
ENTRYPOINT ["java", \
    "-XX:+UseContainerSupport", \
    "-XX:MaxRAMPercentage=75.0", \
    "-XX:+ExitOnOutOfMemoryError", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-cp", ".:lib/*", \
    "com.file.FileServiceApplication"]
