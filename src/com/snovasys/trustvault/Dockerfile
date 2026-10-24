
FROM eclipse-temurin:21-jdk AS build
WORKDIR /app

COPY src ./src

RUN mkdir -p out \
    && javac --add-modules jdk.httpserver \
       -d out $(find src -name "*.java" ! -name "module-info.java")

FROM eclipse-temurin:21-jre
WORKDIR /app

COPY --from=build /app/out ./out

ENV PORT=8083
EXPOSE 8083

CMD ["java", "--add-modules", "jdk.httpserver", "-cp", "out", "com.snovasys.trustvault.TrustVaultServer"]
