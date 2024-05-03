FROM openjdk:17
ADD target/auth-0.0.1-SNAPSHOT.jar auth-0.0.1-SNAPSHOT.jar
ENTRYPOINT ["java", "-jar","auth-0.0.1-SNAPSHOT.jar"]
EXPOSE 8081