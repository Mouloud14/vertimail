# -- Étape 1 : Construction (Build) --
FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
# On compile et on crée le .jar (en sautant les tests pour aller plus vite)
RUN mvn clean package -DskipTests

# -- Étape 2 : Lancement (Run) --
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
# On récupère le .jar créé à l'étape 1
# (Attention: le nom *.jar prendra le premier fichier trouvé, c'est pratique)
COPY --from=build /app/target/*-fat.jar app.jar

# Render nous donne un PORT dynamique via une variable d'environnement
ENV PORT=8888
EXPOSE $PORT

# La commande pour démarrer
ENTRYPOINT ["java", "-jar", "app.jar"]
