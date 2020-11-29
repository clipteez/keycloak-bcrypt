# Keycloak BCrypt

Add a password hash provider to handle BCrypt (Version 2Y) passwords inside Keycloak.

## Build
```bash
./gradlew jar
```

## Test with docker-compose
```bash
cp build/libs/keycloak-bcrypt-2Y-1.5.0.jar docker/
docker-compose up -d
```

## Install
```
curl -L https://github.com/leroyguillaume/keycloak-bcrypt/releases/download/1.5.0/keycloak-bcrypt-2Y-1.5.0.jar > KEYCLOAK_HOME/standalone/deployments/keycloak-bcrypt-2Y-1.5.0.jar
```
You need to restart Keycloak.

## How to use
Go to `Authentication` / `Password policy` and add hashing algorithm policy with value `bcrypt-2Y`.

To test if installation works, create new user and set its credentials.
