﻿# 02230306-WEB102-PA2

This project is a RESTful API built with Hono and Prisma for managing user authentication and a collection of Pokemons. It uses JWT for securing protected routes and includes basic CRUD operations for the Pokemon entity.

# Getting Started
## Prerequisites
Node.js

PostgreSQL (or another supported database)

Prisma CLI

## API Endpoints
Public Endpoints
POST /register

Registers a new user.

Request body
```
{
  "email": "user@example.com",
  "username": "username",
  "password": "password"
}
```
GET /protected/pokemon

Retrieves all Pokemons for the authenticated user.

PUT /protected/pokemon/

Updates a Pokemon by ID for the authenticated user.

Request body:
```
{
  "name": "Raichu",
  "type": "Electric",
  "description": "An evolved electric Pokemon"
}
```
DELETE /protected/pokemon/

Deletes a Pokemon by ID for the authenticated user.

## Error Handling
The API uses HTTP status codes to indicate the result of an operation:

200 OK: The request was successful.

201 Created: A resource was successfully created.

400 Bad Request: The request was invalid or cannot be served.

401 Unauthorized: The request requires user authentication.

404 Not Found: The requested resource could not be found.

500 Internal Server Error: An error occurred on the server.

