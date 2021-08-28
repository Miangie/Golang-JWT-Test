# Golang JWT Test
Testing JWT and cookies in golang for future REST API uses

## Endpoints
```go
GET  /coffee    // Test checking if user is signed in
GET  /users     // Returns all users objects (for learning purposes)
POST /login     // Checks creds and if correct - writes JWT token cookie
POST /register  // Registers new user
```

`/login` and `/register` accept data in URL-Encoded-Form with fields `username` and `password`

## Security
For learning purpose, cookie is not flagged as secure so no valid TLS cert. is required
