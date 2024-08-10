# Golang JWT Authentication Service

This repository contains a JWT (JSON Web Token) authentication service built with Golang. This service can be easily integrated into other projects to handle user authentication using JWT tokens.

## Features

- **User Registration**: Register new users with secure password hashing.
- **User Login**: Authenticate users and issue JWT tokens upon successful login.
- **JWT Middleware**: Protect routes by validating JWT tokens.
- **Role-Based Access Control**: Define user roles and restrict access to specific endpoints.
- **Refresh Tokens**: Support for refreshing JWT tokens.

## Tech Stack

- **Golang**: Main programming language.
- **Gin Framework**: Lightweight web framework for building REST APIs.
- **JWT**: JSON Web Token for secure authentication.
- **Validator**: Package used for input validation.
- **MongoDB**: NoSQL database using the standard MongoDB Go driver.

## Prerequisites

- **Golang**: Ensure you have Golang installed on your machine. [Download Golang](https://golang.org/dl/)
- **MongoDB**: Ensure MongoDB is installed and running. [Install MongoDB](https://docs.mongodb.com/manual/installation/)

## Installation

1. **Clone the repository**:

    ```bash
    git clone https://github.com/Sumitk99/JWT_auth.git
    cd JWT_auth
    ```

2. **Install dependencies**:

    ```bash
    go mod tidy
    ```

3. **Set up environment variables**:

    Create a `.env` file in the root directory and add the following:

    ```plaintext
    PORT=8080
    JWT_SECRET=your_secret_key
    MONGO_URI=mongodb://localhost:27017
    DB_NAME=your_db_name
    ```

4. **Run the service**:

    ```bash
    go run main.go
    ```

## API Endpoints

### Authentication

- **POST /register**: Register a new user.

    **Request Body**:
    ```json
    {
        "username": "exampleuser",
        "password": "examplepassword"
    }
    ```

- **POST /login**: Login and receive a JWT token.

    **Request Body**:
    ```json
    {
        "email": "your-email",
        "password": "your-password"
    }
    ```


### Protected Routes

- **GET /protected**: Example of a protected route.

    **Headers**:
    ```plaintext
    Authorization: Bearer your_jwt_token
    ```

## Middleware

The JWT middleware is used to protect routes. To apply it to your routes:

```go
func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())

	incomingRoutes.GET("/users", controller.GetUsers())
	incomingRoutes.GET("/users/:user_id", controller.GetUser())
}

func Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientToken := c.Request.Header.Get("token")
		if clientToken == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("No Authorization Token found.")})
			c.Abort()
			return
		}

		claims, err := helper.ValidateToken(clientToken)

		if len(err) > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			c.Abort()
			return
		}

		c.Set("email", claims.Email)
		c.Set("first_name", claims.FirstName)
		c.Set("last_name", claims.LastName)
		c.Set("user_id", claims.Uid)
		c.Set("user_type", claims.UserType)
		c.Next()

	}
}
