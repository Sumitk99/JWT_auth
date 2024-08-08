package middleware

import (
	"fmt"
	"github.com/Sumitk99/JWT_auth/helpers"
	"github.com/gin-gonic/gin"
	"net/http"
)

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
