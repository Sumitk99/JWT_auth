package routes

import (
	controller "github.com/Sumitk99/JWT_auth/controllers"
	middleware "github.com/Sumitk99/JWT_auth/middleware"
	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())

	incomingRoutes.GET("/users", controller.GetUsers())
	incomingRoutes.GET("/users/:user_id", controller.GetUser())
}
