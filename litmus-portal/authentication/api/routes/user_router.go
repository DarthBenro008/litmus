package routes

import (
	"litmus/litmus-portal/authentication/api/handlers"
	"litmus/litmus-portal/authentication/api/middleware"
	"litmus/litmus-portal/authentication/pkg/server_configs"
	"litmus/litmus-portal/authentication/pkg/user"

	"github.com/gin-gonic/gin"
)

// UserRouter creates all the required routes for user authentications purposes.
func UserRouter(router *gin.Engine, userService user.Service, serverConfigService server_configs.Service) {
	router.GET("/dex/login", handlers.DexLogin(serverConfigService))
	router.GET("/dex/callback", handlers.DexCallback(userService, serverConfigService))
	router.GET("/status", handlers.Status(userService))
	router.POST("/login", handlers.LoginUser(userService))
	router.Use(middleware.JwtMiddleware())
	router.POST("/update/password", handlers.UpdatePassword(userService))
	router.POST("/reset/password", handlers.ResetPassword(userService))
	router.POST("/create", handlers.CreateUser(userService))
	router.POST("/update/details", handlers.UpdateUser(userService))
	router.GET("/users", handlers.FetchUsers(userService))
	router.POST("/updatestate", handlers.UpdateUserState(userService))
}
