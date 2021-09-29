package routes

import (
	"github.com/gin-gonic/gin"
	"litmus/litmus-portal/authentication/api/handlers"
	"litmus/litmus-portal/authentication/pkg/user"
)

// DexRouter creates all the required routes for OAuth purposes.
func DexRouter(router *gin.Engine, service user.Service) {
	router.GET("/dex/login", handlers.DexLogin())
	router.GET("/dex/callback", handlers.DexCallback(service))
}
