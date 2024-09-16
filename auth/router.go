package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func setupRouter() *gin.Engine {
	r := gin.Default()
	//docs.SwaggerInfo.BasePath = "/post"

	auth := r.Group("/auth")
	{
		auth.POST("/tokens_by_guid", func(c *gin.Context) {
			tokensByGuid(c)
		})
		auth.POST("/renew_tokens", func(c *gin.Context) {
			renewTokensHandler(c)
		})
	}
	testAccess := r.Group("/test")
	{
		testAccess.Use(accessMiddleware)
		testAccess.POST("/verify_access", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"ping": "pong"})
		})
	}

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
	return r
}

func StartServer(port string, secret string, access int, refresh int) {
	r := setupRouter()
	signingSecret = secret
	accessLifetime = access
	refreshLifetime = refresh

	r.Run(":" + port)
}
