package main

import (
	"net/http"

	_ "authorization-task/cmd/api/docs" // замените your_project на актуальный путь

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func (app *application) routes() http.Handler {
	g := gin.Default()

	g.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	api := g.Group("/api")
	{
		api.POST("auth", app.AuthorizeUser)
		api.POST("refresh", app.Refresh)
		api.GET("currentUser", app.GetCurrentUser)
		api.POST("deauthorize", app.DeauthorizeUser)
	}

	return g
}
