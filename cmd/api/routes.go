package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (app *application) routes() http.Handler {
	g := gin.Default()

	api := g.Group("/api")
	{
		api.POST("auth", app.AuthorizeUser)
		// api.POST("refresh", app.RefreshTokens)
		api.GET("currentUser", app.GetCurrentUser)
		api.POST("deauthorize", app.DeauthorizeUser)
	}

	return g
}
