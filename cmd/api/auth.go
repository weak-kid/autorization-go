package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

type authRequest struct {
	UserGUID string `json:"GUID" binding:"required,uuid"`
}

type customClaims struct {
	RefreshId int    `json:"refreshId"`
	UserGUID  string `json:"userGUID"`
	jwt.StandardClaims
}

func (app *application) AuthorizeUser(c *gin.Context) {
	userAgent := c.Request.UserAgent()
	ipAddr := c.ClientIP()
	var auth authRequest
	if err := c.ShouldBindJSON(&auth); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	refreshToken, accessTokenString, err := app.generateNewTokens(c, auth.UserGUID, userAgent, ipAddr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": auth.UserGUID})
		return
	}

	c.JSON(http.StatusOK, gin.H{"access": accessTokenString, "refresh": refreshToken})
}

func (app *application) GetCurrentUser(c *gin.Context) {
	accessHeader := c.GetHeader("Access")

	claims, err := ParseJwtToken(accessHeader, app.jwtSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error})
		return
	}

	userGUID := claims.UserGUID
	refreshId := claims.RefreshId

	refreshTokenString, err := app.repo.Get(refreshId)
	if err != nil || refreshTokenString.UserGUID != userGUID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
		return
	}

	// ONLY FOR REFRESH
	// if userAgent != refreshTokenString.UserAgent {
	// 	app.deauthorizeFromAll(userGUID)
	// }

	// if ipAddr != refreshTokenString.IpAddr {
	// 	app.sendWebHook(refreshTokenString.IpAddr, ipAddr, userGUID)
	// }

	c.JSON(http.StatusOK, gin.H{"GUID": refreshTokenString.UserGUID})
}

func (app *application) DeauthorizeUser(c *gin.Context) {
	accessHeader := c.GetHeader("Access")

	claims, err := ParseJwtToken(accessHeader, app.jwtSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error})
		return
	}

	userGUID := claims.UserGUID
	refreshId := claims.RefreshId

	refreshTokenString, err := app.repo.Get(refreshId)
	if err != nil || refreshTokenString.UserGUID != userGUID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
		return
	}

	app.repo.DeleteUsersTokens(userGUID)

	// ONLY FOR REFRESH
	// if userAgent != refreshTokenString.UserAgent {
	// 	app.deauthorizeFromAll(userGUID)
	// }

	// if ipAddr != refreshTokenString.IpAddr {
	// 	app.sendWebHook(refreshTokenString.IpAddr, ipAddr, userGUID)
	// }

	c.JSON(http.StatusOK, gin.H{"GUID": refreshTokenString.UserGUID})
}

func (app *application) generateNewTokens(c *gin.Context, userGUID, userAgent, ipAddr string) (string, string, error) {
	refreshToken, hashedRefreshToken, err := app.GenerateRefreshToken(userGUID)
	if err != nil {
		return "", "", err
	}

	refreshId, err := app.repo.InsertTokenRowReturningId(userGUID, string(hashedRefreshToken), userAgent, ipAddr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": userGUID})
		return "", "", err
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"refreshId": refreshId,
		"userGUID":  userGUID,
		"exp":       time.Now().Add(time.Hour * 72).Unix(),
	})

	accessTokenString, err := accessToken.SignedString([]byte(app.jwtSecret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Check3"})
	}

	return refreshToken, accessTokenString, err
}

func (app *application) generateRefreshToken(userGUID string) (string, string, error) {
	randomPart := make([]byte, 32)
	rand.Read(randomPart)

	h := hmac.New(sha512.New, []byte(app.refreshSecret))
	h.Write([]byte(userGUID))
	h.Write(randomPart)
	signature := h.Sum(nil)[:16]

	token := strings.Join([]string{
		base64.RawURLEncoding.EncodeToString(randomPart),
		base64.RawURLEncoding.EncodeToString(signature),
	}, ".")

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	return token, string(hashedToken), err
}

func ParseJwtToken(accessHeader, jwtSecret string) (*customClaims, error) {
	if accessHeader == "" {
		return nil, errors.New("Access header is required")
	}

	tokenString := strings.TrimPrefix(accessHeader, "Bearer ")
	if tokenString == accessHeader {
		return nil, errors.New("Bearer token is required")
	}

	token, err := jwt.ParseWithClaims(tokenString, &customClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(jwtSecret), nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("Invalid token")
	}

	claims, ok := token.Claims.(*customClaims)
	if !ok {
		return nil, errors.New("Invalid token")
	}

	return claims, nil
}
