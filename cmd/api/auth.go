package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

type authRequestOrResponse struct {
	UserGUID string `json:"GUID" binding:"required,uuid" example:"026b1196-05fa-49ec-acad-bb09ad170148"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required" example:"valid refresh token"`
}

type tokensResponse struct {
	RefreshToken string `json:"refresh" example:"new refresh token"`
	AccessToken  string `json:"access" example:"new access token"`
}

type customClaims struct {
	RefreshId int    `json:"refreshId"`
	UserGUID  string `json:"userGUID"`
	jwt.StandardClaims
}

// @Summary Аутентификация пользователя
// @Description Генерирует access и refresh токены
// @Tags auth
// @Accept json
// @Produce json
// @Param input body authRequestOrResponse true "Данные пользователя"
// @Success 200 {object} tokensResponse "Токены"
// @Example {access: "jwt.token", refresh: "base64token"}
// @Failure 400 "Bad request(GUID required)"
// @Failure 500 "Something went wrong"
// @Router /api/auth [post]
func (app *application) AuthorizeUser(c *gin.Context) {
	userAgent := c.Request.UserAgent()
	ipAddr := c.ClientIP()
	var Auth authRequestOrResponse
	if err := c.ShouldBindJSON(&Auth); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "GUID required"})
		return
	}

	var Response tokensResponse

	refreshToken, accessToken, err := app.generateNewTokens(c, Auth.UserGUID, userAgent, ipAddr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Something went wrond"})
		return
	}

	Response.RefreshToken = refreshToken
	Response.AccessToken = accessToken

	c.JSON(http.StatusOK, Response)
}

// @Summary Получение текущего пользователя
// @Description Возвращает GUID текущего аутентифицированного пользователя
// @Tags user
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} authRequestOrResponse "GUID пользователя"
// @Failure 401 "Unauthorized access"
// @Router /api/currentUser [get]
func (app *application) GetCurrentUser(c *gin.Context) {
	accessHeader := c.GetHeader("Access")

	claims, err := ParseJwtToken(accessHeader, app.jwtSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
		return
	}

	userGUID := claims.UserGUID
	refreshId := claims.RefreshId

	refreshTokenRow, err := app.repo.Get(refreshId)
	if err != nil || refreshTokenRow.UserGUID != userGUID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
		return
	}

	c.JSON(http.StatusOK, authRequestOrResponse{UserGUID: refreshTokenRow.UserGUID})
}

// @Summary Деавторизация
// @Description Отзывает все токены пользователя
// @Tags auth
// @Security ApiKeyAuth
// @Success 204
// @Failure 401 "Unauthorized access"
// @Router /api/deauthorize [post]
func (app *application) DeauthorizeUser(c *gin.Context) {
	accessHeader := c.GetHeader("Access")

	claims, err := ParseJwtToken(accessHeader, app.jwtSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	userGUID := claims.UserGUID
	refreshId := claims.RefreshId

	refreshTokenRow, err := app.repo.Get(refreshId)
	if err != nil || refreshTokenRow.UserGUID != userGUID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
		return
	}

	app.repo.DeleteUsersTokens(userGUID)

	c.JSON(http.StatusNoContent, nil)
}

// @Summary Обновление токенов
// @Description Обновляет пару access и refresh токенов
// @Tags auth
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param input body refreshRequest true "Refresh токен"
// @Success 200 {object} tokensResponse "Новые токены"
// @Failure 400 "Bad request(refresh token required)"
// @Failure 401 "Unauthorized access"
// @Failure 403 "Forbidden(User-Agent changed, or invalid refresh token)"
// @Router /api/refresh [post]
func (app *application) Refresh(c *gin.Context) {
	accessHeader := c.GetHeader("Access")
	ipAddr := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")
	var Refresh refreshRequest
	var Response tokensResponse

	if err := c.ShouldBindJSON(&Refresh); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	claims, err := ParseJwtToken(accessHeader, app.jwtSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	userGUID := claims.UserGUID
	refreshId := claims.RefreshId

	refreshTokenRow, err := app.repo.Get(refreshId)
	if err != nil || refreshTokenRow.UserGUID != userGUID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
		return
	}

	if !validateRefreshToken(Refresh.RefreshToken, userGUID, app.refreshSecret) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Invalid refresh token"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(refreshTokenRow.TokenHash), []byte(Refresh.RefreshToken)); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "Invalid refresh token"})
		return
	}

	if userAgent != refreshTokenRow.UserAgent {
		app.repo.DeleteUsersTokens(userGUID)
		c.JSON(http.StatusForbidden, gin.H{"error": "User agent changed"})
		return
	}

	if ipAddr != refreshTokenRow.IpAddr {
		go app.sendWebHook(c, refreshTokenRow.IpAddr, ipAddr, userGUID)
	}

	refreshToken, accessToken, err := app.generateNewTokens(c, userGUID, userAgent, ipAddr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Something went wrong"})
		return
	}

	app.repo.DeleteRefreshToken(refreshId)

	Response.RefreshToken = refreshToken
	Response.AccessToken = accessToken

	c.JSON(http.StatusOK, Response)
}

func validateRefreshToken(token, userGUID, refreshSecret string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}

	randomPart, _ := base64.RawURLEncoding.DecodeString(parts[0])
	h := hmac.New(sha512.New, []byte(refreshSecret))
	h.Write([]byte(userGUID))
	h.Write(randomPart)
	expectedSig := base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:16])

	return hmac.Equal([]byte(parts[1]), []byte(expectedSig))
}

func (app *application) sendWebHook(c *gin.Context, oldIpAddr, newIpAddr, userGUID string) {
	payload := map[string]interface{}{
		"event":       "refresh_from_new_ip",
		"user_guid":   userGUID,
		"original_ip": oldIpAddr,
		"new_ip":      newIpAddr,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	}

	jsonData, _ := json.Marshal(payload)

	resp, err := http.Post(
		app.webHookUrl,
		"application/json",
		bytes.NewBuffer(jsonData),
	)

	if err != nil {
		// добавить логгирование
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		// добавить логгирование
	}
}

func (app *application) generateNewTokens(c *gin.Context, userGUID, userAgent, ipAddr string) (string, string, error) {
	refreshToken, hashedRefreshToken, err := app.generateRefreshToken(userGUID)
	if err != nil {
		return "", "", err
	}

	refreshId, err := app.repo.InsertTokenRowReturningId(userGUID, string(hashedRefreshToken), userAgent, ipAddr)
	if err != nil {
		return "", "", err
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"refreshId": refreshId,
		"userGUID":  userGUID,
		"exp":       time.Now().Add(time.Hour * 72).Unix(),
	})

	accessTokenString, err := accessToken.SignedString([]byte(app.jwtSecret))
	if err != nil {
		return "", "", err
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
