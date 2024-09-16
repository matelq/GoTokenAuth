package auth

import (
	"errors"
	"fmt"
	"net/http"
	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/matelq/GoAuth/mockmail"
	"golang.org/x/crypto/bcrypt"
)

var signingSecret string
var accessLifetime int
var refreshLifetime int

type RefreshClaims struct {
	AccessCrc string `json:"access_crc"`
	InitialIp string `json:"initial_ip"`
	jwt.RegisteredClaims
}

type AccessClaims struct {
	InitialIp string `json:"initial_ip"`
	jwt.RegisteredClaims
}

func tokensByGuid(c *gin.Context) {
	var request struct {
		Guid string `json:"user_guid"`
	}

	if err := c.BindJSON(&request); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !isValidUUID(request.Guid) {
		c.AbortWithStatusJSON(http.StatusBadRequest, "Guid is not valid")
		return
	}

	accessToken, err := generateAccessToken(request.Guid, c.ClientIP())
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	refreshToken, err := generateRefreshToken(request.Guid, accessToken, c.ClientIP())
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func renewTokensHandler(c *gin.Context) {
	var request struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.BindJSON(&request); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	accessToken, err := parseAccessToken(request.AccessToken)

	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
	case errors.Is(err, jwt.ErrTokenMalformed):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "There's no access token provided"})
		return
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid access token signature"})
		return
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Access token is not active yet"})
		return
	case accessToken.Valid:
	default:
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Couldn't handle this access token: %s", err)})
		return
	}

	refreshToken, err := parseRefreshToken(request.RefreshToken, request.AccessToken)
	switch {
	case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Refresh token cannot be matched"})
	case errors.Is(err, jwt.ErrTokenMalformed):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "There's no access token provided"})
		return
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid access token signature"})
		return
	case errors.Is(err, jwt.ErrTokenNotValidYet) || errors.Is(err, jwt.ErrTokenExpired):
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Access token is either expired or not active yet"})
		return
	case refreshToken.Valid:
	default:
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Couldn't handle this access token: %s", err)})
		return
	}

	rclaims, ok := refreshToken.Claims.(*RefreshClaims)
	if !ok {
		c.AbortWithStatus(http.StatusInternalServerError)
	}

	guid, err := refreshToken.Claims.GetSubject()
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	if rclaims.InitialIp != c.ClientIP() {
		mockmail.SendEmailByGuid(guid, fmt.Sprintf("Access to your account were granted to unexpected ip: %s", c.ClientIP()))
	}

	newAccessToken, err := generateAccessToken(guid, c.ClientIP())
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	newRefreshToken, err := generateRefreshToken(guid, newAccessToken, c.ClientIP())
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	})
}

func accessMiddleware(c *gin.Context) {
	var request struct {
		AccessToken string `json:"access_token"`
	}
	if err := c.BindJSON(&request); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	token, err := parseAccessToken(request.AccessToken)

	switch {
	case errors.Is(err, jwt.ErrTokenMalformed):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "There's no token provided"})
		return
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid signature"})
		return
	case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet):
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Token is either expired or not active yet"})
		return
	case token.Valid:
	default:
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Couldn't handle this token: %s", err)})
		return
	}

	c.Next()
}
