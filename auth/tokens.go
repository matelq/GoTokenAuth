package auth

import (
	b64 "encoding/base64"
	"fmt"
	"strconv"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	db "github.com/matelq/GoAuth/database"
	"github.com/snksoft/crc"
	"golang.org/x/crypto/bcrypt"
)

func parseRefreshToken(refreshTokenB64 string, accessToken string) (*jwt.Token, error) {
	crc32 := crc.CalculateCRC(crc.CRC32, []byte(accessToken))


	refreshToken, err := b64.StdEncoding.DecodeString(refreshTokenB64)
	if err != nil {
		return nil, err
	}

	token, err := jwt.ParseWithClaims(string(refreshToken), &RefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(signingSecret), nil
	}, jwt.WithLeeway(5*time.Second))

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*RefreshClaims)
	if !ok {
		return nil, fmt.Errorf("unknown claims type, cannot proceed")
	}

	matchingToken, err := tryGetMatchingRefreshToken(refreshTokenB64, claims.IssuedAt.Time)
	if err != nil {
		return nil, err
	}
	

	err = db.DeleteRefreshHash(string(matchingToken))
	if err != nil {
		return nil, err
	}

	if claims.AccessCrc != strconv.FormatUint(crc32, 10) {
		return nil, fmt.Errorf("access token is not matching refresh token")
	}

	return token, nil
}

func generateRefreshToken(guid string, accessToken string, initialIp string) (string, error) {

	crc32 := crc.CalculateCRC(crc.CRC32, []byte(accessToken))
	claims := RefreshClaims{
		strconv.FormatUint(crc32, 10),
		initialIp,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Second * time.Duration(refreshLifetime))),
			Subject:   guid,
			IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	refreshToken, err := token.SignedString([]byte(signingSecret))
	if err != nil {
		return "", err
	}
	refreshB64 := b64.StdEncoding.EncodeToString([]byte(refreshToken))

	hashedRefreshB64, err := bcrypt.GenerateFromPassword(stringToSha256(refreshB64), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	err = db.InsertRefreshTokenHash(string(hashedRefreshB64))
	if err != nil {
		return "", err
	}

	return refreshB64, nil
}

func generateAccessToken(guid string, initialIp string) (string, error) {

	claims := AccessClaims{
		initialIp,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Second * time.Duration(accessLifetime))),
			Subject:   guid,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	accessToken, err := token.SignedString([]byte(signingSecret))
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func parseAccessToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(string(tokenString), &AccessClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(signingSecret), nil
	}, jwt.WithLeeway(5*time.Second))

	if err != nil {
		return nil, err
	}

	_, ok := token.Claims.(*AccessClaims)
	if !ok {
		return nil, fmt.Errorf("unknown claims type, cannot proceed")
	}

	return token, nil
}

func tryGetMatchingRefreshToken(tokenB64 string, issuedAt time.Time) (string, error) {
	sha256Refresh := stringToSha256(tokenB64)

	viableTokens, err := db.SelectViableRefreshTokens(issuedAt.UTC())
	if err != nil {
		return "", err
	}

	for _, token := range viableTokens {
		err = bcrypt.CompareHashAndPassword([]byte(token), sha256Refresh)
		if err == nil {
			return token, nil
		}
	}

	return "", err
}

