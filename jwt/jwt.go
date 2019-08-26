package jwt

import (
	"errors"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/sirupsen/logrus"
)

//Config include secret
type Config struct {
	secret string
}

//NewJwt init config
func NewJwt(secret string) *Config {
	return &Config{
		secret: secret,
	}
}

//CreateToken create a new token with SigningMethodHS256 stand for username
func (c *Config) CreateToken(username string) string {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := make(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Hour * time.Duration(1)).Unix()
	claims["iat"] = time.Now().Unix()
	claims["sub"] = username
	token.Claims = claims
	tokenString, err := token.SignedString([]byte(c.secret))
	if err != nil {
		logrus.Errorf("Jwt Generate Error %v", err)
		return ""
	}
	return tokenString
}

//Varify token
func (c *Config) Varify(r *http.Request) (*jwt.Token, error) {
	token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(c.secret), nil
		})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("Jwt Token not valid")
	}
	return token, nil
}

//GetUser return username in token
func GetUser(token *jwt.Token) string {
	claims, _ := token.Claims.(jwt.MapClaims)
	return claims["sub"].(string)
}
