package auth0

import "github.com/dgrijalva/jwt-go"

type Parser struct {
	Domain   string
	Audience string
}

func (a Parser) Parse(token string) (*jwt.Token, error) {
	return jwt.Parse(token, a.validateJwt)
}