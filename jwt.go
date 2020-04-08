package auth0

import (
	"encoding/json"
	"errors"
	"fmt"
	jwtgo "github.com/dgrijalva/jwt-go"
	"net/http"
)

func (a Parser) getPemCert(token *jwtgo.Token) (string, error) {
	cert := ""
	resp, err := http.Get(fmt.Sprintf("%s.well-known/jwks.json", a.domain))

	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("Unable to find appropriate key.")
		return cert, err
	}

	return cert, nil
}

func (a Parser) validateJwt(token *jwtgo.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwtgo.SigningMethodRSA); !ok {
		return nil, errors.New("unexpected signing method")
	}

	checkAud := token.Claims.(jwtgo.MapClaims).VerifyAudience(a.audience, false)
	if !checkAud {
		return nil, errors.New("invalid audience")
	}

	// Verify 'iss' claim
	checkIss := token.Claims.(jwtgo.MapClaims).VerifyIssuer(a.domain, false)
	if !checkIss {
		return nil, errors.New("invalid issuer")
	}

	cert, err := a.getPemCert(token)
	if err != nil {
		return nil, err
	}

	return jwtgo.ParseRSAPublicKeyFromPEM([]byte(cert))
}
