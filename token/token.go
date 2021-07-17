package token

import (
	"github.com/agriardyan/identity-lib-v2/claim"
	"github.com/dgrijalva/jwt-go"
)

func ParseWithClaims(tokenString string, keyFunc jwt.Keyfunc) (*jwt.Token, *claim.IdentityClaim, error) {
	claims := &claim.IdentityClaim{}
	tkn, err := jwt.ParseWithClaims(tokenString, claims, keyFunc)
	return tkn, claims, err
}
