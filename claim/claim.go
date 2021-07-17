package claim

import "github.com/dgrijalva/jwt-go"

const (
	RequesterUserID = "requesterUserId"
)

//IdentityClaim model for jwt claim
type IdentityClaim struct {
	UserID      string         `json:"user_id,omitempty"`
	Namespace   string         `json:"namespace,omitempty"`
	ClientID    string         `json:"client_id,omitempty"`
	UserType    string         `json:"user_type,omitempty"`
	Permissions map[string]int `json:"permissions"`
	jwt.StandardClaims
}
