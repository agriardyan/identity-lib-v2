package claim

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/emicklei/go-restful"
)

const (
	RequesterUserID     = "requesterUserId"
	CurrentSessionClaim = "currentSessionClaim"
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

func ParseClaimAttribute(req *restful.Request) *IdentityClaim {
	rawClaim := req.Attribute(CurrentSessionClaim)
	if claim, ok := rawClaim.(*IdentityClaim); ok {
		return claim
	}
	return nil
}
