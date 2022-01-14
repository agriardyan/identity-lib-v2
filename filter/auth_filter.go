package filter

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/agriardyan/identity-lib-v2/claim"
	"github.com/agriardyan/identity-lib-v2/token"
	"github.com/dgrijalva/jwt-go"
	"github.com/emicklei/go-restful"
	"github.com/sirupsen/logrus"
)

var ErrUnauthorized = errors.New("unauthorized")
var ErrInvalidToken = errors.New("invalidtoken")
var ErrExpiredToken = errors.New("expiredtoken")
var ErrForbidden = errors.New("forbidden")

const (
	HeaderParameterAuthorization      = "Authorization"
	Admin                             = "admin"
	BasicTokenType                    = "Basic"
	BearerTokenType                   = "Bearer"
	UserID                            = "userId"
	ClientID                          = "clientId"
	ClientSecret                      = "clientSecret"
	UnauthenticatedRequestCode        = 1002001
	UnauthenticatedRequestExplanation = "Unauthenticated request"
	InvalidTokenCode                  = 1002002
	InvalidTokenExplanation           = "Invalid token"
	ExpiredTokenCode                  = 1002003
	ExpiredTokenExplanation           = "Expired token"
	ForbiddenRequestCode              = 1003001
	ForbiddenRequestExplanation       = "Forbidden request. Check your privilege!"
	NamespacePlaceholder              = "{namespace}"
	UserPlaceholder                   = "{userId}"
	ResourceSeparator                 = ":"
	StarValue                         = "*"
)

//AuthResponse auth response model
type AuthResponse struct {
	Code        int    `json:"code"`
	Explanation string `json:"explanation"`
}

//IAuthFilter contract for auth filter
type IAuthFilter interface {
	Auth(requiredPermission string, requiredAction int) restful.FilterFunction
	BasicAuth() restful.FilterFunction
}

//AuthFilter auth filter
type AuthFilter struct {
	secretKey     string
	jwtParserFunc func(tokenString string, keyFunc jwt.Keyfunc) (*jwt.Token, *claim.IdentityClaim, error)
}

//NewSymmetric create filter instance with symmetric signing
func NewSymmetric(secretKey string) *AuthFilter {
	return NewSymmetricWithParser(secretKey, token.ParseWithClaims)
}

//NewSymmetricFilter create filter instance with symmetric signing and custom parser
func NewSymmetricWithParser(secretKey string, jwtParserFunc func(tokenString string, keyFunc jwt.Keyfunc) (*jwt.Token, *claim.IdentityClaim, error)) *AuthFilter {
	return &AuthFilter{
		secretKey:     secretKey,
		jwtParserFunc: jwtParserFunc,
	}
}

//Auth authenticate and authorize the request
func (auth *AuthFilter) Auth(requiredPermission string, requiredAction int) restful.FilterFunction {
	return func(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {

		claimObj, err := auth.authorizeHandler(req, requiredPermission, requiredAction)

		switch err {
		case ErrUnauthorized:
			_ = resp.WriteHeaderAndJson(
				http.StatusUnauthorized,
				&AuthResponse{
					Code:        UnauthenticatedRequestCode,
					Explanation: UnauthenticatedRequestExplanation,
				},
				restful.MIME_JSON,
			)
			return
		case ErrExpiredToken:
			_ = resp.WriteHeaderAndJson(
				http.StatusUnauthorized,
				&AuthResponse{
					Code:        ExpiredTokenCode,
					Explanation: ExpiredTokenExplanation,
				},
				restful.MIME_JSON,
			)
			return
		case ErrInvalidToken:
			_ = resp.WriteHeaderAndJson(
				http.StatusUnauthorized,
				&AuthResponse{
					Code:        ExpiredTokenCode,
					Explanation: ExpiredTokenExplanation,
				},
				restful.MIME_JSON,
			)
			return
		case ErrForbidden:
			_ = resp.WriteHeaderAndJson(
				http.StatusForbidden,
				&AuthResponse{
					Code:        ForbiddenRequestCode,
					Explanation: ForbiddenRequestExplanation,
				},
				restful.MIME_JSON,
			)
			return
		}

		req.SetAttribute(claim.RequesterUserID, claimObj.UserID)
		req.SetAttribute(claim.CurrentSessionClaim, claimObj)

		chain.ProcessFilter(req, resp)
	}
}

func (auth *AuthFilter) authorizeHandler(req *restful.Request, requiredPermission string, requiredAction int) (*claim.IdentityClaim, error) {
	rawToken := req.HeaderParameter(HeaderParameterAuthorization)
	splittedToken := strings.Fields(rawToken)

	if len(splittedToken) != 2 {
		return nil, ErrUnauthorized
	}

	if splittedToken[0] != BearerTokenType {
		return nil, ErrUnauthorized
	}

	jwtKey := []byte(auth.secretKey)

	_, claimObj, err := auth.jwtParserFunc(splittedToken[1], func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if errVal, ok := err.(*jwt.ValidationError); ok {
			if errVal.Errors == jwt.ValidationErrorExpired {
				return nil, ErrExpiredToken
			}
		}
		logrus.Errorf("Failed to parse claim. Error: %s", err)
		return nil, ErrInvalidToken
	}

	requiredPermissionPlaceholderReplaced := auth.replacePlaceholders(requiredPermission, req)
	claimedPerms := claimObj.Permissions
	isAuthorized := auth.matchWithClaims(requiredPermissionPlaceholderReplaced, requiredAction, claimedPerms)
	if !isAuthorized {
		return nil, ErrForbidden
	}

	return claimObj, nil
}

//replacePlaceholders replace the placeholder from expected resource with one from request path param
//for example: assuming the req.PathParameter(namespace) return 12345
//the resource external:fnb:namespace:{namespace}:menu will become external:fnb:namespace:123456:menu
func (auth *AuthFilter) replacePlaceholders(expectedResource string, req *restful.Request) string {
	newResource := ""
	splittedRes := strings.Split(expectedResource, ResourceSeparator)
	for _, res := range splittedRes {
		if strings.HasPrefix(res, "{") && strings.HasSuffix(res, "}") {
			trimmed := strings.TrimFunc(res, func(r rune) bool {
				return !unicode.IsLetter(r)
			})
			pathParam := req.PathParameter(trimmed)
			if pathParam != "" {
				res = pathParam
			}
		}
		newResource += res + ResourceSeparator
	}
	finalTrim := strings.Trim(newResource, ResourceSeparator)
	return finalTrim
}

//matchWithClaims match the permission
//remember that resource format is visibility:servicename:param1:value1:param2:value2
//for example: internal:fnb:namespace:*:user:*:menu or just namespace:{namespace}:menu:*
func (auth *AuthFilter) matchWithClaims(requiredResource string, requiredAction int, claimedPerms map[string]int) bool {

	if claimedPerms[requiredResource]&requiredAction > 0 { // required and granted perfectly match
		return true
	}

	requiredResourceSubs := strings.Split(requiredResource, ResourceSeparator)
	for claimedResource, claimedAction := range claimedPerms {
		claimedResourceSubs := strings.Split(claimedResource, ResourceSeparator)
		if len(claimedResourceSubs) != len(requiredResourceSubs) {
			continue
		}
		if auth.matchOneClaim(claimedResourceSubs, requiredResourceSubs) {
			return requiredAction&claimedAction > 0
		}
	}
	return false
}

func (auth *AuthFilter) matchOneClaim(claimedResourceSubs, requiredResourceSubs []string) bool {
	for i, requiredResourceSub := range requiredResourceSubs {
		if requiredResourceSub != claimedResourceSubs[i] && claimedResourceSubs[i] != StarValue && requiredResourceSub != StarValue {
			return false
		}
	}
	return true
}

func (auth *AuthFilter) isExpire(claims *claim.IdentityClaim) bool {
	now := time.Now().Unix()
	return claims.ExpiresAt <= now
}

//BasicAuth perform parse and validation for basic auth, and put credential to request attribute
//note that you still needs to validate the credential against what you have in DB. This function does not do that for you.
func (auth *AuthFilter) BasicAuth() restful.FilterFunction {
	return func(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
		rawToken := req.HeaderParameter(HeaderParameterAuthorization)
		splittedToken := strings.Fields(rawToken)

		responseBodyUnauthenticated := &AuthResponse{
			Code:        UnauthenticatedRequestCode,
			Explanation: UnauthenticatedRequestExplanation,
		}

		if len(splittedToken) != 2 {
			_ = resp.WriteHeaderAndJson(
				http.StatusUnauthorized,
				responseBodyUnauthenticated,
				restful.MIME_JSON,
			)
			return
		}

		if splittedToken[0] != BasicTokenType {
			_ = resp.WriteHeaderAndJson(
				http.StatusUnauthorized,
				responseBodyUnauthenticated,
				restful.MIME_JSON,
			)
			return
		}

		contentBytes, err := base64.StdEncoding.DecodeString(splittedToken[1])
		if err != nil {
			logrus.Errorf("Failed to parse the basic auth. Error: %v", err)
			_ = resp.WriteHeaderAndJson(
				http.StatusUnauthorized,
				&AuthResponse{
					Code:        InvalidTokenCode,
					Explanation: InvalidTokenExplanation,
				},
				restful.MIME_JSON,
			)
			return
		}

		content := string(contentBytes)
		contents := strings.Split(content, ":")

		if len(contents) < 1 || len(contents) > 2 {
			_ = resp.WriteHeaderAndJson(
				http.StatusUnauthorized,
				responseBodyUnauthenticated,
				restful.MIME_JSON,
			)
			return
		}

		clientID := contents[0]
		clientSecret := contents[1]
		req.SetAttribute(ClientID, clientID)
		req.SetAttribute(ClientSecret, clientSecret)

		chain.ProcessFilter(req, resp)
	}
}
