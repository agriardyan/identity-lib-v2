package filter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agriardyan/identity-lib-v2/claim"
	"github.com/dgrijalva/jwt-go"
	"github.com/emicklei/go-restful"

	"github.com/stretchr/testify/assert"
)

func TestMatchOneClaim(t *testing.T) {
	auth := NewSymmetric("testKey")

	claimedResource := []string{"external", "fnb", "namespaceA", "kiosk", "123456", "customer"}
	requiredResource := []string{"external", "fnb", "namespaceA", "kiosk", "123456", "customer"}
	testResult := auth.matchOneClaim(claimedResource, requiredResource)
	assert.Equal(t, true, testResult)

	claimedResource = []string{"external", "fnb", "namespaceA", "kiosk", "123456", "customer"}
	requiredResource = []string{"external", "fnb", "namespaceA", "kiosk", "*", "customer"}
	testResult = auth.matchOneClaim(claimedResource, requiredResource)
	assert.Equal(t, true, testResult)

	claimedResource = []string{"external", "fnb", "namespaceA", "kiosk", "*", "customer"}
	requiredResource = []string{"external", "fnb", "namespaceA", "kiosk", "12345", "customer"}
	testResult = auth.matchOneClaim(claimedResource, requiredResource)
	assert.Equal(t, true, testResult)

	claimedResource = []string{"external", "fnb", "*", "kiosk", "*", "customer"}
	requiredResource = []string{"external", "fnb", "namespaceA", "kiosk", "12345", "customer"}
	testResult = auth.matchOneClaim(claimedResource, requiredResource)
	assert.Equal(t, true, testResult)

	claimedResource = []string{"external", "fnb", "namespaceA", "kiosk", "*"}
	requiredResource = []string{"external", "fnb", "namespaceA", "kiosk", "12345"}
	testResult = auth.matchOneClaim(claimedResource, requiredResource)
	assert.Equal(t, true, testResult)

	claimedResource = []string{"external", "fnb", "namespaceA", "kiosk", "123456", "customer"}
	requiredResource = []string{"internal", "fnb", "namespaceA", "kiosk", "*", "customer"}
	testResult = auth.matchOneClaim(claimedResource, requiredResource)
	assert.Equal(t, false, testResult)
}

var DummyHandlerResult = ""

func DummyHandler(initialResource string) func(req *restful.Request, resp *restful.Response) {
	return func(req *restful.Request, resp *restful.Response) {
		auth := NewSymmetric("testKey")
		DummyHandlerResult = auth.replacePlaceholders(initialResource, req)
	}
}

func TestReplacePlaceholder(t *testing.T) {

	initialResource1 := "external:fnb:namespace:{namespace}:menu"
	initialResource2 := "external:fnb:namespace:{namespace}:kiosk:{kioskId}"
	initialResource3 := "external:fnb:namespace:{namespace}:kiosk:{kioskId}"
	initialResource4 := "external:fnb:namespace:{namespace}:kiosk:*"

	ws := new(restful.WebService)
	ws.Consumes(restful.MIME_XML)
	ws.Route(ws.GET("/external/{namespace}").To(DummyHandler(initialResource1)))
	ws.Route(ws.GET("/external/{namespace}/kiosk/{kioskId}/menu").To(DummyHandler(initialResource2)))
	ws.Route(ws.GET("/external/{namespace}/kiosk/{kioskId}/menu/people/{peopleId}").To(DummyHandler(initialResource3)))
	ws.Route(ws.GET("/external/{namespace}/kiosk/{kioskId}").To(DummyHandler(initialResource4)))
	restful.Add(ws)

	bodyReader := strings.NewReader("")
	httpRequest, _ := http.NewRequest("GET", "/external/abcnamespace", bodyReader)
	httpRequest.Header.Set("Content-Type", restful.MIME_XML)
	httpWriter := httptest.NewRecorder()

	restful.DefaultContainer.ServeHTTP(httpWriter, httpRequest)

	// this is rather stupid approach for test, but gorestful didn't write the interface and I'm too lazy to wrap restful.Request just for test
	expectedResource := "external:fnb:namespace:abcnamespace:menu"
	assert.Equal(t, expectedResource, DummyHandlerResult, "Should replace placeholder")

	httpRequest, _ = http.NewRequest("GET", "/external/abcnamespace/kiosk/kioskabc/menu", bodyReader)
	restful.DefaultContainer.ServeHTTP(httpWriter, httpRequest)

	expectedResource = "external:fnb:namespace:abcnamespace:kiosk:kioskabc"
	assert.Equal(t, expectedResource, DummyHandlerResult, "Should replace placeholder")

	httpRequest, _ = http.NewRequest("GET", "/external/abcnamespace/kiosk/kioskabc/menu/people/john", bodyReader)
	restful.DefaultContainer.ServeHTTP(httpWriter, httpRequest)

	expectedResource = "external:fnb:namespace:abcnamespace:kiosk:kioskabc"
	assert.Equal(t, expectedResource, DummyHandlerResult, "Should not append anything")

	httpRequest, _ = http.NewRequest("GET", "/external/abcnamespace/kiosk/kioskabc", bodyReader)
	restful.DefaultContainer.ServeHTTP(httpWriter, httpRequest)

	expectedResource = "external:fnb:namespace:abcnamespace:kiosk:*"
	assert.Equal(t, expectedResource, DummyHandlerResult, "Should not change the *")
}

func TestMatchWithClaims(t *testing.T) {
	auth := NewSymmetric("testKey")

	testClaimedPerm := make(map[string]int)
	testClaimedPerm["internal:hrm:namespace:abcnamespace:kiosk:*"] = 1
	testClaimedPerm["internal:hrm:namespace:abcnamespace:menu"] = 3
	testClaimedPerm["external:fnb:namespace:abcnamespace:discount"] = 15

	requiredResource := "internal:hrm:namespace:*:kiosk:*"
	result := auth.matchWithClaims(requiredResource, 1, testClaimedPerm)
	assert.Equal(t, true, result, "Should match")

	requiredResource = "internal:hrm:namespace:*:menu"
	result = auth.matchWithClaims(requiredResource, 1, testClaimedPerm)
	assert.Equal(t, true, result, "Should match")

	requiredResource = "internal:hrm:namespace:*:menu"
	result = auth.matchWithClaims(requiredResource, 2, testClaimedPerm)
	assert.Equal(t, true, result, "Should match")

	requiredResource = "internal:hrm:namespace:*:menu"
	result = auth.matchWithClaims(requiredResource, 8, testClaimedPerm)
	assert.Equal(t, false, result, "Should not match")

	requiredResource = "internal:fnb:namespace:*:discount"
	result = auth.matchWithClaims(requiredResource, 8, testClaimedPerm)
	assert.Equal(t, false, result, "Should not match")
}

type testInput_authorizationHandler struct {
	req                *restful.Request
	requiredPermission string
	requiredAction     int
}

type testExpected_authorizationHandler struct {
	claim *claim.IdentityClaim
	err   error
}

type testScenario_authorizationHandler struct {
	message  string
	auth     *AuthFilter
	input    testInput_authorizationHandler
	expected testExpected_authorizationHandler
}

func TestAuthorizationHandler(t *testing.T) {
	userClaim := &claim.IdentityClaim{
		Permissions: map[string]int{
			"svc:namespace:*:resource":  15,
			"svc:namespace:*:resource2": 2,
			"svc:namespace:*:resource3": 8,
		},
	}
	auth := NewSymmetric("123")
	authWithParser := NewSymmetricWithParser("123", func(tokenString string, keyFunc jwt.Keyfunc) (*jwt.Token, *claim.IdentityClaim, error) {
		claimObj := userClaim
		return nil, claimObj, nil
	})
	authWithExpiredParser := &AuthFilter{
		secretKey: "123",
		jwtParserFunc: func(tokenString string, keyFunc jwt.Keyfunc) (*jwt.Token, *claim.IdentityClaim, error) {
			return nil, nil, jwt.NewValidationError("", jwt.ValidationErrorExpired)
		},
	}
	authWithInvalidToken := &AuthFilter{
		secretKey: "123",
		jwtParserFunc: func(tokenString string, keyFunc jwt.Keyfunc) (*jwt.Token, *claim.IdentityClaim, error) {
			return nil, nil, jwt.NewValidationError("", jwt.ValidationErrorSignatureInvalid)
		},
	}
	testScenarios := []testScenario_authorizationHandler{
		{
			message: "Request header does not contains Authorization",
			auth:    auth,
			input: testInput_authorizationHandler{
				req:                restful.NewRequest(&http.Request{Header: http.Header{"Authorization": []string{""}}}),
				requiredPermission: "svc:namespace:*:resource",
				requiredAction:     2,
			},
			expected: testExpected_authorizationHandler{
				err: ErrUnauthorized,
			},
		},
		{
			message: "Authorization header does not contains Bearer token",
			auth:    auth,
			input: testInput_authorizationHandler{
				req:                restful.NewRequest(&http.Request{Header: http.Header{"Authorization": []string{"Basic ..."}}}),
				requiredPermission: "svc:namespace:*:resource",
				requiredAction:     2,
			},
			expected: testExpected_authorizationHandler{
				err: ErrUnauthorized,
			},
		},
		{
			message: "Token is expired",
			auth:    authWithExpiredParser,
			input: testInput_authorizationHandler{
				req:                restful.NewRequest(&http.Request{Header: http.Header{"Authorization": []string{"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE2MjY0OTk2MDB9.arPjT1st5PHKxjPyPnr6u9qruseA2ph6PUWNlIrMes4"}}}),
				requiredPermission: "svc:namespace:*:resource",
				requiredAction:     2,
			},
			expected: testExpected_authorizationHandler{
				err: ErrExpiredToken,
			},
		},
		{
			message: "Token is invalid",
			auth:    authWithInvalidToken,
			input: testInput_authorizationHandler{
				req:                restful.NewRequest(&http.Request{Header: http.Header{"Authorization": []string{"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE2MjY0OTk2MDB9.arPjT1st5PHKxjPyPnr6u9qruseA2ph6PUWNlIrMes4"}}}),
				requiredPermission: "svc:namespace:*:resource",
				requiredAction:     2,
			},
			expected: testExpected_authorizationHandler{
				err: ErrInvalidToken,
			},
		},
		{
			message: "Delete is forbidden because not enough privilege",
			auth:    authWithParser,
			input: testInput_authorizationHandler{
				req:                restful.NewRequest(&http.Request{Header: http.Header{"Authorization": []string{"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE2MjY0OTk2MDAsInBlcm1pc3Npb25zIjp7InN2YzpuYW1lc3BhY2U6KjpyZXNvdXJjZSI6Miwic3ZjOm5hbWVzcGFjZToqOnJlc291cmNlMiI6MTV9fQ.qr3aUPEU0ESXpRyDE3Bjbe2CD6dSBIgm2jokz4vzukw"}}}),
				requiredPermission: "svc:namespace:*:resource2",
				requiredAction:     8,
			},
			expected: testExpected_authorizationHandler{
				err: ErrForbidden,
			},
		},
		{
			message: "Read is allowed",
			auth:    authWithParser,
			input: testInput_authorizationHandler{
				req:                restful.NewRequest(&http.Request{Header: http.Header{"Authorization": []string{"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE2MjY0OTk2MDAsInBlcm1pc3Npb25zIjp7InN2YzpuYW1lc3BhY2U6KjpyZXNvdXJjZSI6Miwic3ZjOm5hbWVzcGFjZToqOnJlc291cmNlMiI6MTV9fQ.qr3aUPEU0ESXpRyDE3Bjbe2CD6dSBIgm2jokz4vzukw"}}}),
				requiredPermission: "svc:namespace:*:resource",
				requiredAction:     2,
			},
			expected: testExpected_authorizationHandler{
				claim: userClaim,
				err:   nil,
			},
		},
		{
			message: "Delete is allowed",
			auth:    authWithParser,
			input: testInput_authorizationHandler{
				req:                restful.NewRequest(&http.Request{Header: http.Header{"Authorization": []string{"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE2MjY0OTk2MDAsInBlcm1pc3Npb25zIjp7InN2YzpuYW1lc3BhY2U6KjpyZXNvdXJjZSI6Miwic3ZjOm5hbWVzcGFjZToqOnJlc291cmNlMiI6MTV9fQ.qr3aUPEU0ESXpRyDE3Bjbe2CD6dSBIgm2jokz4vzukw"}}}),
				requiredPermission: "svc:namespace:*:resource3",
				requiredAction:     8,
			},
			expected: testExpected_authorizationHandler{
				claim: userClaim,
				err:   nil,
			},
		},
	}

	for _, testScenario := range testScenarios {
		claim, err := testScenario.auth.authorizeHandler(testScenario.input.req, testScenario.input.requiredPermission, testScenario.input.requiredAction)
		assert.Equal(t, testScenario.expected.claim, claim)
		assert.Equal(t, testScenario.expected.err, err)
	}
}
