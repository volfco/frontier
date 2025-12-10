package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/raystack/frontier/core/authenticate"
	frontiersession "github.com/raystack/frontier/core/authenticate/session"
	"github.com/raystack/frontier/core/group"
	"github.com/raystack/frontier/core/user"
	v1mocks "github.com/raystack/frontier/internal/api/v1beta1connect/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestDiscovery(t *testing.T) {
	authn := new(v1mocks.AuthnService)
	sessions := new(v1mocks.SessionService)
	users := new(v1mocks.UserService)
	groups := new(v1mocks.GroupService)
	codec := securecookie.New([]byte(strings.Repeat("h", 32)), []byte(strings.Repeat("b", 32)))
	p := newOIDCProvider(authn, sessions, users, groups, codec, "http://localhost:8002", "http://localhost:8002", nil)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	p.handleDiscovery(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	var got map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	require.Equal(t, "http://localhost:8002", got["issuer"])
	require.Equal(t, "http://localhost:8002/oidc/oidc/authorize", got["authorization_endpoint"])
}

func TestAuthorizeRedirect(t *testing.T) {
	authn := new(v1mocks.AuthnService)
	sessions := new(v1mocks.SessionService)
	users := new(v1mocks.UserService)
	groups := new(v1mocks.GroupService)
	codec := securecookie.New([]byte(strings.Repeat("h", 32)), []byte(strings.Repeat("b", 32)))
	p := newOIDCProvider(authn, sessions, users, groups, codec, "http://localhost:8002", "http://localhost:8002", nil)

	sid := uuid.New()
	cookieVal, err := codec.Encode("sid", sid.String())
	require.NoError(t, err)

	sess := &frontiersession.Session{ID: sid, UserID: "user-1", AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour)}
	sessions.EXPECT().GetByID(mock.Anything, sid).Return(sess, nil)

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "client")
	q.Set("redirect_uri", "http://app/cb")
	q.Set("scope", "openid email")
	q.Set("state", "xyz")
	q.Set("nonce", "abc")
	req := httptest.NewRequest(http.MethodGet, "/oidc/oidc/authorize?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: cookieVal})
	rr := httptest.NewRecorder()
	p.handleAuthorize(rr, req)
	require.Equal(t, http.StatusFound, rr.Code)
	loc := rr.Header().Get("Location")
	require.True(t, strings.HasPrefix(loc, "http://app/cb"))
	u, _ := url.Parse(loc)
	require.NotEmpty(t, u.Query().Get("code"))
	require.Equal(t, "xyz", u.Query().Get("state"))
}

func TestTokenExchange(t *testing.T) {
	authn := new(v1mocks.AuthnService)
	sessions := new(v1mocks.SessionService)
	users := new(v1mocks.UserService)
	groups := new(v1mocks.GroupService)
	codec := securecookie.New([]byte(strings.Repeat("h", 32)), []byte(strings.Repeat("b", 32)))
	p := newOIDCProvider(authn, sessions, users, groups, codec, "http://localhost:8002", "http://localhost:8002", nil)

	princ := authenticate.Principal{ID: "user-1", Type: "app/user"}
	code := "code-1"
	p.mu.Lock()
	p.codes[code] = authCodeData{ClientID: "client", RedirectURI: "http://app/cb", Scope: "openid", State: "s", Nonce: "n", Principal: princ, Expiry: time.Now().UTC().Add(time.Minute)}
	p.mu.Unlock()

	authn.EXPECT().BuildToken(mock.Anything, princ, mock.Anything).Return([]byte("IDTOKEN"), nil).Once()
	authn.EXPECT().BuildToken(mock.Anything, princ, mock.Anything).Return([]byte("ACCESSTOKEN"), nil).Once()

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", "client")
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	p.handleToken(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	var got map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	require.Equal(t, "IDTOKEN", got["id_token"])
	require.Equal(t, "ACCESSTOKEN", got["access_token"])
}

func TestUserInfo(t *testing.T) {
	authn := new(v1mocks.AuthnService)
	sessions := new(v1mocks.SessionService)
	users := new(v1mocks.UserService)
	groups := new(v1mocks.GroupService)
	codec := securecookie.New([]byte(strings.Repeat("h", 32)), []byte(strings.Repeat("b", 32)))
	p := newOIDCProvider(authn, sessions, users, groups, codec, "http://localhost:8002", "http://localhost:8002", nil)

	princ := authenticate.Principal{ID: "user-1", Type: "app/user", User: &user.User{Email: "a@b.com", Title: "Alice"}}
	authn.EXPECT().GetPrincipal(mock.Anything, authenticate.AccessTokenClientAssertion).Return(princ, nil)
	users.EXPECT().GetByID(mock.Anything, "user-1").Return(user.User{Email: "a@b.com", Title: "Alice"}, nil)
	groups.EXPECT().ListByUser(mock.Anything, "user-1", "app/user", mock.Anything).Return([]group.Group{{ID: "g1"}}, nil)

	// JSON token with scope including groups, sufficient for insecure parse
	req := httptest.NewRequest(http.MethodGet, "/oidc/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer {\"scope\":\"openid groups\",\"exp\":4102444800,\"jti\":\"x\"}")
	rr := httptest.NewRecorder()
	p.handleUserInfo(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	var got map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	require.Equal(t, "user-1", got["sub"])
	require.Equal(t, "a@b.com", got["email"])
	require.Equal(t, []any{"g1"}, got["groups"])
}
