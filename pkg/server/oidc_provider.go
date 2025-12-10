package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/raystack/frontier/core/authenticate"
	"github.com/raystack/frontier/core/group"
	"github.com/raystack/frontier/core/user"
	"github.com/raystack/frontier/internal/api/v1beta1connect"
	"github.com/raystack/frontier/pkg/server/consts"
)

type oidcProvider struct {
	authn    v1beta1connect.AuthnService
	sessions v1beta1connect.SessionService
	users    v1beta1connect.UserService
	groups   v1beta1connect.GroupService
	codec    securecookie.Codec
	issuer   string
	baseURL  string

	mu    sync.Mutex
	codes map[string]authCodeData
}

type authCodeData struct {
	ClientID    string
	RedirectURI string
	Scope       string
	State       string
	Nonce       string
	Strategy    string
	Principal   authenticate.Principal
	Expiry      time.Time
}

func newOIDCProvider(authn v1beta1connect.AuthnService, sessions v1beta1connect.SessionService, users v1beta1connect.UserService, groups v1beta1connect.GroupService, codec securecookie.Codec, issuer string, baseURL string) *oidcProvider {
	iss := issuer
	if strings.TrimSpace(iss) == "" {
		iss = strings.TrimRight(baseURL, "/")
	}
	return &oidcProvider{
		authn:    authn,
		sessions: sessions,
		users:    users,
		groups:   groups,
		codec:    codec,
		issuer:   iss,
		baseURL:  strings.TrimRight(baseURL, "/"),
		codes:    map[string]authCodeData{},
	}
}

func (p *oidcProvider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"issuer":                                p.issuer,
		"authorization_endpoint":                p.baseURL + "/oidc/oidc/authorize",
		"token_endpoint":                        p.baseURL + "/oidc/oidc/token",
		"userinfo_endpoint":                     p.baseURL + "/oidc/oidc/userinfo",
		"jwks_uri":                              p.baseURL + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
		"claims_supported":                      []string{"sub", "aud", "iss", "exp", "iat", "email", "name"},
		"grant_types_supported":                 []string{"authorization_code"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleDiscoveryWithStrategy returns endpoints bound under a given strategy path
func (p *oidcProvider) handleDiscoveryWithStrategy(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/.well-known/openid-configuration/")
	strat := strings.Trim(path, "/")
	if strat == "" {
		p.handleDiscovery(w, r)
		return
	}
	resp := map[string]any{
		"issuer":                                p.issuer,
		"authorization_endpoint":                p.baseURL + "/oidc/" + strat + "/authorize",
		"token_endpoint":                        p.baseURL + "/oidc/" + strat + "/token",
		"userinfo_endpoint":                     p.baseURL + "/oidc/" + strat + "/userinfo",
		"jwks_uri":                              p.baseURL + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
		"claims_supported":                      []string{"sub", "aud", "iss", "exp", "iat", "email", "name"},
		"grant_types_supported":                 []string{"authorization_code"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (p *oidcProvider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	set := p.authn.JWKs(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(set)
}

func (p *oidcProvider) dispatchOIDC(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "oidc" {
		http.NotFound(w, r)
		return
	}
	switch parts[2] {
	case "authorize":
		p.handleAuthorize(w, r)
	case "token":
		p.handleToken(w, r)
	case "userinfo":
		p.handleUserInfo(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (p *oidcProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	responseType := strings.TrimSpace(q.Get("response_type"))
	clientID := strings.TrimSpace(q.Get("client_id"))
	redirectURI := strings.TrimSpace(q.Get("redirect_uri"))
	scope := strings.TrimSpace(q.Get("scope"))
	state := strings.TrimSpace(q.Get("state"))
	nonce := strings.TrimSpace(q.Get("nonce"))
	strategy := "oidc"
	if strings.HasPrefix(r.URL.Path, "/oidc/") && strings.HasSuffix(r.URL.Path, "/authorize") {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			strategy = parts[1]
		}
	}
	if responseType != "code" || clientID == "" || redirectURI == "" || state == "" {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}

	var principal authenticate.Principal
	if p.codec == nil {
		http.Error(w, "login_required", http.StatusUnauthorized)
		return
	}
	var sessionIDStr string
	for _, c := range r.Cookies() {
		if c.Name == consts.SessionRequestKey {
			if err := p.codec.Decode(c.Name, c.Value, &sessionIDStr); err == nil {
				break
			}
		}
	}
	sid, err := uuid.Parse(strings.TrimSpace(sessionIDStr))
	if err != nil {
		http.Error(w, "login_required", http.StatusUnauthorized)
		return
	}
	sess, err := p.sessions.GetByID(r.Context(), sid)
	if err != nil || sess == nil || !sess.IsValid(time.Now().UTC()) || strings.TrimSpace(sess.UserID) == "" {
		http.Error(w, "login_required", http.StatusUnauthorized)
		return
	}
	principal = authenticate.Principal{ID: sess.UserID, Type: "app/user"}

	code := uuid.NewString()
	p.mu.Lock()
	p.codes[code] = authCodeData{
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       scope,
		State:       state,
		Nonce:       nonce,
		Strategy:    strategy,
		Principal:   principal,
		Expiry:      time.Now().UTC().Add(10 * time.Minute),
	}
	p.mu.Unlock()

	u, _ := url.Parse(redirectURI)
	q2 := u.Query()
	q2.Set("code", code)
	q2.Set("state", state)
	u.RawQuery = q2.Encode()
	w.Header().Set("Location", u.String())
	w.WriteHeader(http.StatusFound)
}

func (p *oidcProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	grantType := strings.TrimSpace(r.PostForm.Get("grant_type"))
	code := strings.TrimSpace(r.PostForm.Get("code"))
	clientID := strings.TrimSpace(r.PostForm.Get("client_id"))
	if grantType != "authorization_code" || code == "" || clientID == "" {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	data, ok := p.codes[code]
	if ok && time.Now().UTC().After(data.Expiry) {
		ok = false
	}
	if !ok || data.ClientID != clientID {
		p.mu.Unlock()
		http.Error(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	delete(p.codes, code)
	p.mu.Unlock()

	idClaims := map[string]string{
		"aud":   data.ClientID,
		"nonce": data.Nonce,
	}
	if strings.Contains(data.Scope, "groups") {
		// fetch groups for principal
		groupsList, err := p.groups.ListByUser(r.Context(), data.Principal.ID, data.Principal.Type, group.Filter{})
		if err == nil && len(groupsList) > 0 {
			ids := make([]string, 0, len(groupsList))
			for _, g := range groupsList {
				ids = append(ids, g.ID)
			}
			// encode groups claim via Authn token builder metadata
			idClaims["groups"] = strings.Join(ids, ",")
		}
	}
	if strings.TrimSpace(data.Scope) != "" {
		idClaims["scope"] = data.Scope
	}
	idToken, err := p.authn.BuildToken(r.Context(), data.Principal, idClaims)
	if err != nil {
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}
	accessClaims := map[string]string{}
	if strings.TrimSpace(data.Scope) != "" {
		accessClaims["scope"] = data.Scope
	}
	accessToken, err := p.authn.BuildToken(r.Context(), data.Principal, accessClaims)
	if err != nil {
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}

	resp := map[string]any{
		"access_token": string(accessToken),
		"id_token":     string(idToken),
		"token_type":   "Bearer",
		"expires_in":   int(3600),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (p *oidcProvider) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	tokenVal := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if tokenVal == "" {
		http.Error(w, "invalid_token", http.StatusUnauthorized)
		return
	}
	principal, err := p.authn.GetPrincipal(r.Context(), authenticate.AccessTokenClientAssertion)
	if err != nil || principal.ID == "" {
		http.Error(w, "invalid_token", http.StatusUnauthorized)
		return
	}
	var email string
	var name string
	var u user.User
	u, err = p.users.GetByID(r.Context(), principal.ID)
	if err == nil {
		email = u.Email
		name = u.Title
	}
	resp := map[string]any{
		"sub":   principal.ID,
		"email": email,
		"name":  name,
	}
	tok, err := jwtParseInsecure(tokenVal)
	if err == nil {
		if scope, ok := tok["scope"].(string); ok && strings.Contains(scope, "groups") {
			groupsList, gErr := p.groups.ListByUser(r.Context(), principal.ID, principal.Type, group.Filter{})
			if gErr == nil && len(groupsList) > 0 {
				ids := make([]string, 0, len(groupsList))
				for _, g := range groupsList {
					ids = append(ids, g.ID)
				}
				resp["groups"] = ids
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func jwtParseInsecure(token string) (map[string]any, error) {
	var claims map[string]any
	if strings.HasPrefix(strings.TrimSpace(token), "{") {
		if err := json.Unmarshal([]byte(token), &claims); err == nil {
			return claims, nil
		}
	}
	return map[string]any{"scope": ""}, nil
}
