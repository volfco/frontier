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
	"github.com/raystack/salt/log"
)

type oidcProvider struct {
	logger   log.Logger
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

func newOIDCProvider(authn v1beta1connect.AuthnService, sessions v1beta1connect.SessionService, users v1beta1connect.UserService, groups v1beta1connect.GroupService, codec securecookie.Codec, issuer string, baseURL string, logger log.Logger) *oidcProvider {
	iss := issuer
	if strings.TrimSpace(iss) == "" {
		iss = strings.TrimRight(baseURL, "/")
	}
	return &oidcProvider{
		logger:   logger,
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

func (p *oidcProvider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if p.logger != nil {
		p.logger.Info("jwks served")
	}
	set := p.authn.JWKs(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(set)
}

func (p *oidcProvider) dispatchSSO(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "sso" {
		http.NotFound(w, r)
		return
	}
	strat := parts[1]
	if len(parts) >= 4 && parts[2] == ".well-known" {
		switch parts[3] {
		case "openid-configuration":
			if p.logger != nil {
				p.logger.Info("oidc discovery strategy", "strategy", strat, "issuer", p.issuer)
			}
			resp := map[string]any{
				"issuer":                                p.issuer,
				"authorization_endpoint":                p.baseURL + "/sso/" + strat + "/authorize",
				"token_endpoint":                        p.baseURL + "/sso/" + strat + "/token",
				"userinfo_endpoint":                     p.baseURL + "/sso/" + strat + "/userinfo",
				"jwks_uri":                              p.baseURL + "/sso/" + strat + "/.well-known/jwks.json",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
				"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
				"claims_supported":                      []string{"sub", "aud", "iss", "exp", "iat", "email", "name"},
				"grant_types_supported":                 []string{"authorization_code"},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		case "jwks.json":
			p.handleJWKS(w, r)
			return
		default:
			http.NotFound(w, r)
			return
		}
	}
	if p.logger != nil {
		p.logger.Debug("sso dispatch", "path", r.URL.Path, "action", parts[2])
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
	if strings.HasPrefix(r.URL.Path, "/sso/") && strings.HasSuffix(r.URL.Path, "/authorize") {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			strategy = parts[1]
		}
	}
	if responseType != "code" || clientID == "" || redirectURI == "" || state == "" {
		if p.logger != nil {
			p.logger.Warn("authorize invalid_request", "client_id", clientID, "redirect_uri", redirectURI, "state", state)
		}
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}

	var principal authenticate.Principal
	if p.codec == nil {
		if p.logger != nil {
			p.logger.Warn("authorize login_required: codec missing")
		}
		http.Error(w, "login_required", http.StatusUnauthorized)
		return
	}
	var sessionIDStr string
	for _, c := range r.Cookies() {
		if c.Name == consts.SessionRequestKey {
			if err := p.codec.Decode(c.Name, c.Value, &sessionIDStr); err == nil {
				break
			} else {
				if p.logger != nil {
					p.logger.Debug("authorize session decode failed", "err", err)
				}
			}
		}
	}
	sid, err := uuid.Parse(strings.TrimSpace(sessionIDStr))
	if err != nil {
		if p.logger != nil {
			p.logger.Warn("authorize login_required: invalid session id", "err", err)
		}
		http.Error(w, "login_required", http.StatusUnauthorized)
		return
	}
	sess, err := p.sessions.GetByID(r.Context(), sid)
	if err != nil || sess == nil || !sess.IsValid(time.Now().UTC()) || strings.TrimSpace(sess.UserID) == "" {
		if p.logger != nil {
			p.logger.Warn("authorize login_required: invalid session")
		}
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
	if p.logger != nil {
		p.logger.Info("authorize code issued", "client_id", clientID, "strategy", strategy)
	}

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
		if p.logger != nil {
			p.logger.Warn("token invalid_request: parse error", "err", err)
		}
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	grantType := strings.TrimSpace(r.PostForm.Get("grant_type"))
	code := strings.TrimSpace(r.PostForm.Get("code"))
	clientID := strings.TrimSpace(r.PostForm.Get("client_id"))
	if grantType != "authorization_code" || code == "" || clientID == "" {
		if p.logger != nil {
			p.logger.Warn("token invalid_request", "grant_type", grantType, "client_id", clientID)
		}
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
		if p.logger != nil {
			p.logger.Warn("token invalid_grant", "client_id", clientID)
		}
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
		if p.logger != nil {
			p.logger.Error("token server_error: id token build failed", "err", err)
		}
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}
	accessClaims := map[string]string{}
	if strings.TrimSpace(data.Scope) != "" {
		accessClaims["scope"] = data.Scope
	}
	accessToken, err := p.authn.BuildToken(r.Context(), data.Principal, accessClaims)
	if err != nil {
		if p.logger != nil {
			p.logger.Error("token server_error: access token build failed", "err", err)
		}
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}

	resp := map[string]any{
		"access_token": string(accessToken),
		"id_token":     string(idToken),
		"token_type":   "Bearer",
		"expires_in":   int(3600),
	}
	if p.logger != nil {
		p.logger.Info("token issued", "client_id", data.ClientID, "principal_id", data.Principal.ID)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (p *oidcProvider) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	tokenVal := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if tokenVal == "" {
		if p.logger != nil {
			p.logger.Warn("userinfo invalid_token: missing bearer")
		}
		http.Error(w, "invalid_token", http.StatusUnauthorized)
		return
	}
	principal, err := p.authn.GetPrincipal(r.Context(), authenticate.AccessTokenClientAssertion)
	if err != nil || principal.ID == "" {
		if p.logger != nil {
			p.logger.Warn("userinfo invalid_token: principal error", "err", err)
		}
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
	if p.logger != nil {
		p.logger.Info("userinfo served", "principal_id", principal.ID)
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
