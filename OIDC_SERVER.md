# Frontier OIDC Provider

This document describes the minimal OpenID Connect (OIDC) Provider built into the Frontier Connect server, how it works, how to operate it, and how to use it from a client.

## Overview

- Implements a basic Authorization Code flow with discovery, token, userinfo, and JWKS endpoints.
- Endpoints are served on the Frontier Connect server port, using the configured issuer or defaulting to the Connect base URL.
- Tokens are signed using Frontier's token service (RSA JWKs) and exposed via JWKS for verification.
- Authorization depends on Frontier sessions; `/oauth2/authorize` requires a valid `sid` cookie set by existing login flows.

## Endpoints

- Discovery: `GET /.well-known/openid-configuration`
- JWKS: `GET /.well-known/jwks.json`
- Authorize: `GET /oauth2/authorize`
- Token: `POST /oauth2/token` (form-encoded)
- UserInfo: `GET /userinfo`

## Issuer and Base URL

- Issuer: If `authentication.token.issuer` is configured, the discovery document uses it. Otherwise, issuer falls back to the Connect server base URL.
- Base URL: Built from `host` and `connect.port` and used for discovery document endpoint URLs.

## Prerequisites

- Token signing keys configured (RSA JWKs) and available to Frontier's token service.
  - Frontier builds tokens with its key set; make sure keys exist or token operations will be disabled.
- Session management configured with 32-byte `authentication.session.hash_secret_key` and `authentication.session.block_secret_key`.
  - Without valid session codec keys, `/oauth2/authorize` returns `login_required`.
- Connect server running with CORS configuration appropriate for your client.

## Flow

1. Discovery
   - Fetch configuration at `/.well-known/openid-configuration` to obtain endpoints and capabilities.

2. Login / Session
   - Use existing Frontier auth flows to create a session; browser receives a secure `sid` cookie.
   - The OIDC provider relies on that session to authenticate the user at `/oauth2/authorize`.

3. Authorization Request
   - Send a GET request to `/oauth2/authorize` with query parameters:
     - `response_type=code`
     - `client_id=<your_client_id>`
     - `redirect_uri=<your_redirect_uri>`
     - `scope=openid email profile` (as needed)
     - `state=<opaque_state>`
     - `nonce=<opaque_nonce>`
   - The endpoint validates session and redirects to `redirect_uri` with `code` and `state`.

4. Token Exchange
   - POST to `/oauth2/token` (Content-Type: `application/x-www-form-urlencoded`) with:
     - `grant_type=authorization_code`
     - `code=<code_received>`
     - `client_id=<your_client_id>`
   - Response includes:
     - `id_token` (JWT with `aud`, `nonce`, `iss`, `sub`, etc.)
     - `access_token` (Frontier JWT)
     - `token_type=Bearer`
     - `expires_in=<seconds>`

5. UserInfo
   - Request `GET /userinfo` with `Authorization: Bearer <access_token>`.
   - Response includes `sub` and, when available, `email` and `name`.

## Examples

Discovery:

```sh
curl -s http://<host>:<connect_port>/.well-known/openid-configuration | jq
```

Authorize (browser-based, requires `sid` cookie):

```sh
open "http://<host>:<connect_port>/oauth2/authorize?response_type=code&client_id=<cid>&redirect_uri=<cb>&scope=openid%20email&state=<state>&nonce=<nonce>"
```

Token exchange:

```sh
curl -s -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  -d 'code=<code>' \
  -d 'client_id=<cid>' \
  http://<host>:<connect_port>/oauth2/token
```

UserInfo:

```sh
curl -s -H 'Authorization: Bearer <access_token>' \
  http://<host>:<connect_port>/userinfo
```

JWKS:

```sh
curl -s http://<host>:<connect_port>/.well-known/jwks.json | jq
```

## Operational Details

- Server wiring: Endpoints are registered on the Connect mux during server startup.
- Issuer fallback: If no issuer is configured, the OIDC provider uses the Connect base URL to keep discovery consistent.
- Sessions: The provider decodes the `sid` cookie using the configured secure cookie codec; requests without a valid session receive `login_required`.
- Tokens: Both `id_token` and `access_token` are built using Frontier's AuthnService; JWKS exposes public keys for verification.
- CORS: The Connect server applies CORS middleware; ensure `AllowedOrigins` includes your client application domains.

## Error Responses

- `invalid_request`: Missing or malformed parameters.
- `login_required`: No valid session cookie (`sid`) or session is invalid/expired.
- `invalid_grant`: Code is missing, expired, or does not match `client_id`.
- `invalid_token`: UserInfo called without a valid bearer token.
- `server_error`: Internal error building tokens.

## Limitations and Next Steps

- Client registration and secret validation are not enforced by default.
  - To harden, add client storage, validate `redirect_uri`, and support `client_secret_basic` or `PKCE`.
- `redirect_uri` trust model should be tightened for production (whitelists/regex).
- Add auditing and metrics specific to OIDC flows if required.

## Configuration Tips

- Set `authentication.token.issuer` to a stable HTTPS URL reachable by clients.
- Ensure token keys are generated and loaded so JWKS is populated and tokens are verifiable.
- Configure session cookie attributes (`domain`, `secure`, `same_site`) according to your deployment.
- Align Connect port and host with reverse proxy settings if you are fronting Frontier behind a gateway.

## Troubleshooting

- Discovery shows incorrect URLs: Verify `host` and `connect.port`, and check issuer configuration.
- `login_required` on `/oauth2/authorize`: Ensure the `sid` cookie exists and is valid; log in via Frontier before initiating OIDC.
- Token verification fails: Check JWKS availability and that your verifier uses the provided `kid` and `RS256`.
- `userinfo` returns empty `email`/`name`: Ensure the user exists and has those fields set.

