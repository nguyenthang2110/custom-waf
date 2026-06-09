package auth

import (
	"fmt"
	"strings"
	"time"

	"waf-project/internal/models"

	"github.com/golang-jwt/jwt/v5"
)

// minSecretLen is the floor for the HMAC-SHA256 signing key. 32 bytes ≈ 256
// bits, matching the security level of HS256's output. Below that, the
// key becomes the weakest link and brute-force feasibility climbs fast.
const minSecretLen = 32

// placeholderSecrets are strings shipped in the example config / docs that
// must never reach production. Matched case-insensitively against the
// whole secret so partial overlap doesn't trigger a false positive.
var placeholderSecrets = []string{
	"your-secret-key-change-this-in-production-256-bit-minimum",
	"change-me",
	"changeme",
	"secret",
	"please-change",
}

// Claims represents JWT claims
type Claims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// JWTManager handles JWT operations
type JWTManager struct {
	secret  []byte
	expiry  time.Duration
	revoker Revoker // optional — nil disables logout-revocation checks
}

// SetRevoker wires a revocation backend into the manager. Without one,
// ValidateToken can't tell logged-out-but-not-expired tokens from valid
// ones, so logouts only clear cookies (not Bearer-presented tokens).
func (m *JWTManager) SetRevoker(r Revoker) {
	m.revoker = r
}

// jwtIssuer and jwtAudience are stamped into every token issued by this
// manager and verified on every token validated. Binding tokens to the
// issuing service means a token leaked into another deployment that
// happens to reuse this secret (mistake during key rotation, shared
// dev/prod secret) will be rejected because it carries the wrong `iss`.
// The audience claim guards the same way for downstream consumers.
const (
	jwtIssuer   = "waf-project"
	jwtAudience = "waf-dashboard"
)

// NewJWTManager creates a new JWT manager. Fails hard if the secret is
// empty, too short, or matches a known placeholder — every JWT signed with
// a weak key is one offline brute-force away from total auth bypass, so
// we'd rather refuse to start than silently sign trust-anchor tokens with
// "change-me".
func NewJWTManager(secret string, expiryStr string) (*JWTManager, error) {
	expiry, err := time.ParseDuration(expiryStr)
	if err != nil {
		return nil, fmt.Errorf("invalid expiry duration: %w", err)
	}

	trimmed := strings.TrimSpace(secret)
	if trimmed == "" {
		return nil, fmt.Errorf("auth.jwt_secret is empty — set a random ≥%d-byte secret in configs/config.yaml", minSecretLen)
	}
	if len(trimmed) < minSecretLen {
		return nil, fmt.Errorf("auth.jwt_secret is %d bytes — need at least %d (use `openssl rand -hex 32` to generate one)", len(trimmed), minSecretLen)
	}
	lowered := strings.ToLower(trimmed)
	for _, ph := range placeholderSecrets {
		if lowered == strings.ToLower(ph) {
			return nil, fmt.Errorf("auth.jwt_secret still set to the placeholder %q — replace it before starting", ph)
		}
	}

	return &JWTManager{
		secret: []byte(secret),
		expiry: expiry,
	}, nil
}

// GenerateToken creates a new JWT token for a user. Every token gets a
// crypto-random jti so it can be individually revoked at logout — without
// a jti, /logout could only invalidate cookies, leaving any Bearer-
// presented copies of the same token usable until natural expiry.
func (m *JWTManager) GenerateToken(user *models.User) (string, error) {
	jti, err := newJTI()
	if err != nil {
		return "", fmt.Errorf("failed to generate jti: %w", err)
	}
	now := time.Now()
	claims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    jwtIssuer,
			Audience:  jwt.ClaimStrings{jwtAudience},
			Subject:   fmt.Sprintf("%d", user.ID),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.expiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken validates a JWT token and returns claims. Beyond signature
// and expiry, we also enforce the issuer + audience binding stamped by
// GenerateToken — a token issued for a different deployment that somehow
// got presented here is rejected even if its signature checks out under
// our key.
func (m *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			// Pin to HS256 explicitly — defence-in-depth against the
			// classic alg:none / RS↔HS confusion bugs.
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return m.secret, nil
		},
		jwt.WithIssuer(jwtIssuer),
		jwt.WithAudience(jwtAudience),
		jwt.WithValidMethods([]string{"HS256"}),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Revocation check — a logged-out token's jti lives in the revoker
	// until its natural exp passes. Without a revoker we skip the check
	// (degraded mode; logout still clears the cookie).
	if m.revoker != nil && claims.ID != "" && m.revoker.IsRevoked(claims.ID) {
		return nil, fmt.Errorf("token has been revoked")
	}

	return claims, nil
}

// RevokeToken parses tokenString (without enforcing revocation, since the
// whole point is to revoke it) and pushes its jti into the configured
// revoker. The caller — handleLogout — uses this to make the token
// useless across both cookie and Bearer-header paths.
//
// Returns nil even if the token is malformed: revoking a bad token is a
// no-op rather than an error, so a confused client can still log out.
func (m *JWTManager) RevokeToken(tokenString string) error {
	if m.revoker == nil {
		return nil // no backend wired — logout is cookie-only
	}
	// Parse without invoking the revoker check; we want jti + exp even
	// if the token is technically revoked already.
	token, _, err := jwt.NewParser(
		jwt.WithIssuer(jwtIssuer),
		jwt.WithAudience(jwtAudience),
		jwt.WithValidMethods([]string{"HS256"}),
	).ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return nil // malformed — nothing to revoke
	}
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil
	}
	exp := time.Time{}
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Time
	}
	m.revoker.Revoke(claims.ID, exp)
	return nil
}

// ExtractUserID extracts user ID from token
func (m *JWTManager) ExtractUserID(tokenString string) (int, error) {
	claims, err := m.ValidateToken(tokenString)
	if err != nil {
		return 0, err
	}
	return claims.UserID, nil
}
