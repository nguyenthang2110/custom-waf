// internal/api/auth_handlers.go
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	"waf-project/internal/models"
)

// minPasswordLen is the floor for any password the server will accept,
// applied uniformly to /register, admin-create, admin-reset, and the
// self-service /me/password change.
const minPasswordLen = 8

// usernameRe is the allow-list for usernames. Letters / digits / dot /
// underscore / dash, length 3-32. Anything else (angle brackets, quotes,
// whitespace) is rejected — this is the backend half of the XSS defence,
// the frontend escapes when rendering.
var usernameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{3,32}$`)

// validateUsername returns a non-nil error if s isn't a safe username.
// Used at /register and admin-create — username is immutable so this
// only runs on initial creation.
func validateUsername(s string) error {
	if !usernameRe.MatchString(s) {
		return fmt.Errorf("username must be 3-32 chars of letters, digits, dot, underscore or dash")
	}
	return nil
}

// validateEmail returns a non-nil error if s isn't a parseable email.
// We use net/mail.ParseAddress (RFC 5322-ish) rather than a regex —
// good enough to catch typos and reject obviously-malicious inputs like
// `<script>`@`evil`, without trying to be a full address validator.
// Maximum length 254 matches the SMTP envelope limit.
func validateEmail(s string) error {
	if len(s) > 254 {
		return fmt.Errorf("email must be at most 254 characters")
	}
	addr, err := mail.ParseAddress(s)
	if err != nil {
		return fmt.Errorf("email is not a valid address")
	}
	// ParseAddress accepts `Name <a@b>` — we want just the bare address.
	if addr.Address != s {
		return fmt.Errorf("email must not include a display name")
	}
	return nil
}

// RegisterRequest represents the PUBLIC registration request body.
// Note: any `role` field sent by a client is intentionally IGNORED by
// handleRegister — public sign-up always creates a viewer. Admins use
// POST /waf-api/auth/users to create elevated accounts.
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// AdminCreateUserRequest is the body for POST /waf-api/auth/users (admin
// only). Unlike RegisterRequest, Role IS honoured (and validated) here.
type AdminCreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// UpdateUserRequest is the body for PUT /waf-api/auth/users/{id} (admin)
// and the email-only subset of PUT /waf-api/auth/me. Empty fields mean
// "don't touch" — only non-empty values are applied.
type UpdateUserRequest struct {
	Email string `json:"email,omitempty"`
	Role  string `json:"role,omitempty"`
}

// ChangePasswordRequest is the body for POST /waf-api/auth/me/password.
// Requires the OldPassword so a stolen JWT alone can't rotate the
// victim's password (and lock them out).
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// AdminResetPasswordRequest is the body for POST /waf-api/auth/users/{id}/password.
// Admin reset does NOT require the target's old password — that's the
// whole point (helping locked-out users).
type AdminResetPasswordRequest struct {
	NewPassword string `json:"new_password"`
}

// LoginRequest represents login request body
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents login response
type LoginResponse struct {
	Token     string       `json:"token"`
	User      *models.User `json:"user"`
	ExpiresAt time.Time    `json:"expires_at"`
}

// ErrorResponse represents error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// handleRegister handles user registration
func (s *APIServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorJSON(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorJSON(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)

	// Validate input
	if req.Username == "" || req.Email == "" || req.Password == "" {
		writeErrorJSON(w, "Username, email, and password are required", http.StatusBadRequest)
		return
	}
	if err := validateUsername(req.Username); err != nil {
		writeErrorJSON(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateEmail(req.Email); err != nil {
		writeErrorJSON(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate password strength
	if len(req.Password) < minPasswordLen {
		writeErrorJSON(w, fmt.Sprintf("Password must be at least %d characters", minPasswordLen), http.StatusBadRequest)
		return
	}

	// SECURITY: public registration is HARD-CODED to viewer. Any `role`
	// field a client sends is dropped on the floor. Elevated roles are
	// created exclusively via POST /waf-api/auth/users (admin-gated).
	// This closes the privilege-escalation hole where anonymous users
	// could self-promote to admin by setting `"role":"admin"` in the body.
	const role = "viewer"

	// Create user in database
	user, err := s.userRepo.Create(req.Username, req.Email, req.Password, role, s.bcryptCost)
	if err != nil {
		if isUniqueViolation(err) {
			writeErrorJSON(w, "Username or email already exists", http.StatusConflict)
			return
		}
		writeErrorJSON(w, fmt.Sprintf("Failed to create user: %v", err), http.StatusInternalServerError)
		return
	}

	// Log the registration event
	s.auditLogger.LogSystemEvent("USER_REGISTERED",
		fmt.Sprintf("New user registered: %s (email: %s, role: %s)", user.Username, user.Email, user.Role))

	// Return user (without password hash)
	writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "User registered successfully",
		"user": map[string]interface{}{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
			"role":     user.Role,
		},
	})
}

// dummyBcryptHash is a real bcrypt hash of a random string, generated at
// package init. When /login can't find the requested user, we still spend
// ~bcrypt-cost time hashing the submitted password against this dummy hash
// so the response time is indistinguishable from the wrong-password case.
// Without this, an attacker can enumerate valid usernames by timing the
// difference between "user not found" (no bcrypt, ~ms) and "wrong password"
// (bcrypt, ~100ms).
var dummyBcryptHash []byte

func init() {
	// Cost 10 matches the typical bcryptCost. Even if the configured cost
	// differs slightly, the absolute difference (a few ms) is far below
	// what a network attacker can measure reliably.
	h, err := bcrypt.GenerateFromPassword([]byte("not-a-real-password-just-for-timing-parity"), 10)
	if err != nil {
		// bcrypt.GenerateFromPassword only fails on impossibly-large input
		// or cost out of range. With these fixed inputs it can't, but if
		// it somehow did we'd rather fall back to an empty hash than crash
		// at startup — CompareHashAndPassword will then fail in constant
		// (very small) time, which is acceptable as a degraded mode.
		dummyBcryptHash = []byte{}
		return
	}
	dummyBcryptHash = h
}

// handleLogin handles user login
func (s *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorJSON(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorJSON(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Constant-time auth path: regardless of whether the user exists, we
	// always run one bcrypt comparison so timing can't be used to enumerate
	// usernames. The first branch hashes against a real account; the
	// second hashes against a precomputed dummy hash so the work is the
	// same. Both end in a generic 401 with the same message.
	user, lookupErr := s.userRepo.GetByUsername(req.Username)
	var passwordOK bool
	if lookupErr == nil && user != nil {
		passwordOK = user.ValidatePassword(req.Password)
	} else {
		// User not found — still pay the bcrypt cost.
		_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(req.Password))
		passwordOK = false
	}
	if !passwordOK {
		writeErrorJSON(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Generate JWT token
	token, err := s.jwtManager.GenerateToken(user)
	if err != nil {
		writeErrorJSON(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Update last login
	if err := s.userRepo.UpdateLastLogin(user.ID); err != nil {
		// Log error but don't fail the login
		fmt.Printf("Failed to update last login: %v\n", err)
	}

	// Log the login event
	s.auditLogger.LogSystemEvent("USER_LOGIN",
		fmt.Sprintf("User logged in: %s (role: %s)", user.Username, user.Role))

	// Calculate expiration time
	expiresAt := time.Now().Add(24 * time.Hour) // Should match JWT expiry

	// Also set the token in an HttpOnly cookie so the browser sends it on
	// page navigations (the JSON body keeps the token visible for the SPA's
	// fetch() calls, which use the Bearer header). HttpOnly stops XSS from
	// reading the cookie; Secure is auto-enabled when the request arrived
	// over TLS so dev (HTTP) still works.
	http.SetCookie(w, &http.Cookie{
		Name:     "waf_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode, // Lax so login form POST + same-site navigation work
		MaxAge:   24 * 3600,
	})

	writeJSON(w, LoginResponse{
		Token:     token,
		User:      user,
		ExpiresAt: expiresAt,
	})
}

// handleLogout handles user logout. Two-step revocation:
//
//  1. The cookie is wiped client-side so browser navigations no longer
//     send a credential.
//  2. The presented token's jti is added to the server-side revocation
//     set so any cached Bearer copy (in localStorage, in a script's
//     fetch retry buffer, in a stolen-token attacker's hand) is rejected
//     by ValidateToken before its natural expiry.
//
// Step 2 was the missing piece in the previous implementation: deleting
// the cookie didn't stop Authorization-header auth from continuing for
// up to 24 h.
func (s *APIServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorJSON(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Revoke the token if one was presented. We do this BEFORE wiping
	// the cookie so the cookie path can still hand us the jti.
	if s.jwtManager != nil {
		if tok := extractToken(r); tok != "" {
			_ = s.jwtManager.RevokeToken(tok)
		}
	}

	// Expire the cookie. MaxAge -1 deletes it immediately.
	http.SetCookie(w, &http.Cookie{
		Name:     "waf_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Logged out successfully",
	})
}

// handleMe dispatches /waf-api/auth/me by method:
//
//	GET  → return current user
//	PUT  → update own profile (currently: email only)
//
// requireAuthN sits in front of this handler in RegisterRoutes so we
// always have a valid JWT here. The previous code only handled GET, so
// PUT used to fall through to writeErrorJSON.
func (s *APIServer) handleMe(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetCurrentUser(w, r)
	case http.MethodPut:
		s.handleUpdateOwnProfile(w, r)
	default:
		writeErrorJSON(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetCurrentUser handles getting current user info
func (s *APIServer) handleGetCurrentUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorJSON(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// requireAuthN attaches the JWT claims via withAuth(); fall back to
	// a fresh authenticate() call if auth is globally disabled but a
	// token was provided anyway.
	auth, ok := userFromContext(r)
	if !ok {
		ctxAuth, _ := s.authenticate(r)
		if ctxAuth == nil {
			writeErrorJSON(w, "User not found in context", http.StatusUnauthorized)
			return
		}
		auth = ctxAuth
	}

	user, err := s.userRepo.GetByID(auth.UserID)
	if err != nil {
		writeErrorJSON(w, "User not found", http.StatusNotFound)
		return
	}

	writeJSON(w, map[string]interface{}{
		"success": true,
		"user":    user,
	})
}

// handleUpdateOwnProfile lets a logged-in user update their own email.
// Username is immutable post-creation; role changes go through the admin
// path so the user can't promote themselves.
func (s *APIServer) handleUpdateOwnProfile(w http.ResponseWriter, r *http.Request) {
	auth, ok := s.currentUser(r)
	if !ok {
		writeErrorJSON(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorJSON(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		writeErrorJSON(w, "Email is required", http.StatusBadRequest)
		return
	}
	if err := validateEmail(req.Email); err != nil {
		writeErrorJSON(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Note: req.Role is intentionally ignored on the self-service path —
	// self-promotion would defeat the whole admin model. The /users/{id}
	// admin endpoint is the only way to change a role.

	if err := s.userRepo.UpdateEmail(auth.UserID, req.Email); err != nil {
		if isUniqueViolation(err) {
			writeErrorJSON(w, "Email already in use", http.StatusConflict)
			return
		}
		writeErrorJSON(w, fmt.Sprintf("Failed to update email: %v", err), http.StatusInternalServerError)
		return
	}

	s.auditLogger.LogSystemEvent("USER_PROFILE_UPDATED",
		fmt.Sprintf("User %s (id=%d) updated own email to %s", auth.Username, auth.UserID, req.Email))

	user, _ := s.userRepo.GetByID(auth.UserID)
	writeJSON(w, map[string]interface{}{"success": true, "user": user})
}

// handleChangeOwnPassword lets a logged-in user rotate their password.
// Old password is required so a stolen JWT can't lock the rightful
// owner out (and so that "change password" never becomes a one-step
// account takeover from anywhere the token leaks to).
func (s *APIServer) handleChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorJSON(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	auth, ok := s.currentUser(r)
	if !ok {
		writeErrorJSON(w, "Authentication required", http.StatusUnauthorized)
		return
	}
	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorJSON(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if len(req.NewPassword) < minPasswordLen {
		writeErrorJSON(w,
			fmt.Sprintf("New password must be at least %d characters", minPasswordLen),
			http.StatusBadRequest)
		return
	}
	user, err := s.userRepo.GetByID(auth.UserID)
	if err != nil {
		writeErrorJSON(w, "User not found", http.StatusNotFound)
		return
	}
	if !user.ValidatePassword(req.OldPassword) {
		writeErrorJSON(w, "Current password is incorrect", http.StatusUnauthorized)
		return
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), s.bcryptCost)
	if err != nil {
		writeErrorJSON(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}
	if err := s.userRepo.UpdatePasswordHash(auth.UserID, string(hashed)); err != nil {
		writeErrorJSON(w, fmt.Sprintf("Failed to update password: %v", err), http.StatusInternalServerError)
		return
	}

	s.auditLogger.LogSystemEvent("USER_PASSWORD_CHANGED",
		fmt.Sprintf("User %s (id=%d) changed own password", auth.Username, auth.UserID))

	writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Password updated. Existing sessions remain valid until JWT expiry.",
	})
}

// handleUsers dispatches /waf-api/auth/users by method:
//
//	GET  → list all users
//	POST → admin creates a new user with arbitrary role
//
// The route is wrapped in requireAdmin, so both branches assume admin.
func (s *APIServer) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListUsers(w, r)
	case http.MethodPost:
		s.handleAdminCreateUser(w, r)
	default:
		writeErrorJSON(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleListUsers handles listing all users (admin only)
func (s *APIServer) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.userRepo.List()
	if err != nil {
		writeErrorJSON(w, "Failed to list users", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]interface{}{
		"success": true,
		"users":   users,
		"count":   len(users),
	})
}

// handleAdminCreateUser creates a user with an explicit role. Admin-only.
// This is the legitimate replacement for the role escalation that
// /waf-api/auth/register used to permit.
func (s *APIServer) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var req AdminCreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorJSON(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)
	req.Role = strings.TrimSpace(strings.ToLower(req.Role))
	if req.Username == "" || req.Email == "" || req.Password == "" {
		writeErrorJSON(w, "Username, email, and password are required", http.StatusBadRequest)
		return
	}
	if err := validateUsername(req.Username); err != nil {
		writeErrorJSON(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateEmail(req.Email); err != nil {
		writeErrorJSON(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Password) < minPasswordLen {
		writeErrorJSON(w,
			fmt.Sprintf("Password must be at least %d characters", minPasswordLen),
			http.StatusBadRequest)
		return
	}
	if req.Role == "" {
		req.Role = "viewer"
	}
	if !models.IsValidRole(req.Role) {
		writeErrorJSON(w,
			fmt.Sprintf("Invalid role %q (allowed: %s)", req.Role, strings.Join(models.ValidRoles, ", ")),
			http.StatusBadRequest)
		return
	}
	user, err := s.userRepo.Create(req.Username, req.Email, req.Password, req.Role, s.bcryptCost)
	if err != nil {
		if isUniqueViolation(err) {
			writeErrorJSON(w, "Username or email already exists", http.StatusConflict)
			return
		}
		writeErrorJSON(w, fmt.Sprintf("Failed to create user: %v", err), http.StatusInternalServerError)
		return
	}

	actor, _ := s.currentUser(r)
	s.auditLogger.LogSystemEvent("USER_CREATED_BY_ADMIN",
		fmt.Sprintf("Admin %s created user %s (id=%d, role=%s)",
			actorName(actor), user.Username, user.ID, user.Role))

	writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "User created",
		"user":    user,
	})
}

// handleUserByID dispatches /waf-api/auth/users/{id} and
// /waf-api/auth/users/{id}/password. Path parsing is prefix-based to
// stay compatible with Go versions before 1.22's pattern syntax.
func (s *APIServer) handleUserByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/waf-api/auth/users/")
	if rest == "" {
		writeErrorJSON(w, "User ID required", http.StatusBadRequest)
		return
	}
	parts := strings.SplitN(rest, "/", 2)
	id, err := strconv.Atoi(parts[0])
	if err != nil || id <= 0 {
		writeErrorJSON(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Sub-resource: /users/{id}/password
	if len(parts) == 2 && parts[1] != "" {
		switch parts[1] {
		case "password":
			if r.Method != http.MethodPost {
				writeErrorJSON(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			s.handleAdminResetPassword(w, r, id)
			return
		default:
			writeErrorJSON(w, "Unknown sub-resource", http.StatusNotFound)
			return
		}
	}

	// Bare /users/{id}
	switch r.Method {
	case http.MethodPut:
		s.handleAdminUpdateUser(w, r, id)
	case http.MethodDelete:
		s.handleAdminDeleteUser(w, r, id)
	case http.MethodGet:
		// Useful for the admin UI's "edit" form prefill.
		u, err := s.userRepo.GetByID(id)
		if err != nil {
			writeErrorJSON(w, "User not found", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]interface{}{"success": true, "user": u})
	default:
		writeErrorJSON(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAdminUpdateUser changes role and/or email of any user. Admin only.
// Three guards stack:
//  1. Self-demotion is forbidden outright (CLAUDE.md invariant). Even
//     when other admins exist, you can't downgrade your own role through
//     this endpoint — that's a footgun and the UI also blocks it.
//  2. Demoting the last remaining admin is rejected (409) so the system
//     can't be locked into an admin-less state.
//  3. Validation runs before any DB write so a bad body never leaves
//     half-applied state. (#10 wraps role+email in a tx for the rest.)
func (s *APIServer) handleAdminUpdateUser(w http.ResponseWriter, r *http.Request, targetID int) {
	actor, _ := s.currentUser(r)

	target, err := s.userRepo.GetByID(targetID)
	if err != nil {
		writeErrorJSON(w, "User not found", http.StatusNotFound)
		return
	}

	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorJSON(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	req.Role = strings.TrimSpace(strings.ToLower(req.Role))

	if req.Email == "" && req.Role == "" {
		writeErrorJSON(w, "Nothing to update", http.StatusBadRequest)
		return
	}

	// Validation that doesn't need DB state — does first so we don't
	// take a transaction lock for a request that's going to 400.
	var newRoleForTx string
	if req.Role != "" && req.Role != target.Role {
		// Self-demotion guard — mirrors the delete-self block and the UI
		// disabled-button. Even when other admins exist we refuse, because
		// the legitimate path is "have another admin do it for you" and the
		// foot-shooting path (locking yourself out of your own dashboard)
		// has no benign use case.
		if actor != nil && actor.UserID == targetID {
			writeErrorJSON(w, "Cannot change your own role — ask another admin", http.StatusBadRequest)
			return
		}
		if !models.IsValidRole(req.Role) {
			writeErrorJSON(w,
				fmt.Sprintf("Invalid role %q (allowed: %s)", req.Role, strings.Join(models.ValidRoles, ", ")),
				http.StatusBadRequest)
			return
		}
		newRoleForTx = req.Role
	}
	var newEmailForTx string
	if req.Email != "" && req.Email != target.Email {
		if err := validateEmail(req.Email); err != nil {
			writeErrorJSON(w, err.Error(), http.StatusBadRequest)
			return
		}
		newEmailForTx = req.Email
	}

	// Atomic: role + email update + last-admin check, all under the same
	// SELECT ... FOR UPDATE lock. Without this, two admins demoting two
	// other admins concurrently could both pass the n>1 check and leave
	// zero admins, and a partial failure (role updated, email failed)
	// could leave the row inconsistent.
	if newRoleForTx != "" || newEmailForTx != "" {
		if err := s.userRepo.UpdateUserAtomic(targetID, newEmailForTx, newRoleForTx); err != nil {
			switch {
			case errors.Is(err, models.ErrLastAdmin):
				writeErrorJSON(w, "Cannot demote the last admin", http.StatusConflict)
			case errors.Is(err, models.ErrUserNotFound):
				writeErrorJSON(w, "User not found", http.StatusNotFound)
			case isUniqueViolation(err):
				writeErrorJSON(w, "Email already in use", http.StatusConflict)
			default:
				writeErrorJSON(w, fmt.Sprintf("Failed to update user: %v", err), http.StatusInternalServerError)
			}
			return
		}
		// Audit log AFTER successful commit so we never claim a change
		// that the DB rolled back.
		if newRoleForTx != "" {
			s.auditLogger.LogSystemEvent("USER_ROLE_CHANGED",
				fmt.Sprintf("Admin %s changed role of %s (id=%d) from %s to %s",
					actorName(actor), target.Username, targetID, target.Role, newRoleForTx))
		}
		if newEmailForTx != "" {
			s.auditLogger.LogSystemEvent("USER_EMAIL_CHANGED_BY_ADMIN",
				fmt.Sprintf("Admin %s changed email of %s (id=%d) from %s to %s",
					actorName(actor), target.Username, targetID, target.Email, newEmailForTx))
		}
	}

	updated, _ := s.userRepo.GetByID(targetID)
	writeJSON(w, map[string]interface{}{"success": true, "user": updated})
}

// handleAdminDeleteUser deletes a user. Self-delete is rejected outright;
// last-admin deletion is rejected by the atomic transaction so two
// admins deleting two other admins concurrently can't race past the
// check.
func (s *APIServer) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request, targetID int) {
	actor, ok := s.currentUser(r)
	if ok && actor.UserID == targetID {
		writeErrorJSON(w, "Cannot delete your own account", http.StatusBadRequest)
		return
	}

	// Fetch first for the audit log — we want the username/role in the
	// log message, and the atomic delete only returns an error code.
	target, err := s.userRepo.GetByID(targetID)
	if err != nil {
		writeErrorJSON(w, "User not found", http.StatusNotFound)
		return
	}

	if err := s.userRepo.DeleteUserAtomic(targetID); err != nil {
		switch {
		case errors.Is(err, models.ErrLastAdmin):
			writeErrorJSON(w, "Cannot delete the last admin", http.StatusConflict)
		case errors.Is(err, models.ErrUserNotFound):
			writeErrorJSON(w, "User not found", http.StatusNotFound)
		default:
			writeErrorJSON(w, fmt.Sprintf("Failed to delete user: %v", err), http.StatusInternalServerError)
		}
		return
	}

	s.auditLogger.LogSystemEvent("USER_DELETED",
		fmt.Sprintf("Admin %s deleted user %s (id=%d, role=%s)",
			actorName(actor), target.Username, targetID, target.Role))

	writeJSON(w, map[string]interface{}{"success": true, "message": "User deleted"})
}

// handleAdminResetPassword sets a new password for any user without
// requiring the old one. Use case: admin recovers a locked-out user.
func (s *APIServer) handleAdminResetPassword(w http.ResponseWriter, r *http.Request, targetID int) {
	var req AdminResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorJSON(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if len(req.NewPassword) < minPasswordLen {
		writeErrorJSON(w,
			fmt.Sprintf("Password must be at least %d characters", minPasswordLen),
			http.StatusBadRequest)
		return
	}

	target, err := s.userRepo.GetByID(targetID)
	if err != nil {
		writeErrorJSON(w, "User not found", http.StatusNotFound)
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), s.bcryptCost)
	if err != nil {
		writeErrorJSON(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}
	if err := s.userRepo.UpdatePasswordHash(targetID, string(hashed)); err != nil {
		writeErrorJSON(w, fmt.Sprintf("Failed to update password: %v", err), http.StatusInternalServerError)
		return
	}

	actor, _ := s.currentUser(r)
	s.auditLogger.LogSystemEvent("USER_PASSWORD_RESET_BY_ADMIN",
		fmt.Sprintf("Admin %s reset password of %s (id=%d)",
			actorName(actor), target.Username, targetID))

	writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Password reset. Tell the user to log in with the new password.",
	})
}

// currentUser pulls the authenticated identity off the request, first
// from the context (set by requireAuthN/requireAdmin), then by re-running
// authenticate() for the case where auth is globally off but a token
// was still presented.
func (s *APIServer) currentUser(r *http.Request) (*authContext, bool) {
	if u, ok := userFromContext(r); ok {
		return u, true
	}
	if u, _ := s.authenticate(r); u != nil {
		return u, true
	}
	return nil, false
}

// actorName returns a label for audit logs, including the case where
// auth is globally disabled (no authenticated identity).
func actorName(a *authContext) string {
	if a == nil {
		return "<auth-disabled>"
	}
	return fmt.Sprintf("%s(id=%d)", a.Username, a.UserID)
}

// isUniqueViolation reports whether err is a PostgreSQL unique-constraint
// violation (SQLSTATE 23505). Uses errors.As to unwrap wrapped errors
// (`fmt.Errorf("…: %w", err)` from the repository layer) and asserts
// the lib/pq error type so we match on the structured code instead of a
// substring of the human-readable message — the previous "contains
// 'unique' or 'duplicate'" check fired on any error whose text happened
// to mention either word, e.g. a connection error during a uniqueness
// check would have been mis-mapped to 409 Conflict.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505"
	}
	return false
}

// writeErrorJSON writes an error response as JSON
func writeErrorJSON(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}
