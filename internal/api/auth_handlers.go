// internal/api/auth_handlers.go
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"waf-project/internal/models"
)

// RegisterRequest represents registration request body
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role,omitempty"` // Only admins can set role
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

	// Validate input
	if req.Username == "" || req.Email == "" || req.Password == "" {
		writeErrorJSON(w, "Username, email, and password are required", http.StatusBadRequest)
		return
	}

	// Validate password strength
	if len(req.Password) < 8 {
		writeErrorJSON(w, "Password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	// Default role is viewer
	role := "viewer"
	if req.Role != "" {
		// TODO: Check if current user is admin before allowing role assignment
		role = req.Role
	}

	// Create user in database
	user, err := s.userRepo.Create(req.Username, req.Email, req.Password, role, s.bcryptCost)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
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

	// Get user from database
	user, err := s.userRepo.GetByUsername(req.Username)
	if err != nil {
		writeErrorJSON(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Validate password
	if !user.ValidatePassword(req.Password) {
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

	writeJSON(w, LoginResponse{
		Token:     token,
		User:      user,
		ExpiresAt: expiresAt,
	})
}

// handleLogout handles user logout
func (s *APIServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorJSON(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// For JWT, logout is handled client-side by removing token
	// Server doesn't need to do anything

	writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Logged out successfully",
	})
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

// handleListUsers handles listing all users (admin only)
func (s *APIServer) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorJSON(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

// writeErrorJSON writes an error response as JSON
func writeErrorJSON(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}
