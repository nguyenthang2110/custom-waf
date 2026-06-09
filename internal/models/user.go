package models

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ErrLastAdmin is returned by the atomic update/delete methods when the
// requested change would leave the system with zero admins. Handlers
// surface this as 409 Conflict so the operator sees a clear reason.
var ErrLastAdmin = errors.New("operation would leave zero admins")

// ErrUserNotFound is returned when the target user disappears between
// the request landing and the transaction acquiring the row lock.
var ErrUserNotFound = errors.New("user not found")

// User represents a user in the system
type User struct {
	ID           int        `json:"id"`
	Username     string     `json:"username"`
	Email        string     `json:"email"`
	PasswordHash string     `json:"-"` // Never serialize password
	Role         string     `json:"role"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastLogin    *time.Time `json:"last_login,omitempty"`
}

// UserRepository handles database operations for users
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

// Create creates a new user with hashed password
func (r *UserRepository) Create(username, email, password, role string, bcryptCost int) (*User, error) {
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Insert user
	query := `
		INSERT INTO users (username, email, password_hash, role)
		VALUES ($1, $2, $3, $4)
		RETURNING id, username, email, password_hash, role, created_at, updated_at, last_login
	`

	user := &User{}
	err = r.db.QueryRow(query, username, email, string(hashedPassword), role).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLogin,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

// GetByUsername finds a user by username
func (r *UserRepository) GetByUsername(username string) (*User, error) {
	query := `
		SELECT id, username, email, password_hash, role, created_at, updated_at, last_login
		FROM users
		WHERE username = $1
	`

	user := &User{}
	err := r.db.QueryRow(query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLogin,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

// GetByEmail finds a user by email
func (r *UserRepository) GetByEmail(email string) (*User, error) {
	query := `
		SELECT id, username, email, password_hash, role, created_at, updated_at, last_login
		FROM users
		WHERE email = $1
	`

	user := &User{}
	err := r.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLogin,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

// GetByID finds a user by ID
func (r *UserRepository) GetByID(id int) (*User, error) {
	query := `
		SELECT id, username, email, password_hash, role, created_at, updated_at, last_login
		FROM users
		WHERE id = $1
	`

	user := &User{}
	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLogin,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

// ValidatePassword checks if password matches hash
func (u *User) ValidatePassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	return err == nil
}

// UpdateLastLogin updates the user's last login timestamp
func (r *UserRepository) UpdateLastLogin(userID int) error {
	query := `UPDATE users SET last_login = NOW() WHERE id = $1`
	_, err := r.db.Exec(query, userID)
	return err
}

// List returns all users (for admin)
func (r *UserRepository) List() ([]*User, error) {
	query := `
		SELECT id, username, email, password_hash, role, created_at, updated_at, last_login
		FROM users
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		user := &User{}
		err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.Email,
			&user.PasswordHash,
			&user.Role,
			&user.CreatedAt,
			&user.UpdatedAt,
			&user.LastLogin,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, user)
	}

	return users, nil
}

// Delete deletes a user
func (r *UserRepository) Delete(userID int) error {
	query := `DELETE FROM users WHERE id = $1`
	result, err := r.db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// ValidRoles is the canonical, app-side allow-list of role values. The DB
// also enforces this via a CHECK constraint (migration 001), so any drift
// here only affects error messages — the DB will still reject bad rows.
var ValidRoles = []string{"admin", "editor", "viewer"}

// IsValidRole reports whether s is one of the application's known roles.
// Used to fail fast in handlers before hitting the DB.
func IsValidRole(s string) bool {
	for _, r := range ValidRoles {
		if r == s {
			return true
		}
	}
	return false
}

// UpdatePasswordHash overwrites the user's password hash. The caller is
// responsible for bcrypt-hashing the new plaintext at the configured cost
// (so we don't have to thread bcryptCost through every call site).
func (r *UserRepository) UpdatePasswordHash(userID int, hash string) error {
	query := `UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2`
	result, err := r.db.Exec(query, hash, userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// UpdateRole changes the user's role. Caller MUST validate role via
// IsValidRole AND enforce "don't demote the last admin" before calling —
// the DB CHECK constraint will reject unknown roles but won't protect
// against locking yourself out of the admin role.
func (r *UserRepository) UpdateRole(userID int, role string) error {
	query := `UPDATE users SET role = $1, updated_at = NOW() WHERE id = $2`
	result, err := r.db.Exec(query, role, userID)
	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// UpdateEmail changes the user's email. The UNIQUE constraint on the
// column means duplicates surface as a *pq.Error with SQLSTATE 23505;
// the api package's isUniqueViolation maps that to 409 Conflict.
func (r *UserRepository) UpdateEmail(userID int, email string) error {
	query := `UPDATE users SET email = $1, updated_at = NOW() WHERE id = $2`
	result, err := r.db.Exec(query, email, userID)
	if err != nil {
		return fmt.Errorf("failed to update email: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

// CountByRole returns how many users currently hold a given role.
//
// DEPRECATED: do not use for the last-admin guard. The previous pattern
// (CountByRole + UpdateRole/Delete) is racy — two concurrent demotions
// could both read n=2 and then both commit, leaving zero admins. Use
// UpdateUserAtomic / DeleteUserAtomic instead, which take a row lock
// across all admin rows for the duration of the check + write.
// CountByRole is retained for read-only stats consumers.
func (r *UserRepository) CountByRole(role string) (int, error) {
	var n int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = $1`, role).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("failed to count users by role: %w", err)
	}
	return n, nil
}

// UpdateUserAtomic applies any combination of role/email/passwordHash
// changes to a single user inside one transaction, with a
// SELECT ... FOR UPDATE lock on every admin row plus the target row.
// The lock serialises concurrent admin demotions so the "no zero admins"
// invariant holds even under load.
//
// Empty fields are skipped. newRole must already be validated by the
// caller (IsValidRole). To leave a field untouched, pass "".
//
// Returns ErrLastAdmin if the change would demote the only admin, and
// ErrUserNotFound if the target row vanishes between request and lock.
// A unique-violation on email surfaces as a *pq.Error (SQLSTATE 23505).
func (r *UserRepository) UpdateUserAtomic(userID int, newEmail, newRole string) error {
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	// Rollback is a no-op after a successful Commit, so this is safe.
	defer tx.Rollback()

	currentRole, adminCount, err := lockAdminsAndTarget(tx, userID)
	if err != nil {
		return err
	}

	if newRole != "" && newRole != currentRole {
		if currentRole == "admin" && newRole != "admin" && adminCount <= 1 {
			return ErrLastAdmin
		}
		if _, err := tx.Exec(
			`UPDATE users SET role = $1, updated_at = NOW() WHERE id = $2`,
			newRole, userID,
		); err != nil {
			return fmt.Errorf("update role: %w", err)
		}
	}
	if newEmail != "" {
		if _, err := tx.Exec(
			`UPDATE users SET email = $1, updated_at = NOW() WHERE id = $2`,
			newEmail, userID,
		); err != nil {
			// Pass *pq.Error through so isUniqueViolation can match.
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// DeleteUserAtomic deletes the target inside a transaction, refusing to
// proceed if the target is the only remaining admin. Uses the same
// FOR UPDATE lock pattern as UpdateUserAtomic so the count + delete are
// race-free.
func (r *UserRepository) DeleteUserAtomic(userID int) error {
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	currentRole, adminCount, err := lockAdminsAndTarget(tx, userID)
	if err != nil {
		return err
	}
	if currentRole == "admin" && adminCount <= 1 {
		return ErrLastAdmin
	}
	res, err := tx.Exec(`DELETE FROM users WHERE id = $1`, userID)
	if err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return ErrUserNotFound
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// lockAdminsAndTarget runs SELECT ... FOR UPDATE over every admin plus
// the target row inside the given tx. Returns the target's current role
// and the total admin count. The FOR UPDATE prevents any concurrent tx
// from demoting/deleting an admin (or promoting one to admin) until
// this tx commits or rolls back.
func lockAdminsAndTarget(tx *sql.Tx, targetID int) (string, int, error) {
	rows, err := tx.Query(
		`SELECT id, role FROM users WHERE role = 'admin' OR id = $1 FOR UPDATE`,
		targetID,
	)
	if err != nil {
		return "", 0, fmt.Errorf("lock admins: %w", err)
	}
	defer rows.Close()

	var currentRole string
	var adminCount int
	targetFound := false
	for rows.Next() {
		var id int
		var role string
		if err := rows.Scan(&id, &role); err != nil {
			return "", 0, fmt.Errorf("scan: %w", err)
		}
		if id == targetID {
			targetFound = true
			currentRole = role
		}
		if role == "admin" {
			adminCount++
		}
	}
	if err := rows.Err(); err != nil {
		return "", 0, fmt.Errorf("iterate: %w", err)
	}
	if !targetFound {
		return "", 0, ErrUserNotFound
	}
	return currentRole, adminCount, nil
}
