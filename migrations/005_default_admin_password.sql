-- Migration: Set the default admin account credentials to admin/admin
-- Version: 005
-- Description: Public self-registration was removed; the only bootstrap
-- account is the seeded admin. Per request, the default first admin is
-- admin/admin. This writes a fresh bcrypt hash (cost=10) of "admin" and
-- ensures the admin row exists with role=admin.
--
-- SECURITY: "admin" is a deliberately weak bootstrap password. It MUST be
-- changed immediately on first login via the Settings page or
-- PUT /waf-api/auth/me/password in any non-dev environment.
--
-- Idempotent: ON CONFLICT updates the existing row in place.

INSERT INTO users (username, email, password_hash, role)
VALUES (
    'admin',
    'admin@waf.local',
    '$2a$10$.DG5M3AfZRHEzEp2Ig48zeq1XyMzs7t98oJ/oLwXqBAh.GxHApngW',
    'admin'
)
ON CONFLICT (username) DO UPDATE
SET password_hash = EXCLUDED.password_hash,
    role         = 'admin',
    updated_at   = NOW();
