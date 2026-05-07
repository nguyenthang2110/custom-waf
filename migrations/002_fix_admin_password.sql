-- Migration: Repair the default admin account password
-- Version: 002
-- Description: 001 shipped a placeholder bcrypt hash that didn't actually
-- verify against "admin123", so the default account was unusable.
-- This migration writes the correct bcrypt hash (cost=10) and ensures
-- the admin row exists with role=admin.

INSERT INTO users (username, email, password_hash, role)
VALUES (
    'admin',
    'admin@waf.local',
    '$2a$10$bd6fEgYpUIsIFosVoEZbT.TTDKPY9D/ALHCtsOfNNMhg8sQPPOCOC',
    'admin'
)
ON CONFLICT (username) DO UPDATE
SET password_hash = EXCLUDED.password_hash,
    role         = 'admin',
    updated_at   = NOW();
