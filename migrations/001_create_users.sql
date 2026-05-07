-- Migration: Create users table and authentication schema
-- Version: 001
-- Description: Initial user authentication setup

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'viewer' CHECK (role IN ('admin', 'editor', 'viewer')),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- Insert default admin account
-- Password: admin123 (bcrypt hash with cost 10 — verified against
-- the same JWTManager / bcrypt.CompareHashAndPassword the app uses).
-- Change immediately after first login.
INSERT INTO users (username, email, password_hash, role)
VALUES (
    'admin',
    'admin@waf.local',
    '$2a$10$bd6fEgYpUIsIFosVoEZbT.TTDKPY9D/ALHCtsOfNNMhg8sQPPOCOC',
    'admin'
) ON CONFLICT (username) DO NOTHING;

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger for users table
CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Grant permissions (adjust as needed)
-- GRANT ALL PRIVILEGES ON TABLE users TO waf_user;
-- GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO waf_user;
