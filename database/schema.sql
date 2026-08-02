-- =============================================================================
-- CyberShield AI – Production Grade MySQL Database Schema
-- Storage Engine: InnoDB (Enforces ACID - Atomicity, Consistency, Isolation, Durability)
-- Character Set: utf8mb4 / Collation: utf8mb4_unicode_ci
-- =============================================================================

CREATE DATABASE IF NOT EXISTS cybershield_ai
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE cybershield_ai;

-- Disable Foreign Key checks during schema initialization
SET FOREIGN_KEY_CHECKS = 0;

-- -----------------------------------------------------------------------------
-- 1. Users Table
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    uuid CHAR(36) NOT NULL UNIQUE,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NULL,
    last_name VARCHAR(100) NULL,
    phone_number VARCHAR(20) NULL,
    profile_image VARCHAR(255) NULL,
    email_verified TINYINT(1) NOT NULL DEFAULT 0,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    account_locked_until DATETIME NULL,
    last_login_at DATETIME NULL,
    last_password_change DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_users_username (username),
    INDEX idx_users_email (email),
    INDEX idx_users_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 2. Roles Table
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS roles;
CREATE TABLE roles (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    uuid CHAR(36) NOT NULL UNIQUE,
    name VARCHAR(50) NOT NULL UNIQUE,
    display_name VARCHAR(100) NOT NULL,
    description VARCHAR(255) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_roles_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 3. User Roles Association Table
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS user_roles;
CREATE TABLE user_roles (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    uuid CHAR(36) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_user_role (user_id, role_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    INDEX idx_user_roles_user (user_id),
    INDEX idx_user_roles_role (role_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 4. User Sessions Table
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS user_sessions;
CREATE TABLE user_sessions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    uuid CHAR(36) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL,
    session_token VARCHAR(255) NOT NULL UNIQUE,
    ip_address VARCHAR(45) NULL,
    user_agent VARCHAR(512) NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_user_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_sessions_token (session_token),
    INDEX idx_sessions_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 5. Refresh Tokens Table
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS refresh_tokens;
CREATE TABLE refresh_tokens (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    uuid CHAR(36) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    is_revoked TINYINT(1) NOT NULL DEFAULT 0,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_refresh_tokens_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 6. Login History Table
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS login_history;
CREATE TABLE login_history (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    uuid CHAR(36) NOT NULL UNIQUE,
    user_id BIGINT NULL,
    username_attempted VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL, -- e.g., 'SUCCESS', 'FAILED', 'LOCKED'
    ip_address VARCHAR(45) NULL,
    user_agent VARCHAR(512) NULL,
    failure_reason VARCHAR(255) NULL,
    login_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_login_history_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_login_history_user (user_id),
    INDEX idx_login_history_status (status),
    INDEX idx_login_history_login_at (login_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 7. Website Scans Table
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS website_scans;
CREATE TABLE website_scans (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    uuid CHAR(36) NOT NULL UNIQUE,
    user_id BIGINT NULL,
    url TEXT NOT NULL,
    domain VARCHAR(255) NOT NULL,
    risk_level VARCHAR(20) NOT NULL DEFAULT 'Suspicious', -- Safe, Suspicious, Malicious
    phishing_score INT NOT NULL DEFAULT 0,
    ssl_valid TINYINT(1) NOT NULL DEFAULT 0,
    malware_found TINYINT(1) NOT NULL DEFAULT 0,
    domain_age VARCHAR(100) NULL,
    reputation VARCHAR(100) NULL,
    explanation_markdown MEDIUMTEXT NULL,
    result_json JSON NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_website_scans_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_website_scans_user (user_id),
    INDEX idx_website_scans_domain (domain),
    INDEX idx_website_scans_risk (risk_level),
    INDEX idx_website_scans_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 8. Email Scans Table
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS email_scans;
CREATE TABLE email_scans (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    uuid CHAR(36) NOT NULL UNIQUE,
    user_id BIGINT NULL,
    sender VARCHAR(255) NOT NULL,
    body_snippet TEXT NOT NULL,
    risk_level VARCHAR(20) NOT NULL DEFAULT 'Suspicious',
    phishing_score INT NOT NULL DEFAULT 0,
    urgency VARCHAR(50) NULL,
    suspicious_links INT NOT NULL DEFAULT 0,
    spoofed_domain TINYINT(1) NOT NULL DEFAULT 0,
    spf_check VARCHAR(50) NULL,
    explanation_markdown MEDIUMTEXT NULL,
    result_json JSON NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_email_scans_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_email_scans_user (user_id),
    INDEX idx_email_scans_sender (sender),
    INDEX idx_email_scans_risk (risk_level),
    INDEX idx_email_scans_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 9. Image Scans Table
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS image_scans;
CREATE TABLE image_scans (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    uuid CHAR(36) NOT NULL UNIQUE,
    user_id BIGINT NULL,
    filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(512) NULL,
    risk_level VARCHAR(20) NOT NULL DEFAULT 'Suspicious',
    ai_confidence FLOAT NOT NULL DEFAULT 50.0,
    fingerprints VARCHAR(255) NULL,
    jpeg_artifacts VARCHAR(255) NULL,
    explanation_markdown MEDIUMTEXT NULL,
    result_json JSON NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_image_scans_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_image_scans_user (user_id),
    INDEX idx_image_scans_risk (risk_level),
    INDEX idx_image_scans_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 10. Password Scans Table
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS password_scans;
CREATE TABLE password_scans (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    uuid CHAR(36) NOT NULL UNIQUE,
    user_id BIGINT NULL,
    masked_password VARCHAR(255) NOT NULL,
    risk_level VARCHAR(20) NOT NULL DEFAULT 'Medium',
    entropy FLOAT NOT NULL DEFAULT 0.0,
    pwned_count INT NOT NULL DEFAULT 0,
    has_uppercase TINYINT(1) NOT NULL DEFAULT 0,
    has_lowercase TINYINT(1) NOT NULL DEFAULT 0,
    has_digit TINYINT(1) NOT NULL DEFAULT 0,
    has_special TINYINT(1) NOT NULL DEFAULT 0,
    explanation_markdown MEDIUMTEXT NULL,
    recommendations_json JSON NULL,
    result_json JSON NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_password_scans_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_password_scans_user (user_id),
    INDEX idx_password_scans_risk (risk_level),
    INDEX idx_password_scans_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 11. Security Advisor Audits Table
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS security_audits;
CREATE TABLE security_audits (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    uuid CHAR(36) NOT NULL UNIQUE,
    user_id BIGINT NULL,
    title VARCHAR(255) NOT NULL DEFAULT 'Personal Security Exposure Audit',
    overall_score INT NOT NULL DEFAULT 100,
    risk_level VARCHAR(20) NOT NULL DEFAULT 'Safe',
    questionnaire_json JSON NULL,
    advisor_markdown MEDIUMTEXT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_security_audits_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_security_audits_user (user_id),
    INDEX idx_security_audits_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 12. Chat Messages Table
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS chat_messages;
CREATE TABLE chat_messages (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    uuid CHAR(36) NOT NULL UNIQUE,
    user_id BIGINT NULL,
    session_id VARCHAR(64) NOT NULL,
    sender VARCHAR(20) NOT NULL, -- 'user' or 'model'
    message TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_chat_messages_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_chat_messages_user (user_id),
    INDEX idx_chat_messages_session (session_id),
    INDEX idx_chat_messages_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 13. AI Reports Table
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS ai_reports;
CREATE TABLE ai_reports (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    uuid CHAR(36) NOT NULL UNIQUE,
    user_id BIGINT NULL,
    scan_type VARCHAR(50) NOT NULL,
    scan_id BIGINT NULL,
    title VARCHAR(255) NOT NULL,
    summary TEXT NULL,
    report_content MEDIUMTEXT NOT NULL,
    risk_level VARCHAR(20) NOT NULL DEFAULT 'Suspicious',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_ai_reports_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_ai_reports_user (user_id),
    INDEX idx_ai_reports_scan_type (scan_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 14. Audit Logs Table
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS audit_logs;
CREATE TABLE audit_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    uuid CHAR(36) NOT NULL UNIQUE,
    user_id BIGINT NULL,
    action VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NULL,
    details TEXT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_audit_logs_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_audit_logs_user (user_id),
    INDEX idx_audit_logs_action (action),
    INDEX idx_audit_logs_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 15. Notifications Table
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS notifications;
CREATE TABLE notifications (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    uuid CHAR(36) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    is_read TINYINT(1) NOT NULL DEFAULT 0,
    notification_type VARCHAR(50) NOT NULL DEFAULT 'info',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_notifications_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_notifications_user (user_id),
    INDEX idx_notifications_read (is_read)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 16. System Settings Table
-- -----------------------------------------------------------------------------
DROP TABLE IF EXISTS system_settings;
CREATE TABLE system_settings (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(100) NOT NULL UNIQUE,
    setting_value TEXT NULL,
    description VARCHAR(255) NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_settings_key (setting_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Re-enable Foreign Key checks
SET FOREIGN_KEY_CHECKS = 1;

-- =============================================================================
-- Seed Initial Roles
-- =============================================================================
INSERT INTO roles (uuid, name, display_name, description) VALUES
(UUID(), 'admin', 'Administrator', 'Full system access and security audit management'),
(UUID(), 'analyst', 'Security Analyst', 'View telemetry logs, scan reports, and advice matrix'),
(UUID(), 'user', 'Standard User', 'Run scans, view audit history, and talk to AI Assistant')
ON DUPLICATE KEY UPDATE display_name=VALUES(display_name);
