CREATE DATABASE IF NOT EXISTS cybexplore_bac CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE cybexplore_bac;

-- Users table (regular participants + your monitor user)
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,          -- plaintext – intentional vuln for demo
    email VARCHAR(100) UNIQUE DEFAULT NULL,
    phone VARCHAR(20) DEFAULT NULL,
    hostel VARCHAR(100) DEFAULT NULL,
    bio TEXT DEFAULT NULL,
    role ENUM('user', 'admin') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    reset_token VARCHAR(255) DEFAULT NULL,
    reset_token_expiry DATETIME DEFAULT NULL
);

-- Sample monitor user (your private account)
INSERT IGNORE INTO users (id, username, password, role, email)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'cybadmin',
    'your_monitor_password_here',  -- change this!
    'admin',
    'monitor@cybexplore.org'
);

-- Optional: create a few test users
INSERT IGNORE INTO users (id, username, password, role, email)
VALUES 
    (UUID(), 'student1', 'pass123', 'user', 'student1@example.com'),
    (UUID(), 'student2', 'pass123', 'user', 'student2@example.com');


-- Listings table (this is the missing one causing the error)
CREATE TABLE IF NOT EXISTS listings (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL,
    category ENUM('textbooks', 'electronics', 'fashion', 'hostel', 'gadgets', 'beauty', 'sports', 'other') DEFAULT 'other',
    status ENUM('available', 'reserved', 'sold', 'deleted') DEFAULT 'available',
    photo VARCHAR(255) DEFAULT NULL,
    preview_url VARCHAR(500) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Favorites table (optional – only if you're using favorites feature)
CREATE TABLE IF NOT EXISTS favorites (
    user_id VARCHAR(36) NOT NULL,
    listing_id VARCHAR(36) NOT NULL,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, listing_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (listing_id) REFERENCES listings(id) ON DELETE CASCADE
);

USE cybexplore_bac;

CREATE TABLE IF NOT EXISTS monitor_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id VARCHAR(36) NULL,               -- who did it (or NULL for anonymous)
    username VARCHAR(50) NULL,
    action_type VARCHAR(100) NOT NULL,      -- e.g. 'login', 'profile_view', 'admin_access', 'email_change'
    target_id VARCHAR(36) NULL,             -- e.g. profile ID, listing ID
    details TEXT NULL,                      -- extra info (e.g. "Viewed profile 8f2b...", "Changed role to admin")
    ip_address VARCHAR(45) NULL             -- optional for tracking
);

-- Index for fast recent queries
CREATE INDEX idx_timestamp ON monitor_logs(timestamp DESC);

CREATE TABLE messages (
    id INT AUTO_INCREMENT PRIMARY KEY,               -- Unique message ID
    sender_role VARCHAR(20) NOT NULL DEFAULT 'monitor',  -- Who sent the message (monitor/system)
    receiver_user_id VARCHAR(255) NOT NULL,         -- Target user ID (adjust type to match users.id)
    message TEXT NOT NULL,                           -- Message content
    related_log_id INT DEFAULT NULL,                -- Optional link to monitor_logs.id
    is_read BOOLEAN NOT NULL DEFAULT FALSE,         -- Has the user read the message
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, -- Timestamp of creation
    FOREIGN KEY (related_log_id) REFERENCES monitor_logs(id) ON DELETE SET NULL
);
