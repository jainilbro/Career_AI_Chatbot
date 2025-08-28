# create_db.py (Simplified without reset_tokens table, added sessions table for persistent login)

import sqlite3

conn = sqlite3.connect("users.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY COLLATE NOCASE,  -- Case-insensitive usernames
    password TEXT NOT NULL,                    -- Hashed password
    email TEXT NOT NULL UNIQUE
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS chat_history (
    username TEXT PRIMARY KEY,
    history_data BLOB NOT NULL,
    FOREIGN KEY (username) REFERENCES users (username)
)
""")

# New table for session tokens (for persistent login)
cursor.execute("""
CREATE TABLE IF NOT EXISTS sessions (
    username TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users (username)
)
""")

conn.commit()
conn.close()
print("Database and tables created with sessions support.")
