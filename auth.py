import streamlit as st
import libsql_client
import re
import json
import bcrypt
import time
import uuid
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from json.decoder import JSONDecodeError

# -----------------------------------------------------------------------------
# Connection Management (using a context manager)
# -----------------------------------------------------------------------------
@contextmanager
def db_connection():
    """A context manager for safe, resilient database connections with retries."""
    conn = None
    retries = 3
    last_exception = None
    
    for attempt in range(retries):
        try:
            url = st.secrets["TURSO_DATABASE_URL"]
            auth_token = st.secrets["TURSO_AUTH_TOKEN"]
            conn = libsql_client.create_client_sync(url=url, auth_token=auth_token)
            # If connection is successful, break the loop
            last_exception = None
            break
        except Exception as e:
            last_exception = e
            if attempt < retries - 1:
                time.sleep(0.5) 
    
    if conn:
        try:
            yield conn
        finally:
            conn.close()
    else:
        # If all retries failed, show the error and stop
        st.error(f"Database connection failed after {retries} attempts.")
        if last_exception:
            st.exception(last_exception)
        st.stop()

def _rows(rs):
    return getattr(rs, "rows", rs)  # supports objects with .rows and plain lists
# -----------------------------------------------------------------------------
# Schema and User Management Functions (refactored to use the context manager)
# -----------------------------------------------------------------------------

def ensure_db_ready():
    """Ensures the database schema exists with cascading deletes for data integrity."""
    with db_connection() as conn:
        conn.batch([
            ("""CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY COLLATE NOCASE,
                password TEXT NOT NULL,
                email    TEXT NOT NULL UNIQUE COLLATE NOCASE
            )""", []),
            ("""CREATE TABLE IF NOT EXISTS chat_history (
                username    TEXT PRIMARY KEY,
                history_data TEXT NOT NULL,
                FOREIGN KEY (username) REFERENCES users (username) ON DELETE CASCADE
            )""", []),
            ("""CREATE TABLE IF NOT EXISTS sessions (
                username   TEXT NOT NULL,
                token      TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                FOREIGN KEY (username) REFERENCES users (username) ON DELETE CASCADE
            )""", []),
        ])

def fetch_user_by_username_or_email(identifier):
    """Fetches a user by their lowercase username or email using an explicit LOWER() query."""
    with db_connection() as conn:
        normalized_identifier = identifier.lower()
        rs = conn.execute(
            "SELECT username, password, email FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?",
            [normalized_identifier, normalized_identifier]
        )
        rows = _rows(rs)
        return rows[0] if len(rows) > 0 else None

def username_exists(username):
    """Checks if a username already exists in the database using a case-insensitive query."""
    with db_connection() as conn:
        rs = conn.execute(
            "SELECT 1 FROM users WHERE LOWER(username) = ?", 
            [username.lower()]
        )
        return len(_rows(rs)) > 0   

def add_user(username, hashed_password, email):
    """Adds a new user with a lowercase username and email."""
    if username_exists(username):
        return False
    with db_connection() as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                [username.lower(), hashed_password, email.lower()]
            )
            return True
        except Exception as e:
            st.error(f"Database error: {e}")
            return False

def save_chat_history(username, history):
    """Saves chat history as a JSON string."""
    with db_connection() as conn:
        serialized_history = json.dumps(history)
        conn.execute(
            "INSERT OR REPLACE INTO chat_history (username, history_data) VALUES (?, ?)",
            [username, serialized_history]
        )

def load_chat_history(username):
    with db_connection() as conn:
        rs = conn.execute(
            "SELECT history_data FROM chat_history WHERE username = ?", [username]
        )
        rows = _rows(rs)
        if rows and len(rows) > 0:
            raw = rows[0][0]  # could be bytes, str, or even None
            # Decode bytes if needed
            if isinstance(raw, (bytes, bytearray)):
                raw = raw.decode('utf-8', errors='replace')
            # Ensure it's a non-empty string
            if not raw or not raw.strip():
                return {}
            # Safely parse JSON
            try:
                return json.loads(raw)
            except JSONDecodeError:
                # Log or handle malformed JSON here if desired
                return {}
    return {}

# -----------------------------------------------------------------------------
# Password and Session Token Functions
# -----------------------------------------------------------------------------

def is_password_strong(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain an uppercase letter."
    # ... (rest of password checks are the same)
    if not re.search(r"[a-z]", password):
        return False, "Password must contain a lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain a number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain a special character."
    return True, "Password is strong."

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def generate_session_token(username):
    """Generates a token and a UTC ISO8601 timestamp in Python."""
    token = str(uuid.uuid4())
    now_utc_iso = datetime.now(timezone.utc).isoformat()
    thirty_days_ago_iso = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

    with db_connection() as conn:
        conn.execute("DELETE FROM sessions WHERE created_at < ?", [thirty_days_ago_iso])
        
        conn.execute("DELETE FROM sessions WHERE username = ?", [username])
        
        conn.execute(
            "INSERT INTO sessions (username, token, created_at) VALUES (?, ?, ?)", 
            [username, token, now_utc_iso]
        )

    return token


def validate_session_token(token):
    """Validates a session token using ISO8601 format."""
    with db_connection() as conn:
        rs = conn.execute("SELECT username, created_at FROM sessions WHERE token = ?", [token])
        if len(rs.rows) > 0:
            username, created_at_str = rs.rows[0]
            # Use the more robust fromisoformat() to parse the timestamp
            created_dt = datetime.fromisoformat(str(created_at_str))
            now_aware = datetime.now(timezone.utc)
            if now_aware - created_dt < timedelta(days=30):
                return username
        return None

def clear_session_token(username):
    with db_connection() as conn:
        conn.execute("DELETE FROM sessions WHERE username = ?", [username])