# auth.py (clean, Turso/libsql sync client using libsql://)

import streamlit as st
import libsql_client
import re
import pickle
import bcrypt
import uuid
from datetime import datetime, timedelta

# ---------- Connection helpers ----------

def _normalize_libsql_url(url: str) -> str:
    """
    Keep libsql:// as-is; coerce http(s) -> libsql:// and ws:// -> wss://.
    """
    u = str(url).strip()
    if u.startswith("libsql://") or u.startswith("wss://"):
        return u
    if u.startswith("ws://"):
        return "wss://" + u[len("ws://"):]
    if u.startswith("https://"):
        return "libsql://" + u[len("https://"):]
    if u.startswith("http://"):
        return "libsql://" + u[len("http://"):]
    # bare host fallback
    return "libsql://" + u

def get_db_connection():
    """Establishes a connection to the Turso database using Streamlit secrets."""
    try:
        url = st.secrets["TURSO_DATABASE_URL"]
        auth_token = st.secrets["TURSO_AUTH_TOKEN"]
        
        # Check if the URL starts with the expected prefix
        if not url.startswith("libsql://"):
            raise ValueError(f"Invalid Turso URL format. Expected 'libsql://', but got '{url}'")
            
        return libsql_client.create_client_sync(url=url, auth_token=auth_token)

    except (KeyError, ValueError) as e:
        st.error(f"Database configuration error: {e}")
        # Stop the app if the database can't be configured
        st.stop()
    except Exception as e:
        st.error(f"Failed to connect to the database: {e}")
        st.stop()

def ensure_db_ready():
    """
    Called once at startup. Pings DB and ensures schema exists.
    """
    conn = get_db_connection()
    try:
        conn.execute("SELECT 1")  # ping
        conn.batch(
            [
                """CREATE TABLE IF NOT EXISTS users (
                       username TEXT PRIMARY KEY COLLATE NOCASE,
                       password TEXT NOT NULL,
                       email    TEXT NOT NULL UNIQUE
                   )""",
                """CREATE TABLE IF NOT EXISTS chat_history (
                       username TEXT PRIMARY KEY,
                       history_data BLOB NOT NULL,
                       FOREIGN KEY (username) REFERENCES users (username)
                   )""",
                """CREATE TABLE IF NOT EXISTS sessions (
                       username  TEXT NOT NULL,
                       token     TEXT NOT NULL UNIQUE,
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       FOREIGN KEY (username) REFERENCES users (username)
                   )"""
            ],
            [[], [], []]
        )
    finally:
        conn.close()

# ---------- Data helpers ----------

def _first_row(rs):
    return rs if (rs is not None and len(rs) > 0) else None

# ---------- Auth/data functions ----------

def fetch_user_by_username_or_email(identifier):
    conn = get_db_connection()
    try:
        rs = conn.execute(
            "SELECT username, password, email FROM users WHERE LOWER(username) = ? OR email = ?",
            [identifier.lower(), identifier]
        )
        return _first_row(rs)
    finally:
        conn.close()

def username_exists(username):
    conn = get_db_connection()
    try:
        rs = conn.execute("SELECT 1 FROM users WHERE LOWER(username) = ?", [username.lower()])
        return len(rs) > 0
    finally:
        conn.close()

def add_user(username, hashed_password, email):
    username = username.lower()
    if username_exists(username):
        return False
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            [username, hashed_password, email]
        )
        return True
    except Exception as e:
        st.error(f"Database write error: {e}")
        return False
    finally:
        conn.close()

def save_chat_history(username, history):
    conn = get_db_connection()
    try:
        serialized = pickle.dumps(history)
        conn.execute(
            "INSERT OR REPLACE INTO chat_history (username, history_data) VALUES (?, ?)",
            [username, serialized]
        )
    finally:
        conn.close()

def load_chat_history(username):
    conn = get_db_connection()
    try:
        rs = conn.execute("SELECT history_data FROM chat_history WHERE username = ?", [username])
        row = _first_row(rs)
        if row:
            return pickle.loads(row)
        return {}
    finally:
        conn.close()

def is_password_strong(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain an uppercase letter."
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
    token = str(uuid.uuid4())
    conn = get_db_connection()
    try:
        conn.batch(
            [
                "DELETE FROM sessions WHERE username = ?",
                "INSERT INTO sessions (username, token) VALUES (?, ?)"
            ],
            [
                [username],
                [username, token]
            ]
        )
        return token
    finally:
        conn.close()

def _parse_created_at(ts: str):
    try:
        return datetime.fromisoformat(str(ts).replace('Z', '+00:00'))
    except Exception:
        try:
            from datetime import timezone
            return datetime.strptime(str(ts), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except Exception:
            return datetime.utcnow()

def validate_session_token(token):
    conn = get_db_connection()
    try:
        rs = conn.execute("SELECT username, created_at FROM sessions WHERE token = ?", [token])
        row = _first_row(rs)
        if not row:
            return None
        username, created_at = row
        created_dt = _parse_created_at(created_at)
        if datetime.utcnow() - created_dt <= timedelta(days=30):
            return username
        return None
    finally:
        conn.close()

def clear_session_token(username):
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM sessions WHERE username = ?", [username])
    finally:
        conn.close()
