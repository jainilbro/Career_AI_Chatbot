
import streamlit as st
import libsql_client
import re
import pickle
import bcrypt
import uuid
from datetime import datetime, timedelta

# ---------- Connection helpers ----------

def _normalize_libsql_url(url: str) -> str:
    # Accept common forms and coerce to libsql:// or wss:// for the Python client
    if url.startswith("https://"):
        return "libsql://" + url[len("https://"):]
    if url.startswith("http://"):
        return "libsql://" + url[len("http://"):]
    # Allow already-correct schemes: libsql://, wss://, ws:// (ws -> wss)
    if url.startswith("ws://"):
        return "wss://" + url[len("ws://"):]
    return url

def get_db_connection():
    """
    Create a sync client for Turso/libsql using Streamlit secrets.
    Raises a clear error if secrets are missing or URL scheme is wrong.
    """
    try:
        raw_url = st.secrets["TURSO_DATABASE_URL"]
        token = st.secrets["TURSO_AUTH_TOKEN"]
    except Exception as e:
        raise RuntimeError("Missing TURSO_DATABASE_URL or TURSO_AUTH_TOKEN in Streamlit Secrets") from e

    url = _normalize_libsql_url(str(raw_url).strip())
    if not (url.startswith("libsql://") or url.startswith("wss://")):
        raise RuntimeError(f"Invalid Turso URL scheme: {url}. Expected libsql:// or wss://")  # surfaced in UI

    if not token or not isinstance(token, str):
        raise RuntimeError("Empty/invalid TURSO_AUTH_TOKEN secret; generate a fresh token in Turso")  # surfaced in UI

    return libsql_client.create_client_sync(url=url, auth_token=token)

def ensure_db_ready():
    """
    Connects and runs a quick ping; also ensures tables exist on Turso.
    Safe to call once at app startup.
    """
    conn = get_db_connection()
    try:
        # Ping
        conn.execute("SELECT 1")
        # Create tables if missing (mirrors your local create_db.py)
        conn.batch(
            [
                """CREATE TABLE IF NOT EXISTS users (
                       username TEXT PRIMARY KEY COLLATE NOCASE,
                       password TEXT NOT NULL,
                       email    TEXT NOT NULL UNIQUE
                   )""",
                """CREATE TABLE IF NOT EXISTS chat_history (
                       username    TEXT PRIMARY KEY,
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
            [[] ,[] ,[]]
        )
    finally:
        conn.close()

# ---------- Auth/data functions ----------

def fetch_user_by_username_or_email(identifier):
    conn = get_db_connection()
    try:
        rs = conn.execute(
            "SELECT username, password, email FROM users WHERE LOWER(username) = ? OR email = ?",
            [identifier.lower(), identifier]
        )
        return rs if len(rs) > 0 else None
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
        # Surface DB errors clearly in the Streamlit UI
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
        if len(rs) > 0:
            return pickle.loads(rs)
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
    # Try ISO with Z, otherwise fallback to SQLite-style timestamp
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except Exception:
        try:
            from datetime import timezone
            return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except Exception:
            return datetime.utcnow()

def validate_session_token(token):
    conn = get_db_connection()
    try:
        rs = conn.execute("SELECT username, created_at FROM sessions WHERE token = ?", [token])
        if len(rs) == 0:
            return None
        username, created_at = rs
        created_dt = _parse_created_at(str(created_at))
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
