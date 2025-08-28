import streamlit as st
import libsql_client
import re
import pickle
import bcrypt
import uuid
from datetime import datetime, timedelta

def get_db_connection():
    """Establishes a connection to the Turso database using Streamlit secrets."""
    try:
        url = st.secrets["TURSO_DATABASE_URL"]
        auth_token = st.secrets["TURSO_AUTH_TOKEN"]

        # Force the URL to use the libsql+ scheme for HTTP transport
        if url.startswith("https://"):
            url = "libsql+" + url
        elif url.startswith("http://"):
             url = "libsql+" + url

        return libsql_client.create_client_sync(url=url, auth_token=auth_token)

    except KeyError:
        st.error("Database secrets (TURSO_DATABASE_URL, TURSO_AUTH_TOKEN) not found.")
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
            ]
        )
    finally:
        conn.close()

def fetch_user_by_username_or_email(identifier):
    """Fetches a user by username or email using the Turso client API."""
    conn = get_db_connection()
    try:
        rs = conn.execute(
            "SELECT username, password, email FROM users WHERE LOWER(username) = ? OR email = ?",
            [identifier.lower(), identifier]
        )
        return rs[0] if len(rs) > 0 else None
    finally:
        conn.close()

def username_exists(username):
    """Checks if a username already exists in the database."""
    conn = get_db_connection()
    try:
        rs = conn.execute("SELECT 1 FROM users WHERE LOWER(username) = ?", [username.lower()])
        return len(rs) > 0
    finally:
        conn.close()

def add_user(username, hashed_password, email):
    """Adds a new user after checking if they already exist."""
    if username_exists(username):
        return False

    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            [username.lower(), hashed_password, email]
        )
        return True
    except Exception as e:
        st.error(f"Database error: {e}")
        return False
    finally:
        conn.close()

def save_chat_history(username, history):
    """Saves chat history using the Turso client API."""
    conn = get_db_connection()
    serialized_history = pickle.dumps(history)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO chat_history (username, history_data) VALUES (?, ?)",
            [username, serialized_history]
        )
    finally:
        conn.close()

def load_chat_history(username):
    """Loads chat history using the Turso client API."""
    conn = get_db_connection()
    try:
        rs = conn.execute("SELECT history_data FROM chat_history WHERE username = ?", [username])
        if len(rs) > 0:
            return pickle.loads(rs[0][0])
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
        conn.batch([
            "DELETE FROM sessions WHERE username = ?",
            "INSERT INTO sessions (username, token) VALUES (?, ?)"
        ], [[username], [username, token]])
    finally:
        conn.close()
    return token

def validate_session_token(token):
    conn = get_db_connection()
    try:
        rs = conn.execute("SELECT username, created_at FROM sessions WHERE token = ?", [token])
        if len(rs) > 0:
            username, created_at = rs[0]
            # Handle potential timezone issues in a simple way
            created_at_str = str(created_at).split('.')[0]
            created_dt = datetime.fromisoformat(created_at_str)
            if datetime.utcnow() - created_dt < timedelta(days=30):
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
